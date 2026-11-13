from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, Depends, HTTPException, status, Request, Response, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from sqlalchemy import func
from contextlib import asynccontextmanager
import httpx
import bcrypt
from datetime import datetime, timedelta, UTC
import os
import uuid
from typing import Dict
import logging
import asyncio
import time
import re
import stripe
from app.core.security import get_current_user, dep_current_user
from app.core.config import ACCESS_TOKEN_EXPIRE_DELTA,SECRET_KEY, ALGORITHM
from app.core.jwt_utils import create_access_token, decode_access_token

from app.database import engine, Base, get_db
from app.models import (
    DBUser,
    PasswordResetToken,
    RechargeOrder,
    CreditTransaction,
    PaddleWebhookRecord,
    PaddlePricePlan
)

Base.metadata.create_all(bind=engine)

logging.basicConfig(level=logging.INFO)

# ===================== 内存限流 =====================
login_limiter: Dict[str, list[float]] = {}
reset_limiter: Dict[str, list[float]] = {}


def clean_old_records(records: list[float], window_sec: float) -> list[float]:
    now = datetime.now(UTC).timestamp()
    return [ts for ts in records if now - ts < window_sec]


def check_rate_limit(store: Dict[str, list[float]], key: str, max_count: int, window_sec: float) -> bool:
    now_ts = datetime.now(UTC).timestamp()
    records = clean_old_records(store.get(key, []), window_sec)
    if len(records) >= max_count:
        return False
    records.append(now_ts)
    store[key] = records
    return True


def check_login_limit(ip: str) -> bool:
    return check_rate_limit(login_limiter, ip, 5, 600)


def check_reset_email_limit(email: str) -> bool:
    return check_rate_limit(reset_limiter, email, 3, 3600)

# ===================== 密码校验 =====================
def validate_password(password: str) -> bool:
    if len(password) < 8:
        return False
    if not re.search(r"[a-zA-Z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    return True

# ===================== 配置 =====================
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

HCAPTCHA_SECRET = os.getenv("HCAPTCHA_SECRET")
RESEND_API_KEY = os.getenv("RESEND_API_KEY")
EMAIL_FROM = os.getenv("EMAIL_FROM")

http_client: httpx.AsyncClient | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global http_client
    http_client = httpx.AsyncClient(
        timeout=2.5,
        limits=httpx.Limits(max_connections=20, max_keepalive_connections=5)
    )
    yield
    await http_client.aclose()


app = FastAPI(lifespan=lifespan)

origins = [
    "https://filedocswift.com",
    "https://www.filedocswift.com",
    "https://filedocswift.vercel.app"
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def strip_query_params(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/"):
        return await call_next(request)
    url = str(request.url)
    if "?" in url:
        clean_url = url.split("?")[0]
        return Response(status_code=301, headers={"Location": clean_url})
    return await call_next(request)


# ========== 路由导入 & 注册（放在 app 实例之后） ==========
from app.api.user import router as user_router
from app.paddle.webhook import router as paddle_webhook_router
from app.paddle.checkout import router as paddle_checkout_router

app.include_router(user_router, prefix="/api")
app.include_router(paddle_webhook_router, prefix="/api/paddle")
app.include_router(paddle_checkout_router, prefix="/api/paddle")

# ===================== Pydantic Schema =====================
class RegisterReq(BaseModel):
    email: EmailStr
    password: str
    hcaptchaToken: str


class LoginReq(BaseModel):
    email: EmailStr
    password: str
    hcaptchaToken: str


class ResetRequestReq(BaseModel):
    email: EmailStr
    hcaptchaToken: str


class ResetConfirmReq(BaseModel):
    token: str
    password: str

# ===================== 密码工具 =====================
def get_password_hash(password: str) -> str:
    pw_bytes = password.encode("utf-8")[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pw_bytes, salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    pw_bytes = plain_password.encode("utf-8")[:72]
    return bcrypt.checkpw(pw_bytes, hashed_password.encode("utf-8"))


async def verify_password_async(plain_password: str, hashed_password: str) -> bool:
    return await asyncio.to_thread(verify_password, plain_password, hashed_password)


async def verify_hcaptcha(token: str):
    # dev bypass 优先
    if token == "dummy":
        return True

    skip = os.getenv("SKIP_HCAPTCHA", "false").lower() == "true"
    if skip:
        return True

    if not HCAPTCHA_SECRET:
        raise HTTPException(status_code=500, detail="HCAPTCHA_SECRET not configured")

    resp = await http_client.post(
        "https://api.hcaptcha.com/siteverify",
        data={"secret": HCAPTCHA_SECRET, "response": token}
    )
    data = resp.json()
    return data.get("success", False)


async def send_reset_email(to_email: str, reset_token: str):
    if not RESEND_API_KEY or not EMAIL_FROM:
        raise HTTPException(status_code=500, detail="Email service not configured")
    reset_link = f"https://filedocswift.com/reset-password/{reset_token}"
    payload = {
        "from": EMAIL_FROM,
        "to": [to_email],
        "subject": "FiledocSwift Password Reset",
        "html": f"""
    <p>Click the link below to reset your password. Link valid for 1 hour, one-time use.</p>
    <a href="{reset_link}">{reset_link}</a>
    <p>If you didn't request this, ignore this email.</p>
    """
    }
    await http_client.post(
        "https://api.resend.com/emails",
        json=payload,
        headers={"Authorization": f"Bearer {RESEND_API_KEY}"}
    )


# ===================== 接口 =====================
@app.post("/api/auth/register")
async def register(req: RegisterReq, db: Session = Depends(get_db)):
    if not validate_password(req.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters and contain both letters and numbers."
        )
    await verify_hcaptcha(req.hcaptchaToken)
    existing = db.query(DBUser).filter(DBUser.email == req.email).first()
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")
    hashed = get_password_hash(req.password)
    user = DBUser(email=req.email, hashed_password=hashed, credit_balance=3)
    db.add(user)
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise
    db.refresh(user)
    return {"msg": "Register success, please login"}


@app.post("/api/auth/login")
async def login(request: Request, req: LoginReq, db: Session = Depends(get_db)):
    t0 = time.perf_counter()
    client_ip = request.client.host
    if not check_login_limit(client_ip):
        raise HTTPException(status_code=429, detail="Too many login attempts, please try again later")
    t1 = time.perf_counter()

    await verify_hcaptcha(req.hcaptchaToken)
    t2 = time.perf_counter()

    user = (
        db.query(DBUser)
        .filter(func.lower(DBUser.email) == func.lower(req.email))
        .first()
    )
    print("-" * 60)
    print(f"input email: {repr(req.email)}")
    print(f"input password raw: {repr(req.password)}")
    if user:
        print(f"found user in db, email: {repr(user.email)}")
        print(f"stored hashed_password: {repr(user.hashed_password)}")
        ok = bcrypt.checkpw(req.password.encode("utf-8"), user.hashed_password.encode("utf-8"))
        print(f"bcrypt direct check result: {ok}")
    else:
        print("user NOT found from database")
    print("-" * 60)

    if not user or not await verify_password_async(req.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    t3 = time.perf_counter()

    print("=== LOGIN CREATE TOKEN SECRET ===", repr(os.getenv("SECRET_KEY")))
    access_token = create_access_token(
        data={"sub": user.email},
        expires_delta=timedelta(minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")))
    )
    # 修复变量名
    try:
        check = decode_access_token(access_token)
        print(f"✅ SELF CHECK PASS: {check}")
    except Exception as e:
        print(f"❌ SELF CHECK FAIL: {e}")
    t4 = time.perf_counter()

    logging.info(
        f"LOGIN_TIMING | limit:{t1-t0:.3f}s | hcaptcha:{t2-t1:.3f}s | db+bcrypt:{t3-t2:.3f}s | jwt:{t4-t3:.3f}s | total:{t4-t0:.3f}s"
    )
    return {"msg": "Login success", "token": access_token}

@app.post("/api/auth/logout")
async def logout():
    return {"msg": "Logged out"}


@app.get("/api/auth/me")
async def me(current_user: DBUser = Depends(dep_current_user)):
    return {
        "user": {
            "id": current_user.id,
            "email": current_user.email,
            "credit_balance": current_user.credit_balance,
            "subscription_plan": "free",
            "subscription_status": "active",
            "background": "#ffffff",
            "foreground": "#171717"
        }
    }


@app.post("/api/auth/reset-password-request")
async def reset_request(request: Request, req: ResetRequestReq, db: Session = Depends(get_db)):
    if not check_reset_email_limit(req.email):
        raise HTTPException(status_code=429, detail="Too many reset requests for this email, try again later")

    await verify_hcaptcha(req.hcaptchaToken)
    user = db.query(DBUser).filter(DBUser.email == req.email).first()
    if not user:
        return {"msg": "If this email exists in our system, a password reset link has been sent."}

    token_str = str(uuid.uuid4())
    expire = datetime.now(UTC) + timedelta(hours=1)
    reset_token = PasswordResetToken(
        email=req.email,
        token=token_str,
        expires_at=expire,
        used=False
    )
    db.add(reset_token)
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise
    await send_reset_email(req.email, token_str)
    return {"msg": "If this email exists in our system, a password reset link has been sent."}


@app.post("/api/auth/reset-password-confirm")
async def reset_confirm(req: ResetConfirmReq, db: Session = Depends(get_db)):
    if not validate_password(req.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters and contain both letters and numbers."
        )

    rt = db.query(PasswordResetToken).filter(
        PasswordResetToken.token == req.token,
        PasswordResetToken.used == False,
        PasswordResetToken.expires_at > datetime.now(UTC)
    ).first()
    if not rt:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    user = db.query(DBUser).filter(DBUser.email == rt.email).first()
    if not user:
        raise HTTPException(status_code=400, detail="User not found")

    user.hashed_password = get_password_hash(req.password)
    rt.used = True
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise
    return {"msg": "Password updated successfully, please login"}
