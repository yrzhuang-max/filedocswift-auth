from fastapi import FastAPI, Depends, HTTPException, status, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import httpx
from jose import JWTError, jwt
import bcrypt
from datetime import datetime, timedelta
import os
import uuid
from typing import Dict

# ===================== 内存限流 开始 =====================
login_limiter: Dict[str, list[float]] = {}   # key: IP
reset_limiter: Dict[str, list[float]] = {}   # key: email

def clean_old_records(records: list[float], window_sec: float) -> list[float]:
    now = datetime.utcnow().timestamp()
    return [ts for ts in records if now - ts < window_sec]

def check_rate_limit(store: Dict[str, list[float]], key: str, max_count: int, window_sec: float) -> bool:
    now_ts = datetime.utcnow().timestamp()
    records = clean_old_records(store.get(key, []), window_sec)
    if len(records) >= max_count:
        return False
    records.append(now_ts)
    store[key] = records
    return True

# 登录：同一IP 5次 / 10分钟(600s)
def check_login_limit(ip: str) -> bool:
    return check_rate_limit(login_limiter, ip, 5, 600)

# 重置密码邮件：同一邮箱 3次 / 1小时(3600s)
def check_reset_email_limit(email: str) -> bool:
    return check_rate_limit(reset_limiter, email, 3, 3600)
# ===================== 内存限流 结束 =====================

# ===================== 配置 =====================
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24h

HCAPTCHA_SECRET = os.getenv("HCAPTCHA_SECRET")
RESEND_API_KEY = os.getenv("RESEND_API_KEY")
EMAIL_FROM = os.getenv("EMAIL_FROM")

app = FastAPI()

@app.middleware("http")
async def strip_query_params(request: Request, call_next):
    path = request.url.path
    # API路由跳过，不清除参数
    if path.startswith("/api/"):
        return await call_next(request)

    url = str(request.url)
    if "?" in url:
        clean_url = url.split("?")[0]
        return Response(status_code=301, headers={"Location": clean_url})
    return await call_next(request)

# CORS 配置，允许你的前端域名
origins = [
    "http://localhost:3000",
    "https://filedocswift.com",
    "https://www.filedocswift.com"
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===================== 数据库模型 =====================
class DBUser(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)

class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, nullable=False)
    token = Column(String, unique=True, index=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)

Base.metadata.create_all(bind=engine)

# ===================== DB依赖 =====================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

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

# ===================== 工具函数（原生bcrypt） =====================
def get_password_hash(password: str) -> str:
    # bcrypt 限制最多72字节，自动截断
    pw_bytes = password.encode("utf-8")[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pw_bytes, salt).decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    pw_bytes = plain_password.encode("utf-8")[:72]
    return bcrypt.checkpw(pw_bytes, hashed_password.encode("utf-8"))

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def verify_hcaptcha(token: str):
    if not HCAPTCHA_SECRET:
        raise HTTPException(status_code=500, detail="HCAPTCHA_SECRET not configured")
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "https://api.hcaptcha.com/siteverify",
            data={"secret": HCAPTCHA_SECRET, "response": token}
        )
        data = resp.json()
    if not data.get("success"):
        raise HTTPException(status_code=400, detail="hCaptcha validation failed")

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
    async with httpx.AsyncClient() as client:
        await client.post(
            "https://api.resend.com/emails",
            json=payload,
            headers={"Authorization": f"Bearer {RESEND_API_KEY}"}
        )

def get_current_user(db: Session, token: str):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(DBUser).filter(DBUser.email == email).first()
    if user is None:
        raise credentials_exception
    return user

# ===================== 接口 =====================
@app.post("/api/auth/register")
async def register(req: RegisterReq, db: Session = Depends(get_db)):
    await verify_hcaptcha(req.hcaptchaToken)
    existing = db.query(DBUser).filter(DBUser.email == req.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed = get_password_hash(req.password)
    user = DBUser(email=req.email, hashed_password=hashed)
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"msg": "Register success, please login"}

@app.post("/api/auth/login")
async def login(request: Request, req: LoginReq, res: Response, db: Session = Depends(get_db)):
    client_ip = request.client.host
    if not check_login_limit(client_ip):
        raise HTTPException(status_code=429, detail="Too many login attempts, please try again later")

    await verify_hcaptcha(req.hcaptchaToken)
    user = db.query(DBUser).filter(DBUser.email == req.email).first()
    if not user or not verify_password(req.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid email or password")
    access_token = create_access_token(
        data={"sub": user.email},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    res.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    return {"msg": "Login success"}

@app.post("/api/auth/logout")
async def logout(res: Response):
    res.delete_cookie(key="access_token")
    return {"msg": "Logged out"}

@app.get("/api/auth/me")
async def me(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not login")
    user = get_current_user(db, token)
    return {"user": {"id": user.id, "email": user.email}}

@app.post("/api/auth/reset-password-request")
async def reset_request(request: Request, req: ResetRequestReq, db: Session = Depends(get_db)):
    if not check_reset_email_limit(req.email):
        raise HTTPException(status_code=429, detail="Too many reset requests for this email, try again later")

    await verify_hcaptcha(req.hcaptchaToken)
    user = db.query(DBUser).filter(DBUser.email == req.email).first()
    # 不管有没有这个邮箱，返回同样提示，防止邮箱探测
    if not user:
        return {"msg": "If this email exists in our system, a password reset link has been sent."}

    # 生成一次性token，1小时过期
    token_str = str(uuid.uuid4())
    expire = datetime.utcnow() + timedelta(hours=1)
    reset_token = PasswordResetToken(
        email=req.email,
        token=token_str,
        expires_at=expire,
        used=False
    )
    db.add(reset_token)
    db.commit()
    await send_reset_email(req.email, token_str)
    return {"msg": "If this email exists in our system, a password reset link has been sent."}

@app.post("/api/auth/reset-password-confirm")
async def reset_confirm(req: ResetConfirmReq, db: Session = Depends(get_db)):
    rt = db.query(PasswordResetToken).filter(
        PasswordResetToken.token == req.token,
        PasswordResetToken.used == False,
        PasswordResetToken.expires_at > datetime.utcnow()
    ).first()
    if not rt:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    user = db.query(DBUser).filter(DBUser.email == rt.email).first()
    if not user:
        raise HTTPException(status_code=400, detail="User not found")

    # 更新密码
    user.hashed_password = get_password_hash(req.password)
    rt.used = True
    db.commit()
    return {"msg": "Password updated successfully, please login"}