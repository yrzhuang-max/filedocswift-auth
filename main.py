from fastapi import FastAPI, Depends, HTTPException, status, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy import Column, Integer, String
import httpx
import bcrypt
from jose import JWTError, jwt
from datetime import datetime, timedelta
import os

# ===================== 配置 =====================
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL")
# Render默认连接串是 postgres:// ，转异步 asyncpg 格式
if SQLALCHEMY_DATABASE_URL and SQLALCHEMY_DATABASE_URL.startswith("postgres://"):
    SQLALCHEMY_DATABASE_URL = SQLALCHEMY_DATABASE_URL.replace("postgres://", "postgresql+asyncpg://", 1)

engine = create_async_engine(SQLALCHEMY_DATABASE_URL)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
Base = declarative_base()

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "CHANGE_ME_TO_LONG_RANDOM_STRING")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 1天
HCAPTCHA_SECRET = os.getenv("HCAPTCHA_SECRET")

app = FastAPI()

# CORS 配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://filedocswift.com",
        "http://localhost:3000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===================== 数据库 Model =====================
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)

# 启动时创建表
@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

# ===================== DB 依赖 =====================
async def get_db():
    async with AsyncSessionLocal() as db:
        try:
            yield db
        finally:
            await db.close()

# ===================== Pydantic Schema =====================
class RegisterSchema(BaseModel):
    email: EmailStr
    password: str
    hcaptchaToken: str

class LoginSchema(BaseModel):
    email: EmailStr
    password: str
    hcaptchaToken: str

# ===================== 鉴权依赖 =====================
async def get_current_user(db: AsyncSession = Depends(get_db), request: Request = None):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"msg": "Not logged in"}
    )
    token = request.cookies.get("access_token")
    if not token:
        raise credentials_exception
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    from sqlalchemy import select
    res = await db.execute(select(User).where(User.id == int(user_id)))
    user = res.scalar_one_or_none()
    if user is None:
        raise credentials_exception
    return user

# ===================== 接口 =====================
@app.post("/api/auth/register")
async def register(req: RegisterSchema, db: AsyncSession = Depends(get_db)):
    verify_url = "https://api.hcaptcha.com/siteverify"
    async with httpx.AsyncClient(timeout=10) as client:
        cap_resp = await client.post(verify_url, data={
            "secret": HCAPTCHA_SECRET,
            "response": req.hcaptchaToken
        })
    cap_result = cap_resp.json()
    if not cap_result.get("success"):
        raise HTTPException(status_code=400, detail={"msg": "hCaptcha verification failed"})

    from sqlalchemy import select
    res = await db.execute(select(User).where(User.email == req.email))
    exist_user = res.scalar_one_or_none()
    if exist_user:
        raise HTTPException(status_code=400, detail={"msg": "Email already registered."})

    raw_pw = req.password.encode("utf-8")[:72]
    salt = bcrypt.gensalt()
    hashed_pw = bcrypt.hashpw(raw_pw, salt).decode("utf-8")

    new_user = User(email=req.email, hashed_password=hashed_pw)
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return {"msg": "Register success, user saved in database."}


@app.post("/api/auth/login")
async def login(req: LoginSchema, db: AsyncSession = Depends(get_db)):
    verify_url = "https://api.hcaptcha.com/siteverify"
    async with httpx.AsyncClient(timeout=10) as client:
        cap_resp = await client.post(verify_url, data={
            "secret": HCAPTCHA_SECRET,
            "response": req.hcaptchaToken
        })
    cap_result = cap_resp.json()
    if not cap_result.get("success"):
        raise HTTPException(status_code=400, detail={"msg": "hCaptcha verification failed"})

    from sqlalchemy import select
    res = await db.execute(select(User).where(User.email == req.email))
    user = res.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail={"msg": "Email or password incorrect"})

    check_pw = req.password.encode("utf-8")[:72]
    if not bcrypt.checkpw(check_pw, user.hashed_password.encode("utf-8")):
        raise HTTPException(status_code=401, detail={"msg": "Email or password incorrect"})

    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": str(user.id), "email": user.email, "exp": expire}
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    response = Response(content='{"msg":"Login success"}', media_type="application/json")
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/"
    )
    return response


@app.post("/api/auth/logout")
async def logout():
    response = Response(content='{"msg":"Logout success"}', media_type="application/json")
    response.delete_cookie("access_token", path="/")
    return response


@app.get("/api/auth/me")
async def get_me(current_user: User = Depends(get_current_user)):
    return {
        "msg": "ok",
        "user": {
            "id": current_user.id,
            "email": current_user.email
        }
    }
