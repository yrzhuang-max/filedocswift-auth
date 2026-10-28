from fastapi import FastAPI, APIRouter, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional
import httpx
from sqlalchemy import create_engine, Column, Integer, String, DateTime, func
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from passlib.context import CryptContext


# ========== 配置：pydantic-settings 读取环境变量 ==========
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None)
    hcaptcha_secret: str
    database_url: str

settings = Settings()


# ========== Postgres 数据库初始化 ==========
engine = create_engine(settings.database_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ========== 密码加密工具 ==========
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
def hash_password(plain_password: str) -> str:
    return pwd_context.hash(plain_password)


# ========== 用户模型 ==========
class DBUser(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime, default=func.now())


# 启动自动建表
Base.metadata.create_all(bind=engine)


# ========== 数据库依赖 ==========
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ========== 异步 hCaptcha 校验（httpx异步） ==========
async def verify_hcaptcha(token: str):
    if not token:
        raise HTTPException(status_code=400, detail="Please complete hCaptcha")
    payload = {
        "secret": settings.hcaptcha_secret,
        "response": token,
    }
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post("https://hcaptcha.com/siteverify", data=payload)
    res_json = resp.json()
    if not res_json.get("success"):
        raise HTTPException(status_code=400, detail="hCaptcha verification failed")


# ========== FastAPI 实例 ==========
app = FastAPI(title="FileDocSwift Auth API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://filedocswift.com",
        "http://localhost:3000",
        "http://127.0.0.1:3000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ========== 路由 ==========
router = APIRouter(prefix="/api/auth", tags=["auth"])

class RegisterSchema(BaseModel):
    email: EmailStr
    password: str
    hcaptchaToken: Optional[str] = None


@router.post("/register")
async def register(req: RegisterSchema, db: Session = Depends(get_db)):
    await verify_hcaptcha(req.hcaptchaToken)

    exist_user = db.query(DBUser).filter(DBUser.email == req.email).first()
    if exist_user:
        raise HTTPException(status_code=400, detail="Email already registered.")

    new_user = DBUser(
        email=req.email,
        hashed_password=hash_password(req.password)
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"msg": "Register success, user saved in database."}


app.include_router(router)
