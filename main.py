from fastapi import FastAPI, Depends, HTTPException, status, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
import os

# ===================== 配置 =====================
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "CHANGE_ME_TO_LONG_RANDOM_STRING")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 1天
HCAPTCHA_SECRET = os.getenv("HCAPTCHA_SECRET")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()

# CORS 配置，改成你的前端域名
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

Base.metadata.create_all(bind=engine)

# ===================== DB 依赖 =====================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ===================== Pydantic Schema =====================
class RegisterSchema(BaseModel):
    email: EmailStr
    password: str
    hcaptchaToken: str

class LoginSchema(BaseModel):
    email: EmailStr
    password: str
    hcaptchaToken: str

# ===================== 鉴权依赖（从Cookie读取token） =====================
def get_current_user(db: Session = Depends(get_db), request: Request = None):
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
    user = db.query(User).filter(User.id == int(user_id)).first()
    if user is None:
        raise credentials_exception
    return user

# ===================== 接口 =====================
@app.post("/api/auth/register")
def register(req: RegisterSchema, db: Session = Depends(get_db)):
    # hCaptcha verify
    verify_url = "https://api.hcaptcha.com/siteverify"
    cap_resp = requests.post(verify_url, data={
        "secret": HCAPTCHA_SECRET,
        "response": req.hcaptchaToken
    })
    cap_result = cap_resp.json()
    if not cap_result.get("success"):
        raise HTTPException(status_code=400, detail={"msg": "hCaptcha verification failed"})

    # 邮箱是否已存在
    exist_user = db.query(User).filter(User.email == req.email).first()
    if exist_user:
        raise HTTPException(status_code=400, detail={"msg": "Email already registered."})

    hashed_pw = pwd_context.hash(req.password)
    new_user = User(email=req.email, hashed_password=hashed_pw)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"msg": "Register success, user saved in database."}


@app.post("/api/auth/login")
def login(req: LoginSchema, db: Session = Depends(get_db)):
    # hCaptcha verify
    verify_url = "https://api.hcaptcha.com/siteverify"
    cap_resp = requests.post(verify_url, data={
        "secret": HCAPTCHA_SECRET,
        "response": req.hcaptchaToken
    })
    cap_result = cap_resp.json()
    if not cap_result.get("success"):
        raise HTTPException(status_code=400, detail={"msg": "hCaptcha verification failed"})

    user = db.query(User).filter(User.email == req.email).first()
    if not user or not pwd_context.verify(req.password, user.hashed_password):
        raise HTTPException(status_code=401, detail={"msg": "Email or password incorrect"})

    # build JWT
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": str(user.id), "email": user.email, "exp": expire}
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    response = Response(content='{"msg":"Login success"}', media_type="application/json")
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=False,          # Render HTTPS打开；本地调试改成 secure=False
        samesite="lax",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/"
    )
    return response


@app.post("/api/auth/logout")
def logout():
    response = Response(content='{"msg":"Logout success"}', media_type="application/json")
    response.delete_cookie("access_token", path="/")
    return response


@app.get("/api/auth/me")
def get_me(current_user: User = Depends(get_current_user)):
    return {
        "msg": "ok",
        "user": {
            "id": current_user.id,
            "email": current_user.email
        }
    }
