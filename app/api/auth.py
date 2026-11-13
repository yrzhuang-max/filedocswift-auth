# 导入区
from fastapi import APIRouter
from app.core.jwt_utils import create_access_token

# 第一：初始化 router
router = APIRouter()

# 第二：调试接口（放在 router 之后，所有业务接口前面或者末尾都行）
@router.get("/debug/generate-token")
async def debug_generate_token():
    # Sandbox only, REMOVE before production deploy
    return {"token": create_access_token(data={"sub": "test@example.com"})}

# 下面是你原有的全部登录、注册、重置密码、me 等接口
@router.post("/login")
...
