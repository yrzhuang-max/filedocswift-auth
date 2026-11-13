from fastapi import APIRouter
from datetime import timedelta
import os
from app.core.jwt_utils import create_access_token

router = APIRouter()

@router.get("/debug/generate-token")
async def debug_generate_token():
    # Sandbox only, REMOVE before production deploy
    expire_min = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    return {
        "token": create_access_token(
            data={"sub": "test@example.com"},
            expires_delta=timedelta(minutes=expire_min)
        )
    }
