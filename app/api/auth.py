from fastapi import APIRouter, HTTPException
from datetime import timedelta
import os
from app.core.jwt_utils import create_access_token

router = APIRouter()

@router.get("/debug/generate-token")
async def debug_generate_token():
    # Sandbox only, REMOVE before production deploy
    try:
        expire_min = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
        token = create_access_token(
            data={"sub": "test@example.com"},
            expires_delta=timedelta(minutes=expire_min)
        )
        return {"token": token}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
