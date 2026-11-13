from fastapi import APIRouter
from datetime import timedelta
from app.core.jwt_utils import create_access_token

@router.get("/debug/generate-token")
async def debug_generate_token():
    # Sandbox only, REMOVE before production deploy
    return {
        "token": create_access_token(
            data={"sub": "test@example.com"},
            expires_delta=timedelta(minutes=60 * 24)
        )
    }
