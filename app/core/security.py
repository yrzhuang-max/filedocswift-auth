from fastapi import Depends, HTTPException, status, Header
from sqlalchemy.orm import Session
from sqlalchemy import func
from joserfc.errors import JoseError

from app.database import get_db
from app.models import DBUser
from app.core.jwt_utils import decode_access_token


async def get_current_user(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db)
) -> DBUser:
    if not authorization:
        raise HTTPException(status_code=401, detail="no auth header")

    pieces = authorization.strip().split()
    if len(pieces) != 2 or pieces[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="bad bearer format")

    token = pieces[1]
    try:
        decoded = decode_access_token(token)
    except JoseError as exc:
        raise HTTPException(status_code=401, detail=f"decode fail: JoseError: {str(exc)}")
    except Exception as exc:
        raise HTTPException(status_code=401, detail=f"decode fail: {type(exc).__name__}: {str(exc)}")

    sub = decoded.get("sub")
    if sub is None:
        raise HTTPException(status_code=401, detail="sub missing")

    user = (
        db.query(DBUser)
        .filter(func.lower(DBUser.email) == func.lower(sub))
        .first()
    )
    if user is None:
        raise HTTPException(status_code=401, detail=f"user not found, sub={sub}")
    return user


dep_current_user = get_current_user
