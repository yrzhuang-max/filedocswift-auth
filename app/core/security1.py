from fastapi import Depends, HTTPException, status, Header
from sqlalchemy.orm import Session
from sqlalchemy import func
from joserfc.errors import JoseError

from app.database import get_db
from app.models import DBUser
from app.core.jwt_utils import decode_access_token


credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


async def get_current_user(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db)
) -> DBUser:
    if not authorization:
        raise credentials_exception

    pieces = authorization.strip().split()
    if len(pieces) != 2 or pieces[0].lower() != "bearer":
        raise credentials_exception

    token = pieces[1]
    try:
        decoded = decode_access_token(token)
        sub = decoded.get("sub")
        if sub is None:
            raise credentials_exception
    except JoseError:
        raise credentials_exception

    user = (
        db.query(DBUser)
        .filter(func.lower(DBUser.email) == func.lower(sub))
        .first()
    )
    if user is None:
        raise credentials_exception
    return user


dep_current_user = get_current_user
