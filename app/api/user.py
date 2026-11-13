from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel

from app.database import get_db
from app.models import DBUser, CreditTransaction
from app.core.security import dep_current_user

router = APIRouter(prefix="/user", tags=["user"])


class UserProfileResponse(BaseModel):
    id: int
    email: str
    credit_balance: int
    subscription_expires_at: Optional[datetime]
    has_active_subscription: bool

    class Config:
        from_attributes = True


class CreditTransactionResponse(BaseModel):
    id: int
    amount: int
    source: str
    remark: str
    created_at: datetime

    class Config:
        from_attributes = True


@router.get("/profile", response_model=UserProfileResponse)
def get_user_profile(
    current_user: DBUser = Depends(dep_current_user),
    db: Session = Depends(get_db)
):
    now = datetime.utcnow()
    active_sub = bool(
        current_user.subscription_expires_at
        and current_user.subscription_expires_at > now
    )
    return UserProfileResponse(
        id=current_user.id,
        email=current_user.email,
        credit_balance=current_user.credit_balance,
        subscription_expires_at=current_user.subscription_expires_at,
        has_active_subscription=active_sub
    )


@router.get("/credit/transactions", response_model=List[CreditTransactionResponse])
def list_credit_transactions(
    current_user: DBUser = Depends(dep_current_user),
    db: Session = Depends(get_db),
    limit: int = 20,
    offset: int = 0
):
    txs = (
        db.query(CreditTransaction)
        .filter(CreditTransaction.user_id == current_user.id)
        .order_by(CreditTransaction.created_at.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return txs
