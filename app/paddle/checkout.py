from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
import httpx
import os
from dotenv import load_dotenv
from datetime import datetime, UTC

from app.models import DBUser, PaddlePricePlan
from app.database import get_db
from app.core.security import dep_current_user

load_dotenv()
router = APIRouter()

PADDLE_API_KEY = os.getenv("PADDLE_API_KEY", "")
PADDLE_SANDBOX = os.getenv("PADDLE_SANDBOX", "true").lower() == "true"
PADDLE_RETURN_URL = os.getenv("PADDLE_RETURN_URL", "")
PADDLE_CANCEL_URL = os.getenv("PADDLE_CANCEL_URL", "")

if PADDLE_SANDBOX:
    PADDLE_BASE_URL = "https://sandbox-api.paddle.com"
else:
    PADDLE_BASE_URL = "https://api.paddle.com"


class CreateCheckoutRequest(BaseModel):
    price_id: str


def user_has_active_subscription(user: DBUser) -> bool:
    if not user.subscription_expires_at:
        return False
    now = datetime.now(UTC)
    return user.subscription_expires_at > now


@router.get("/plans")
async def list_plans(
    db: Session = Depends(get_db),
    _current_user: DBUser = Depends(dep_current_user)
):
    """Return all active paddle price plans for logged-in user"""
    plans = db.query(PaddlePricePlan).filter(PaddlePricePlan.active.is_(True)).all()
    return [
        {
            "price_id": p.price_id,
            "name": p.name,
            "credit_amount": p.credit_amount,
            "plan_type": p.plan_type,
        }
        for p in plans
    ]


@router.post("/checkout")
async def create_checkout(
    req: CreateCheckoutRequest,
    db: Session = Depends(get_db),
    current_user: DBUser = Depends(dep_current_user)
):
    if not PADDLE_API_KEY:
        raise HTTPException(status_code=500, detail="Paddle API key not configured")

    plan = db.query(PaddlePricePlan).filter_by(price_id=req.price_id, active=True).first()
    if not plan:
        raise HTTPException(status_code=404, detail="Price plan not found")

    if plan.plan_type in ("monthly", "yearly"):
        if user_has_active_subscription(current_user):
            raise HTTPException(
                status_code=400,
                detail="You already have an active subscription, cannot purchase another subscription"
            )

    payload = {
        "items": [
            {
                "price_id": plan.price_id,
                "quantity": 1
            }
        ],
        "custom_data": {
            "user_id": str(current_user.id)
        },
        "collection_mode": "automatic",
        "checkout": {
            "url": None
        }
    }

    headers = {
        "Authorization": f"Bearer {PADDLE_API_KEY}",
        "Content-Type": "application/json"
    }

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{PADDLE_BASE_URL}/transactions",
            json=payload,
            headers=headers
        )

    if resp.status_code not in (200, 201):
        raise HTTPException(status_code=500, detail=f"Paddle create transaction failed: {resp.text}")

    data = resp.json()
    txn = data["data"]
    checkout_url = txn["checkout"]["url"]
    return {
        "checkout_url": checkout_url,
        "transaction_id": txn["id"]
    }


@router.post("/checkout-test")
async def create_checkout_test(
    req: CreateCheckoutRequest,
    db: Session = Depends(get_db)
):
    current_user = db.get(DBUser, 1)
    if not current_user:
        raise HTTPException(status_code=404, detail="test user id=1 not found")

    plan = db.query(PaddlePricePlan).filter_by(price_id=req.price_id, active=True).first()
    if not plan:
        raise HTTPException(status_code=404, detail="price plan not found")

    if plan.plan_type in ("monthly", "yearly"):
        if user_has_active_subscription(current_user):
            raise HTTPException(
                status_code=400,
                detail="You already have an active subscription, cannot purchase another subscription"
            )

    payload = {
        "collection_mode": "automatic",
        "items": [
            {
                "price_id": plan.price_id,
                "quantity": 1
            }
        ],
        "custom_data": {
            "user_id": current_user.id
        }
    }
    if PADDLE_RETURN_URL:
        payload["return_url"] = PADDLE_RETURN_URL
    if PADDLE_CANCEL_URL:
        payload["cancel_url"] = PADDLE_CANCEL_URL

    headers = {"Authorization": f"Bearer {PADDLE_API_KEY}", "Content-Type": "application/json"}
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            resp = await client.post(f"{PADDLE_BASE_URL}/transactions", json=payload, headers=headers)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"call paddle failed: {str(e)}")

    if resp.status_code not in (200, 201):
        raise HTTPException(status_code=500, detail=f"Paddle error: {resp.text}")
    data = resp.json()
    return {
        "checkout_url": data["data"]["checkout"]["url"],
        "transaction_id": data["data"]["id"]
    }
