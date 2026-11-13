from fastapi import APIRouter, Request, HTTPException, Depends
from sqlalchemy.orm import Session
import hmac
import hashlib
import json
import os
from dotenv import load_dotenv
from datetime import datetime, UTC

from app.models import (
    PaddleWebhookRecord,
    DBUser,
    CreditTransaction,
    PaddlePricePlan
)
from app.database import get_db

load_dotenv()
router = APIRouter()

PADDLE_WEBHOOK_SECRET = os.getenv("PADDLE_WEBHOOK_SECRET", "REPLACE_ME")


def user_has_active_subscription(db: Session, user_id: int) -> bool:
    user = db.get(DBUser, user_id)
    if not user or not user.subscription_expires_at:
        return False
    now = datetime.now(UTC)
    return user.subscription_expires_at > now


def verify_paddle_signature(raw_body: bytes, signature_header: str | None) -> bool:
    if not PADDLE_WEBHOOK_SECRET or PADDLE_WEBHOOK_SECRET == "REPLACE_ME":
        return True
    if not signature_header:
        return False

    parts = {}
    for seg in signature_header.split(";"):
        if "=" in seg:
            k, v = seg.split("=", 1)
            parts[k] = v

    ts_str = parts.get("ts")
    received_h1 = parts.get("h1")
    if not ts_str or not received_h1:
        return False

    try:
        ts = int(ts_str)
        now = int(datetime.now(tz=UTC).timestamp())
        if abs(now - ts) > 300:
            print("WARNING: Paddle webhook timestamp expired, reject")
            return False
    except Exception:
        return False

    message = f"{ts_str}:{raw_body.decode('utf-8')}"
    expected = hmac.new(
        PADDLE_WEBHOOK_SECRET.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(expected, received_h1)


@router.post("/webhook")
async def paddle_webhook(
    request: Request,
    db: Session = Depends(get_db)
):
    raw_body = await request.body()
    sig_header = request.headers.get("paddle-signature")

    if not raw_body.strip():
        raise HTTPException(status_code=400, detail="empty body")

    if not verify_paddle_signature(raw_body, sig_header):
        raise HTTPException(status_code=403, detail="Invalid Paddle signature")

    try:
        payload = json.loads(raw_body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="invalid json")

    event_id = payload.get("event_id")
    event_name = payload.get("event_name") or payload.get("event_type") or "unknown"
    data = payload.get("data", {}) or {}

    custom_data = data.get("custom_data") or {}
    user_id = custom_data.get("user_id")

    paddle_customer_id = data.get("customer_id")
    subscription_id = data.get("subscription_id")
    transaction_id = data.get("id")

    line_items = data.get("line_items", [])
    price_id = None
    if line_items and len(line_items) > 0:
        price_id = line_items[0].get("price_id")

    billing_period = data.get("current_billing_period", {})
    ends_at_raw = billing_period.get("ends_at")
    subscription_expire_time = None
    if ends_at_raw:
        try:
            subscription_expire_time = datetime.fromisoformat(ends_at_raw.replace("Z", "+00:00"))
        except ValueError:
            print(f"WARNING: cannot parse ends_at: {ends_at_raw}")

    if not event_id:
        raise HTTPException(status_code=400, detail="missing event_id")

    existing = db.query(PaddleWebhookRecord).filter_by(event_id=event_id).first()
    if existing:
        return {"success": True, "note": "already handled", "event_name": event_name}

    rec = PaddleWebhookRecord(
        event_id=event_id,
        event_type=event_name,
        user_id=user_id,
        paddle_customer_id=paddle_customer_id,
        subscription_id=subscription_id,
        transaction_id=transaction_id,
        handled=False
    )
    db.add(rec)
    db.flush()

    remark = f"Paddle webhook: {event_name}"

    if event_name in ("transaction.completed", "subscription.activated", "subscription.renewed"):
        print(f"INFO: {event_name} | user_id={user_id}, tx={transaction_id}, price_id={price_id}")
        if user_id is not None:
            try:
                uid_int = int(user_id)
            except ValueError:
                print(f"WARNING: user_id is not a valid integer: {user_id}")
            else:
                user = db.get(DBUser, uid_int)
                if not user:
                    print(f"WARNING: user_id {user_id} not found in database")
                else:
                    if not price_id:
                        print("WARNING: price_id missing, skip credit grant")
                    else:
                        plan = db.query(PaddlePricePlan).filter(
                            PaddlePricePlan.price_id == price_id,
                            PaddlePricePlan.active == True
                        ).first()
                        if not plan:
                            print(f"WARNING: price_id {price_id} not found or inactive, skip credit grant")
                        else:
                            if plan.plan_type in ("monthly", "yearly"):
                                if user_has_active_subscription(db, uid_int):
                                    print(
                                        f"REJECT: user {uid_int} already has active subscription, "
                                        f"cannot buy another subscription (price_id={price_id}, type={plan.plan_type})"
                                    )
                                    rec.handled = True
                                    rec.handled_at = datetime.now(UTC)
                                    db.commit()
                                    return {"success": True, "note": "subscription mutually exclusive, skipped credit"}
                                remark = f"Subscription activated: {plan.name}"
                                if subscription_expire_time:
                                    user.subscription_expires_at = subscription_expire_time
                                    print(f"INFO: set subscription expire at: {subscription_expire_time.isoformat()}")
                            else:
                                remark = f"Points added from one-time purchase: {plan.name}"

                            add_credit = plan.credit_amount
                            user.credit_balance += add_credit

                            tx_record = CreditTransaction(
                                user_id=user.id,
                                amount=add_credit,
                                type="recharge",
                                source="paddle",
                                related_id=transaction_id,
                                price_plan_id=plan.id,
                                remark=remark
                            )
                            db.add(tx_record)
                            print(f"INFO: user {user_id} added {add_credit} credits from price_id {price_id}")

    elif event_name == "transaction.payment_failed":
        remark = "Payment failed"
        print(f"INFO: payment failed | user_id={user_id}, customer={paddle_customer_id}")

    elif event_name == "subscription.trialing":
        remark = "Subscription trialing"
        print(f"INFO: subscription trialing | user_id={user_id}, sub={subscription_id}")

    elif event_name == "subscription.past_due":
        remark = "Subscription past due"
        print(f"INFO: subscription past due | user_id={user_id}, sub={subscription_id}")

    elif event_name == "subscription.paused":
        remark = "Subscription paused"
        print(f"INFO: subscription paused | user_id={user_id}, sub={subscription_id}")

    elif event_name == "subscription.resumed":
        remark = "Subscription resumed"
        print(f"INFO: subscription resumed | user_id={user_id}, sub={subscription_id}")

    elif event_name == "subscription.updated":
        remark = "Subscription updated"
        print(f"INFO: subscription updated | user_id={user_id}, sub={subscription_id}")

    elif event_name == "subscription.canceled":
        remark = "Subscription canceled"
        print(f"INFO: subscription canceled | user_id={user_id}, sub={subscription_id}")

    elif event_name == "subscription.expired":
        remark = "Subscription expired"
        print(f"INFO: subscription expired | user_id={user_id}, sub={subscription_id}")
        if user_id is not None:
            try:
                uid_int = int(user_id)
            except ValueError:
                pass
            else:
                user = db.get(DBUser, uid_int)
                if user:
                    user.subscription_expires_at = None

    else:
        print(f"WARNING: unregistered event type: {event_name}")

    rec.handled = True
    rec.handled_at = datetime.now(UTC)
    db.commit()

    return {"success": True, "event_name": event_name, "event_id": event_id}
