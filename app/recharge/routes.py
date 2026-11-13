# app/recharge/router.py
import uuid
import os
import hmac
import hashlib
import requests
import json
from fastapi import APIRouter, Depends, HTTPException, Request, Header
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.recharge.constants import CREDIT_PACKAGES, SUB_PACKAGES

router = APIRouter(prefix="/recharge")

LS_API_KEY = os.getenv("LEMONSQUEEZY_API_KEY", "")
LS_WEBHOOK_SECRET = os.getenv("LEMONSQUEEZY_WEBHOOK_SECRET", "")
LS_STORE_ID = os.getenv("LEMONSQUEEZY_STORE_ID", "")
SITE_URL = os.getenv("SITE_URL", "")


class CreateLSCheckout(BaseModel):
    packageKey: str


def get_auth_user(authorization: str | None, db: Session) -> DBUser:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not login")
    token = authorization.removeprefix("Bearer ")
    return get_current_user(db, token)


@router.post("/ls-checkout")
def create_checkout(
    body: CreateLSCheckout,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db)
):
    user = get_auth_user(authorization, db)
    pkg = CREDIT_PACKAGES.get(body.packageKey) or SUB_PACKAGES.get(body.packageKey)
    if not pkg:
        raise HTTPException(status_code=400, detail="invalid package")
    if not LS_API_KEY or not LS_STORE_ID or not SITE_URL:
        raise HTTPException(status_code=500, detail="LemonSqueezy config missing")

    variant_id = pkg["variant_id"]
    payload = {
        "data": {
            "type": "checkouts",
            "attributes": {
                "custom_data": {
                    "user_email": user.email,
                    "user_id": str(user.id),
                    "package_key": body.packageKey
                },
                "checkout_options": {
                    "redirect_url": f"{SITE_URL}/dashboard/recharge/success?success=1"
                }
            },
            "relationships": {
                "store": {"data": {"type": "stores", "id": LS_STORE_ID}},
                "variant": {"data": {"type": "variants", "id": variant_id}}
            }
        }
    }
    headers = {
        "Authorization": f"Bearer {LS_API_KEY}",
        "Content-Type": "application/json"
    }
    r = requests.post(
        "https://api.lemonsqueezy.com/v1/checkouts",
        json=payload,
        headers=headers,
        timeout=20
    )
    if not r.ok:
        raise HTTPException(status_code=400, detail=f"Create checkout failed: {r.text}")
    data = r.json()
    return {"checkout_url": data["data"]["attributes"]["url"]}


def verify_ls_signature(raw_body: bytes, sig_header: str, secret: str) -> bool:
    digest = hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, sig_header)


@router.post("/lemonsqueezy/webhook")
async def ls_webhook(request: Request, db: Session = Depends(get_db)):
    raw = await request.body()
    sig = request.headers.get("X-Signature")
    if not sig or not LS_WEBHOOK_SECRET:
        raise HTTPException(status_code=403, detail="Missing signature or webhook secret")
    if not verify_ls_signature(raw, sig, LS_WEBHOOK_SECRET):
        raise HTTPException(status_code=403, detail="Signature verify failed")

    payload = json.loads(raw)
    event_name = payload["meta"]["event_name"]
    meta_data = payload["meta"].get("custom_data", {})
    email = meta_data.get("user_email")
    user_id_str = meta_data.get("user_id")
    pkg_key = meta_data.get("package_key")

    if not email or not user_id_str:
        return {"ok": True}
    user_id = int(user_id_str)

    if event_name == "order_created":
        pkg = CREDIT_PACKAGES.get(pkg_key)
        if not pkg:
            return {"ok": True}
        credit_add = pkg["credit"]
        ls_order_id = payload["data"]["id"]
        try:
            db.execute(
                text("""
                    INSERT INTO order_records(user_id, package_key, credits_added, ls_order_id, created_at)
                    VALUES (:uid, :pkg, :add, :lsid, NOW())
                """),
                {
                    "uid": user_id,
                    "pkg": pkg_key,
                    "add": credit_add,
                    "lsid": ls_order_id
                }
            )
            db.execute(
                text("UPDATE users SET credit_balance = credit_balance + :add WHERE id = :uid"),
                {"add": credit_add, "uid": user_id}
            )
            db.execute(
                text("""
                    INSERT INTO credit_transaction(user_id, amount, type, source, related_id, remark)
                    VALUES (:uid, :amt, 'recharge', 'lemonsqueezy', :rid, 'LemonSqueezy one-time credits')
                """),
                {
                    "uid": user_id,
                    "amt": credit_add,
                    "rid": ls_order_id
                }
            )
            db.commit()
        except Exception:
            db.rollback()
            raise

    elif event_name == "subscription_created":
        pkg = SUB_PACKAGES.get(pkg_key)
        if not pkg:
            return {"ok": True}
        ls_sub_id = payload["data"]["id"]
        try:
            db.execute(
                text("""
                    INSERT INTO subscription_records
                    (user_id, package_key, ls_sub_id, credits_per_month, status, created_at, last_credit_grant)
                    VALUES (:uid, :pkg, :lsid, :cp_month, 'active', NOW(), NULL)
                """),
                {
                    "uid": user_id,
                    "pkg": pkg_key,
                    "lsid": ls_sub_id,
                    "cp_month": pkg["credit_per_month"]
                }
            )
            db.commit()
        except Exception:
            db.rollback()
            raise

    elif event_name in (
        "subscription_updated",
        "subscription_cancelled",
        "subscription_expired",
        "subscription_payment_failed"
    ):
        ls_sub_id = payload["data"]["id"]
        status_map = {
            "subscription_cancelled": "cancelled",
            "subscription_expired": "expired",
            "subscription_payment_failed": "payment_failed"
        }
        new_status = status_map.get(event_name)
        if new_status:
            db.execute(
                text("UPDATE subscription_records SET status = :st, updated_at = NOW() WHERE ls_sub_id = :lsid"),
                {"st": new_status, "lsid": ls_sub_id}
            )
            db.commit()

    return {"ok": True}


@router.get("/my-subscription")
def my_subscription(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db)
):
    user = get_auth_user(authorization, db)
    row = db.execute(
        text("""
            SELECT package_key, ls_sub_id, credits_per_month, status
            FROM subscription_records
            WHERE user_id = :uid
            ORDER BY created_at DESC LIMIT 1
        """),
        {"uid": user.id}
    ).mappings().first()

    if not row:
        return {
            "hasSubscription": False,
            "packageKey": None,
            "creditsPerMonth": 0,
            "status": None,
            "renewAt": None,
            "canCancel": False
        }
    return {
        "hasSubscription": True,
        "packageKey": row["package_key"],
        "creditsPerMonth": row["credits_per_month"],
        "status": row["status"],
        "renewAt": None,
        "canCancel": row["status"] == "active"
    }


@router.post("/cancel-subscription")
def cancel_subscription(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db)
):
    user = get_auth_user(authorization, db)
    row = db.execute(
        text("""
            SELECT ls_sub_id
            FROM subscription_records
            WHERE user_id = :uid AND status = 'active'
            LIMIT 1
        """),
        {"uid": user.id}
    ).mappings().first()
    if not row:
        raise HTTPException(status_code=400, detail="No active subscription found")

    ls_sub_id = row["ls_sub_id"]
    headers = {"Authorization": f"Bearer {LS_API_KEY}"}
    resp = requests.post(
        f"https://api.lemonsqueezy.com/v1/subscriptions/{ls_sub_id}/cancel",
        headers=headers,
        timeout=20
    )
    if not resp.ok:
        raise HTTPException(status_code=400, detail=f"LemonSqueezy cancel failed: {resp.text}")

    db.execute(
        text("UPDATE subscription_records SET status = 'cancelled', updated_at = NOW() WHERE ls_sub_id = :lsid"),
        {"lsid": ls_sub_id}
    )
    db.commit()
    return {"ok": True}
