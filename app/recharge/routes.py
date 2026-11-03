import uuid
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
import stripe

from app.auth.deps import UserDep
from app.db.deps import DbDep
from app.recharge.constants import CREDIT_PACKAGES
from app.settings import settings

router = APIRouter(prefix="/recharge")
stripe.api_key = settings.STRIPE_SECRET_KEY


class CreateOrderSchema(BaseModel):
    packageKey: str


@router.post("/create-order")
async def create_order(
    body: CreateOrderSchema,
    user: UserDep,
    db: DbDep
):
    pkg = CREDIT_PACKAGES.get(body.packageKey)
    if not pkg:
        raise HTTPException(status_code=400, detail="Invalid credit package")

    credit_add = pkg["credit"]
    amount_cents = pkg["cents"]
    order_no = f"RC{uuid.uuid4().hex[:16].upper()}"

    async with db.transaction():
        # 写入pending订单
        await db.execute(
            """
            INSERT INTO recharge_order(order_no, user_id, amount_cents, credit_add, status)
            VALUES ($1, $2, $3, $4, 'pending')
            """,
            order_no, user.id, amount_cents, credit_add
        )

        # 创建Stripe Checkout Session
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[
                {
                    "price_data": {
                        "currency": "usd",
                        "unit_amount": amount_cents,
                        "product_data": {
                            "name": f"{credit_add} OCR Conversion Credits",
                            "description": "Permanent OCR credits for scanned PDF conversion",
                        },
                    },
                    "quantity": 1,
                }
            ],
            mode="payment",
            success_url=f"{settings.SITE_URL}/dashboard/recharge/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{settings.SITE_URL}/dashboard/recharge",
            metadata={
                "order_no": order_no,
                "user_id": str(user.id)
            }
        )

        await db.execute(
            "UPDATE recharge_order SET stripe_session_id = $1 WHERE order_no = $2",
            session.id, order_no
        )

    return {"ok": True, "checkoutUrl": session.url}


@router.post("/webhook")
async def stripe_webhook(
    request: Request,
    db: DbDep
):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")
    if not sig_header:
        raise HTTPException(status_code=400, detail="Missing stripe-signature header")

    try:
        event = stripe.Webhook.construct_event(
            payload,
            sig_header,
            settings.STRIPE_WEBHOOK_SECRET
        )
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid signature")

    if event.type != "checkout.session.completed":
        return {"ok": True}

    session = event.data.object
    order_no = session.metadata["order_no"]
    user_id = int(session.metadata["user_id"])

    row = await db.fetchrow(
        "SELECT id, user_id, credit_add, status FROM recharge_order WHERE order_no = $1",
        order_no
    )
    if not row:
        return {"ok": True}
    if row["status"] == "success":
        return {"ok": True}

    async with db.transaction():
        # 更新订单状态
        await db.execute(
            """UPDATE recharge_order
            SET status='success', pay_time = NOW()
            WHERE order_no = $1""",
            order_no
        )
        # 增加点数
        await db.execute(
            """UPDATE user_credit
            SET balance = balance + $1, updated_at = NOW()
            WHERE user_id = $2""",
            row["credit_add"], user_id
        )
        # 写入流水记录
        await db.execute(
            """INSERT INTO credit_transaction(user_id, amount, type, source, related_id, remark)
            VALUES ($1, $2, 'recharge', 'stripe', $3, 'Stripe credit package purchase')""",
            user_id, row["credit_add"], order_no
        )
    return {"ok": True}
