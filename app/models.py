# app/models.py
from sqlalchemy import Column, Integer, String, DateTime, Boolean
from datetime import datetime, UTC
from app.database import Base
subscription_expires_at = Column(DateTime, nullable=True)


class DBUser(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    credit_balance = Column(Integer, default=0, nullable=False)


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, nullable=False)
    token = Column(String, unique=True, index=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)


class RechargeOrder(Base):
    __tablename__ = "recharge_order"
    id = Column(Integer, primary_key=True, index=True)
    order_no = Column(String, unique=True, index=True, nullable=False)
    user_id = Column(Integer, nullable=False)
    amount_cents = Column(Integer, nullable=False)
    credit_add = Column(Integer, nullable=False)
    status = Column(String, nullable=False)
    stripe_session_id = Column(String, nullable=True)
    pay_time = Column(DateTime, nullable=True)


class CreditTransaction(Base):
    __tablename__ = "credit_transaction"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    amount = Column(Integer, nullable=False)
    type = Column(String, nullable=False)
    source = Column(String, nullable=False)
    related_id = Column(String, nullable=True)
    price_plan_id = Column(Integer, nullable=True)
    remark = Column(String, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(UTC))


class PaddleWebhookRecord(Base):
    __tablename__ = "paddle_webhook_records"
    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String, unique=True, index=True, nullable=False)
    event_type = Column(String, nullable=False)
    user_id = Column(String, nullable=True)
    paddle_customer_id = Column(String, nullable=True)
    subscription_id = Column(String, nullable=True)
    transaction_id = Column(String, nullable=True)
    handled = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(UTC))
    handled_at = Column(DateTime, nullable=True)

class PaddlePricePlan(Base):
    __tablename__ = "paddle_price_plans"

    id = Column(Integer, primary_key=True, index=True)
    price_id = Column(String, unique=True, index=True, nullable=False)
    credit_amount = Column(Integer, nullable=False)
    name = Column(String, nullable=True)
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(UTC))

    # 新增
    plan_type = Column(String, nullable=False, default="one_time")
    # 可选：订阅有效期，用于判断是否还有效
    subscription_expire_at = Column(DateTime, nullable=True)
