# init_db.py
from app.database import engine, Base
from app.models import (
    DBUser,
    PasswordResetToken,
    RechargeOrder,
    CreditTransaction,
    PaddleWebhookRecord,
    PaddlePricePlan
)

Base.metadata.create_all(bind=engine)
print("✅ All tables created")