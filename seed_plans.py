from app.database import SessionLocal
from app.models import PaddlePricePlan

db = SessionLocal()

plan1 = PaddlePricePlan(
    price_id="pri_01m6p2kbqc7cvvxnesyqmwmjhk",
    credit_amount=150,
    name="Points Pack",
    active=True,
    plan_type="one_time"
)
plan2 = PaddlePricePlan(
    price_id="pri_01m6ncgte7p2cxqpd3257y993p",
    credit_amount=300,
    name="Pro Monthly",
    active=True,
    plan_type="monthly"
)
plan3 = PaddlePricePlan(
    price_id="pri_01m6ncmydmh0s8pg37prtkjbkp",
    credit_amount=3600,
    name="Pro Yearly",
    active=True,
    plan_type="yearly"
)

db.add_all([plan1, plan2, plan3])
db.commit()
print("Insert finished")
db.close()
