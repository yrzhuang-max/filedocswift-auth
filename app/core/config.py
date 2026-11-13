from dotenv import load_dotenv
import os
from datetime import timedelta

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DELTA = timedelta(hours=24)
