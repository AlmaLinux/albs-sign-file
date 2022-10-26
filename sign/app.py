from fastapi import FastAPI
from sign.api.routes import router
from sign.config import settings
import logging

logging.basicConfig(
    level="INFO",
    format="[%(asctime)s] %(levelname)s - %(message)s"
)

app = FastAPI()
app.include_router(router)
