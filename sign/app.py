from fastapi import FastAPI
from sign.api.routes import router
import logging

logging.basicConfig(
    level="INFO",
    format="[%(asctime)s] %(levelname)s - %(message)s"
)

app = FastAPI()
app.include_router(router)
