import sentry_sdk

from fastapi import FastAPI
from sign.api.routes import router
from sign.config import settings
import logging

logging.basicConfig(
    level="INFO",
    format="[%(asctime)s] %(levelname)s - %(message)s"
)

if settings.sentry_dsn:
    sentry_sdk.init(
        dsn=settings.sentry_dsn,
        traces_sample_rate=settings.sentry_traces_sample_rate,
        environment=settings.sentry_environment,
        ignore_errors=[
            ConnectionResetError
        ],
    )

app = FastAPI(root_path=settings.root_url)
app.include_router(router)
