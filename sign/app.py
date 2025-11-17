import logging
import sys

import sentry_sdk
from fastapi import FastAPI

from sign.api.routes import router
from sign.config import settings
from sign.db.helpers import db_is_connected

logging.basicConfig(
    level="INFO",
    format="[%(asctime)s] %(levelname)s - %(message)s",
)

logger = logging.getLogger(__name__)

if settings.sentry_dsn:
    sentry_sdk.init(
        dsn=settings.sentry_dsn,
        traces_sample_rate=settings.sentry_traces_sample_rate,
        environment=settings.sentry_environment,
        ignore_errors=[
            ConnectionResetError,
        ],
    )

app = FastAPI(root_path=settings.root_url)
app.include_router(router)


@app.on_event("startup")
async def startup_event():
    """
    Verify database connectivity on application startup.
    """
    logger.info("Checking database connection...")
    db_health = db_is_connected()
    if db_health:
        logger.info("Database connection successful")
        return
    logger.error(
        "Database connection failed!\n"
        "Please check:\n"
        "\t1. Database server is running\n"
        "\t2. Connection credentials are correct\n"
        "\t3. Database exists and is accessible\n"
        "\t4. Network connectivity to database\n"
        "Application startup failed due to database connectivity issues"
    )
    sys.exit(1)
