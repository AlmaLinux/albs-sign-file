import logging
import sys
from contextlib import asynccontextmanager

import sentry_sdk
from fastapi import FastAPI

from sign.api.dependencies import get_backend
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


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """
    Application startup/shutdown handler.

    On startup it verifies database connectivity and eagerly initializes the
    signing backend. Initializing the backend here, before the server starts
    accepting requests, ensures the GPG passphrase prompt
    (``PGPPasswordDB.ask_for_passwords``) runs while the process is still
    attached to the controlling terminal, instead of being deferred to the
    first ``/sign`` request.
    """
    logger.info("Checking database connection...")
    if not db_is_connected():
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
    logger.info("Database connection successful")

    logger.info("Initializing signing backend...")
    get_backend()
    logger.info("Signing backend initialized")

    yield


app = FastAPI(root_path=settings.root_url, lifespan=lifespan)
app.include_router(router)
