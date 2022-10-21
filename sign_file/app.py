from fastapi import FastAPI
from .api.routes import router
from .api.signer import pgp

app = FastAPI()
app.include_router(router)
