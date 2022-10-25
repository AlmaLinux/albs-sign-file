from fastapi import FastAPI
from sign_file.api.routes import router
from sign_file.config import settings

app = FastAPI()
app.include_router(router)
