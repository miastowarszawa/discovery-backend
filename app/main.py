from fastapi import FastAPI

from app.api.routes.imports import router as imports_router
from app.api.routes.scans import router as scans_router

app = FastAPI(title="Recon PP")
app.include_router(scans_router)
app.include_router(imports_router)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/api/v1/ping")
async def ping():
    return {"message": "pong"}