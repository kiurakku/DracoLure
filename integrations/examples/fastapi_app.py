"""Inject DracoLure into a FastAPI (ASGI) app.

FastAPI is ASGI, not WSGI, so instead of the WSGI middleware class we use the
stdlib client directly from an HTTP middleware. In "block" mode the request is
rejected with 403 when DracoLure recommends blocking.

    pip install ../python-sdk fastapi uvicorn
    uvicorn fastapi_app:app --port 8091
"""

import os

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse

from dracolure import DracoLureClient, DracoLureError

app = FastAPI()
client = DracoLureClient(
    base_url=os.environ.get("DRACOLURE_URL", "http://localhost:5000"),
    api_key=os.environ.get("DRACOLURE_API_KEY"),
)
MODE = os.environ.get("DRACOLURE_MODE", "monitor")  # "monitor" | "block"


@app.middleware("http")
async def dracolure_guard(request: Request, call_next):
    fwd = request.headers.get("x-forwarded-for", "")
    source_ip = fwd.split(",")[0].strip() if fwd else (
        request.client.host if request.client else "0.0.0.0")
    try:
        verdict = client.ingest(
            method=request.method,
            path=request.url.path,
            query=request.url.query,
            user_agent=request.headers.get("user-agent", ""),
            source_ip=source_ip,
        )
        if MODE == "block" and (verdict.blocked or verdict.recommendation == "block"):
            return PlainTextResponse("Forbidden", status_code=403)
    except DracoLureError:
        pass  # fail-open

    return await call_next(request)


@app.get("/")
async def home():
    return {"message": "Protected FastAPI app — probes reported to DracoLure."}
