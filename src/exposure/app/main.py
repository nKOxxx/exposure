"""FastAPI application factory and local-security middleware (spec section 20).

The app binds to loopback only (enforced by the launcher) and every request is
checked by the :class:`SessionGuard`:

* strict Host validation on all requests (DNS-rebinding defense);
* strict Origin + session-token validation on mutating requests (CSRF defense).

The single-page UI is served with the session token injected so a same-origin
page can read it while a cross-origin page cannot. No external scripts or fonts
are referenced.
"""

from __future__ import annotations

from importlib import resources

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

from exposure import APP_VERSION
from exposure.app.api import router
from exposure.app.service import Service, ServiceError
from exposure.config import Settings
from exposure.security.session import SESSION_HEADER, SessionGuard
from exposure.storage.database import Database

_CSP = (
    "default-src 'none'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "base-uri 'none'; "
    "form-action 'none'; "
    "frame-ancestors 'none'"
)


def _load_index() -> str:
    return (resources.files("exposure.app") / "static" / "index.html").read_text(encoding="utf-8")


def create_app(
    settings: Settings,
    service: Service | None = None,
    guard: SessionGuard | None = None,
) -> FastAPI:
    app = FastAPI(title="Exposure", version=APP_VERSION, docs_url=None, redoc_url=None)

    if service is None:
        db = Database(settings)
        db.connect()
        service = Service(settings, db)
    if guard is None:
        guard = SessionGuard(settings.host, settings.port)

    app.state.service = service
    app.state.guard = guard
    app.state.settings = settings

    @app.exception_handler(ServiceError)
    async def _svc_error(_: Request, exc: ServiceError) -> JSONResponse:
        return JSONResponse(status_code=exc.status, content={"error": str(exc)})

    @app.middleware("http")
    async def _security(request: Request, call_next):  # type: ignore[no-untyped-def]
        g: SessionGuard = request.app.state.guard
        allowed, reason = g.check(
            method=request.method,
            host_header=request.headers.get("host"),
            origin=request.headers.get("origin"),
            token=request.headers.get(SESSION_HEADER),
        )
        if not allowed:
            return JSONResponse(status_code=403, content={"error": f"forbidden:{reason}"})
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = _CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    app.include_router(router)

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> HTMLResponse:
        token = request.app.state.guard.token
        html = _load_index().replace("%%SESSION_TOKEN%%", token)
        return HTMLResponse(content=html)

    return app
