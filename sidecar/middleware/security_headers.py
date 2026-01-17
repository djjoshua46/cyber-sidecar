from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Adds security headers in a way that won't break Swagger docs.
    - Applies stricter COOP/COEP only to non-doc endpoints by default.
    """

    def __init__(self, app, enable_cross_origin_isolation: bool = True) -> None:
        super().__init__(app)
        self.enable_cross_origin_isolation = enable_cross_origin_isolation

    async def dispatch(self, request: Request, call_next) -> Response:
        response: Response = await call_next(request)

        path = request.url.path or "/"
        is_docs = path.startswith("/docs") or path.startswith("/redoc") or path.startswith("/openapi.json")

        # --- Baseline safe headers (good for APIs) ---
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        response.headers.setdefault("X-Permitted-Cross-Domain-Policies", "none")

        # Cache: prefer no-store for API responses (docs can be cached normally)
        if not is_docs:
            response.headers.setdefault("Cache-Control", "no-store")
            response.headers.setdefault("Pragma", "no-cache")
            response.headers.setdefault("Expires", "0")

        # --- Cross-origin isolation headers (Spectre/site isolation class) ---
        # These can break Swagger if it loads cross-origin assets, so skip for docs endpoints.
        if self.enable_cross_origin_isolation and not is_docs:
            response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
            # "require-corp" is stricter; if it breaks something, switch to "credentialless"
            response.headers.setdefault("Cross-Origin-Embedder-Policy", "require-corp")
            response.headers.setdefault("Cross-Origin-Resource-Policy", "same-site")

        return response
