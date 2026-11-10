"""Centralized mapping from generic exceptions to HTTP responses.

Service-layer code signals well-known conditions by raising plain Python
exceptions instead of ``HTTPException``, so services stay usable outside of a
request context (scripts, workers, tests):

- ``LookupError``     -> a requested resource does not exist -> 404
- ``PermissionError`` -> the caller may not access/act on it -> 403

plus the generic ``app.shared.exceptions`` types. Every app calls
``register_exception_handlers(app)`` and then registers its own handlers, so
all ZOOMRIYA APIs answer with the same ``{"detail": ...}`` error shape.

This intentionally does NOT catch ``ValueError``/``TypeError``: they are used
for many unrelated validation failures and don't share a single correct status
code, so they're left for each route to handle explicitly.
"""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.shared.exceptions import (
    ConfigurationError,
    ExternalServiceError,
    ResourceError,
    ValidationError,
)


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(LookupError)
    async def handle_lookup_error(request: Request, exc: LookupError) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc) or "Not found"})

    @app.exception_handler(PermissionError)
    async def handle_permission_error(request: Request, exc: PermissionError) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc) or "Forbidden"})

    @app.exception_handler(ValidationError)
    async def handle_validation_error(
        request: Request, exc: ValidationError
    ) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @app.exception_handler(ConfigurationError)
    async def handle_configuration_error(
        request: Request, exc: ConfigurationError
    ) -> JSONResponse:
        return JSONResponse(status_code=500, content={"detail": str(exc)})

    @app.exception_handler(ExternalServiceError)
    async def handle_external_service_error(
        request: Request, exc: ExternalServiceError
    ) -> JSONResponse:
        # External service issues are typically 503 (service unavailable)
        status_code = 503 if getattr(exc, 'retryable', True) else 502
        return JSONResponse(status_code=status_code, content={"detail": str(exc)})

    @app.exception_handler(ResourceError)
    async def handle_resource_error(
        request: Request, exc: ResourceError
    ) -> JSONResponse:
        # 507 Insufficient Storage
        return JSONResponse(status_code=507, content={"detail": str(exc)})
