"""Generic service-layer exceptions shared by every ZOOMRIYA app.

Services raise these instead of ``HTTPException`` so they stay usable outside
a request (scripts, workers, tests). ``app.shared.errors`` maps them to
HTTP responses. App-specific exceptions subclass ``ServiceError`` in the app.
"""

from __future__ import annotations

from typing import Any


class ServiceError(Exception):
    """Base exception for all service-layer errors.

    All service-specific exceptions should inherit from this class to allow
    catching all service errors with a single except clause when needed.
    """

    def __init__(
        self,
        message: str,
        *,
        details: dict[str, Any] | None = None,
        cause: Exception | None = None
    ):
        super().__init__(message)
        self.message = message
        self.details = details or {}
        self.cause = cause

        # Chain the exception if a cause is provided
        if cause is not None:
            self.__cause__ = cause



class ValidationError(ServiceError):
    """Raised when input validation fails for service operations.

    This includes invalid parameters, malformed requests, or business rule
    violations that prevent normal processing.
    """

    def __init__(
        self,
        message: str,
        *,
        field: str | None = None,
        value: Any = None,
        details: dict[str, Any] | None = None,
        cause: Exception | None = None
    ):
        super().__init__(message, details=details, cause=cause)
        self.field = field
        self.value = value
        if field is not None and details is not None:
            self.details.setdefault("field", field)
        if value is not None and details is not None:
            self.details.setdefault("value", str(value))


class ConfigurationError(ServiceError):
    """Raised when there's a missing or invalid configuration preventing service operation.

    This includes missing API keys, invalid paths, or misconfigured services
    that require administrative attention.
    """

    def __init__(
        self,
        message: str,
        *,
        config_key: str | None = None,
        details: dict[str, Any] | None = None,
        cause: Exception | None = None
    ):
        super().__init__(message, details=details, cause=cause)
        self.config_key = config_key
        if config_key is not None and details is not None:
            self.details.setdefault("config_key", config_key)


class ExternalServiceError(ServiceError):
    """Raised when an external service or dependency fails or is unavailable.

    This includes model loading failures, external API errors, database
    connection issues, or third-party service unavailability.
    """

    def __init__(
        self,
        message: str,
        *,
        service_name: str | None = None,
        details: dict[str, Any] | None = None,
        cause: Exception | None = None,
        retryable: bool = True
    ):
        super().__init__(message, details=details, cause=cause)
        self.service_name = service_name
        self.retryable = retryable
        if service_name is not None and details is not None:
            self.details.setdefault("service_name", service_name)
        if details is not None:
            self.details.setdefault("retryable", retryable)


class ResourceError(ServiceError):
    """A storage resource could not be written (e.g. disk full)."""
