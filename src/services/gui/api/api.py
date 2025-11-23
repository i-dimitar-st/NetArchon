"""API Utilities and Handlers.

Provides functions for processing API requests, retrieving system
and service metrics, managing whitelist/blacklist rules, handling
system logs, and supporting Flask responses (auth, cache control).
"""

from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable, Generator

from flask import (
    Request,
    Response,
    jsonify,
    make_response,
    session,
    stream_with_context,
)

from src.config.config import config
from src.services.dns.db import DnsQueryHistoryDb
from src.services.gui.api.models import (
    RequestCategory,
    RequestQuery,
    RequestResource,
    RequestType,
)
from src.services.gui.utils.auth import decode_and_verify_bearer_token
from src.services.gui.utils.utils import (
    add_to_blacklist,
    add_to_whitelist,
    clear_system_logs,
    delete_from_blacklist,
    delete_from_whitelist,
    extract_auth_bearer,
    generate_dashboard_cards,
    generate_system_stats,
    get_blacklist,
    get_dhcp_leases,
    get_dhcp_statistics,
    get_dns_history,
    get_dns_statistics,
    get_metrics,
    get_system_logs,
    get_whitelist,
)
from src.services.neural_net.neural_net import (
    NNDomainClassifierService,
)


class ApiGateway:
    """Central API handler class."""

    _handlers = {}

    @classmethod
    def init(cls) -> None:
        """Initialize API handlers mapping."""
        cls._handlers = {
            RequestCategory.DASHBOARD: cls._handle_dashboard,
            RequestCategory.INFO: cls._handle_info,
            RequestCategory.CONFIG: cls._handle_config,
            RequestCategory.DNS: cls._handle_dns,
            RequestCategory.DHCP: cls._handle_dhcp,
            RequestCategory.BLACKLIST: cls._handle_blacklist,
            RequestCategory.WHITELIST: cls._handle_whitelist,
            RequestCategory.METRICS: cls._handle_metrics,
            RequestCategory.LOGS: cls._handle_logs,
            RequestCategory.NEURAL_NET: cls._handle_neural_net,
        }

    @staticmethod
    def _generate_response(
        success: bool,
        status_code: int,
        payload: Any = None,
        error: str | None = None,
    ) -> Response:
        """Create a standardized JSON response.

        Args:
            success: Whether the request succeeded.
            status_code: HTTP status code.
            payload: Optional response data.
            error: Optional error message.

        Returns:
            Flask Response object with JSON content.

        """
        return make_response(
            jsonify(
                {
                    "success": success,
                    "payload": (payload if payload is not None else {}),
                    "error": error,
                }
            ),
            status_code,
        )

    @classmethod
    def _not_found_response(cls,message: str = "Invalid request.") -> Response:
        """Return 404 for unmatched handler conditions.

        Args:
            message: Optional custom error message.

        Returns:
            Flask Response object with error status.

        """
        return cls._generate_response(success=False, error=message, status_code=404)

    @classmethod
    def handle_request(cls, request: Request) -> Response:
        """Process incoming API request.
        Handles authentication, validation, and dispatch to the proper handler.

        Args:
            request: Flask Request object.

        Returns:
            Response object with the result or error.

        """
        # --- Auth ---
        _auth: Response | None = cls._handle_auth(request)
        if _auth:
            return _auth

        # --- JSON validation ---
        _data: Any | None = request.get_json(silent=True)
        if not _data:
            return cls._generate_response(
                success=False,
                error="Expected application/json",
                status_code=415,
            )

        # --- Query parsing ---
        _query = RequestQuery(data=_data)

        if not _query.is_valid:
            return cls._generate_response(
                success=False,
                error=_query.error_message,
                status_code=400,
            )

        _handler = cls._handlers.get(_query.category)
        return _handler(_query) if _handler else cls._not_found_response()

    @staticmethod
    def _not_found_response_decorator(func: Callable) -> Callable:
        """Convert None returns to 400 Bad Request.

        Usage:
            @classmethod
            @_not_found_response_decorator
            def _handle_foo(cls, query):
                if condition:
                    return cls._generate_response(...)
                # implicit None converted to 400 response by decorator
        """

        @wraps(func)
        def wrapper(*args, **kwargs) -> Response:
            return func(*args, **kwargs) or ApiGateway._not_found_response()

        return wrapper

    @classmethod
    @_not_found_response_decorator
    def handle_healtz(cls, request: Request) -> Response | None:
        """Handle health check requests.

        Args:
            request: Flask Request object.

        Returns:
            Response on health check, None otherwise.

        """
        if request.method == "GET":
            return cls._generate_response(
                success=True,
                status_code=200,
                payload={
                    "status": "ok",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            )

    @classmethod
    def _handle_auth(cls, request: Request) -> Response | None:
        """Verify the Authorization header and bearer token.

        Args:
            request: Flask Request object.

        Returns:
            Response on failure, None if auth succeeds.

        """
        _bearer_token = extract_auth_bearer(request)
        if not _bearer_token:
            return cls._generate_response(
                success=False,
                error="Missing or invalid Authorization header",
                status_code=401,
            )

        if not decode_and_verify_bearer_token(
            token=_bearer_token,
            csrf_token=session.get("_csrf_token", ""),
        ):
            return cls._generate_response(
                success=False,
                error="Unauthorized",
                status_code=403,
            )

        return None

    # --- Handlers ---

    @classmethod
    @_not_found_response_decorator
    def _handle_dashboard(cls, query: RequestQuery) -> Response | None:
        if query.type == RequestType.GET and query.resource == RequestResource.DATA:
            return cls._generate_response(
                success=True,
                payload={"dashboard": generate_dashboard_cards()},
                status_code=200,
            )

    @classmethod
    @_not_found_response_decorator
    def _handle_info(cls, query: RequestQuery) -> Response | None:
        if query.type == RequestType.GET and query.resource == RequestResource.SYSTEM:
            return cls._generate_response(
                success=True,
                payload={"info": generate_system_stats()},
                status_code=200,
            )

    @classmethod
    @_not_found_response_decorator
    def _handle_blacklist(cls, query: RequestQuery) -> Response | None:
        if query.type == RequestType.GET:
            return cls._generate_response(
                success=True,
                payload={"blacklist": get_blacklist()},
                status_code=200,
            )

        if query.payload and query.type == RequestType.ADD:
            return cls._generate_response(
                success=add_to_blacklist(query.payload),
                status_code=200,
            )

        if query.payload and query.type == RequestType.REMOVE:
            return cls._generate_response(
                success=delete_from_blacklist(query.payload),
                status_code=200,
            )

    @classmethod
    @_not_found_response_decorator
    def _handle_whitelist(cls, query: RequestQuery) -> Response | None:
        if query.type == RequestType.GET:
            return cls._generate_response(
                success=True,
                payload={"whitelist": get_whitelist()},
                status_code=200,
            )

        if query.payload and query.type == RequestType.ADD:
            return cls._generate_response(
                success=add_to_whitelist(query.payload),
                status_code=200,
            )

        if query.payload and query.type == RequestType.REMOVE:
            return cls._generate_response(
                success=delete_from_whitelist(query.payload),
                status_code=200,
            )

    @classmethod
    @_not_found_response_decorator
    def _handle_dns(cls, query: RequestQuery) -> Response | None:
        if query.type == RequestType.GET and query.resource == RequestResource.HISTORY:
            return cls._generate_response(
                success=True,
                payload={"history": get_dns_history()},
                status_code=200,
            )

        if query.type == RequestType.GET and query.resource == RequestResource.STATS:
            return cls._generate_response(
                success=True,
                payload={"statistics": get_dns_statistics()},
                status_code=200,
            )

        if query.type == RequestType.CLEAR:
            return cls._generate_response(
                success=DnsQueryHistoryDb.clear_history(),
                status_code=200,
            )

    @classmethod
    @_not_found_response_decorator
    def _handle_dhcp(cls, query: RequestQuery) -> Response | None:
        if query.type == RequestType.GET and query.resource == RequestResource.LEASES:
            return cls._generate_response(
                success=True,
                payload={"leases": get_dhcp_leases()},
                status_code=200,
            )

        if query.type == RequestType.GET and query.resource == RequestResource.STATS:
            return cls._generate_response(
                success=True,
                payload={"statistics": get_dhcp_statistics()},
                status_code=200,
            )

    @classmethod
    @_not_found_response_decorator
    def _handle_metrics(cls, query: RequestQuery) -> Response | None:
        if query.type == RequestType.GET:
            return cls._generate_response(
                success=True,
                payload={"metrics": get_metrics()},
                status_code=200,
            )

    @classmethod
    @_not_found_response_decorator
    def _handle_config(cls, query: RequestQuery) -> Response | None:
        if query.type == RequestType.GET:
            return cls._generate_response(
                success=True,
                payload={"config": dict(config.get_config())},
                status_code=200,
            )

    @classmethod
    @_not_found_response_decorator
    def _handle_logs(cls, query: RequestQuery) -> Response | None:
        if query.type == RequestType.GET:
            return cls._generate_response(
                success=True,
                payload={"logs": get_system_logs()},
                status_code=200,
            )

        if query.type == RequestType.CLEAR:
            return cls._generate_response(success=clear_system_logs(), status_code=200)

    @classmethod
    @_not_found_response_decorator
    def _handle_neural_net(cls, query: RequestQuery) -> Response | None:
        if (
            query.type == RequestType.GET
            and query.resource == RequestResource.MODEL_AGE
        ):
            return cls._generate_response(
                success=True,
                payload={"timestamp": NNDomainClassifierService.get_model_age()},
                status_code=200,
            )

        if query.type == RequestType.TRAIN:

            def _stream_training() -> Generator[str, None, None]:
                """Stream training progress as NDJSON with proper resource management.

                Returns:
                    Generator yielding NDJSON strings.

                """
                try:
                    for (
                        training_progress
                    ) in NNDomainClassifierService.train_new_model():
                        yield cls._generate_response(
                            success=True,
                            payload=training_progress.to_dict(),
                            status_code=200,
                        ).get_data(as_text=True) + "\n"
                except Exception as err:
                    yield cls._generate_response(
                        success=False,
                        payload={"error": str(err)},
                        status_code=400,
                    ).get_data(as_text=True) + "\n"

            return Response(
                stream_with_context(_stream_training()),
                mimetype="application/x-ndjson",
            )

        if query.payload and query.type == RequestType.PREDICT:
            try:
                return cls._generate_response(
                    success=True,
                    payload={
                        "predictions": NNDomainClassifierService.predict_from_domains(
                            domains=query.payload
                        )
                    },
                    status_code=200,
                )
            except Exception as err:
                return cls._generate_response(
                    success=False, error=str(err), status_code=400
                )

