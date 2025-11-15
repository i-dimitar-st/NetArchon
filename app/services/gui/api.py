from functools import cache
from typing import Any, Callable, Generator

from flask import Request, Response, jsonify, make_response, session, stream_with_context

from app.config.config import config
from app.services.dns.db import DnsQueryHistoryDb
from app.services.gui.auth import decode_and_verify_bearer_token
from app.services.gui.models import RequestCategory, RequestQuery, RequestResource, RequestType
from app.services.gui.utils import (
    add_to_blacklist,
    add_to_whitelist,
    clear_system_logs,
    delete_from_blacklist,
    delete_from_whitelist,
    generate_dashboard_cards,
    generate_system_stats,
    get_blacklist,
    get_dhcp_leases,
    get_dhcp_statistics,
    get_dns_history,
    get_dns_statistics,
    get_metrics,
    get_network_interfaces,
    get_system_logs,
    get_whitelist,
)
from app.services.neural_net.neural_net import NNDomainClassifierService


class ApiGateway:
    """Central API handler class."""

    @classmethod
    @cache
    def _call_handlers_map(cls) -> dict[RequestCategory, Callable[[RequestQuery], Response]]:
        """
        Return a cached mapping of request categories to handler methods.
        """
        return {
            RequestCategory.INFO: cls._handle_info,
            RequestCategory.DASHBOARD: cls._handle_dashboard,
            RequestCategory.BLACKLIST: cls._handle_blacklist,
            RequestCategory.WHITELIST: cls._handle_whitelist,
            RequestCategory.DNS: cls._handle_dns,
            RequestCategory.DHCP: cls._handle_dhcp,
            RequestCategory.NEURAL_NET: cls._handle_neural_net,
            RequestCategory.METRICS: cls._handle_metrics,
            RequestCategory.CONFIG: cls._handle_config,
            RequestCategory.LOGS: cls._handle_logs,
        }

    @staticmethod
    def _make_response(
        success: bool, status_code: int, payload: Any = None, error: str | None = None
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
                    "payload": payload if payload is not None else {},
                    "error": error,
                }
            ),
            status_code,
        )

    @classmethod
    def handle_request(cls, request: Request) -> Response:
        """
        Main entry point for processing an incoming API request.
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
        _data = request.get_json(silent=True)
        if not _data:
            return cls._make_response(
                success=False,
                error="Unsupported media type ensure application/json header is set",
                status_code=415,
            )

        # --- Query parsing ---
        _query = RequestQuery(data=_data)
        if not _query.is_valid:
            return cls._make_response(success=False, error=_query.error_message, status_code=400)

        # --- Call handler ---
        _call_handler = cls._call_handlers_map().get(_query.category)
        if _call_handler:
            return _call_handler(_query)

        # --- Fallback ---
        return cls._make_response(success=False, error="Invalid request", status_code=500)

    # --- Auth ---
    @classmethod
    def _handle_auth(cls, request: Request) -> Response | None:
        """
        Verify the Authorization header and bearer token.
        Args:
            request: Flask Request object.
        Returns:
            Response on failure, None if auth succeeds.
        """
        auth_header: str = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return cls._make_response(
                success=False, error="Missing or invalid Authorization header", status_code=401
            )

        if not decode_and_verify_bearer_token(
            token=auth_header[7:].strip(), csrf_token=session.get("_csrf_token", "")
        ):
            return cls._make_response(success=False, error="Unauthorized", status_code=403)

        return None

    # --- Handlers ---

    @classmethod
    def _handle_dashboard(cls, query: RequestQuery) -> Response:
        print("handling dashboard request:", query.raw)
        if query.type == RequestType.GET and query.resource == RequestResource.DATA:
            return cls._make_response(
                success=True, payload=generate_dashboard_cards(), status_code=200
            )

        return cls._make_response(
            success=False, error=f"Invalid dashboard action '{query.type.value}'", status_code=400
        )

    @classmethod
    def _handle_info(cls, query: RequestQuery) -> Response:
        if query.type == RequestType.GET and query.resource == RequestResource.SYSTEM:
            return cls._make_response(
                success=True, payload=generate_system_stats(), status_code=200
            )

        return cls._make_response(
            success=False, error=f"Invalid info action '{query.type.value}'", status_code=400
        )

    @classmethod
    def _handle_blacklist(cls, query: RequestQuery) -> Response:
        if query.type == RequestType.GET:
            return cls._make_response(success=True, payload=get_blacklist(), status_code=200)

        if query.payload and query.type == RequestType.ADD:
            add_to_blacklist(query.payload)
            return cls._make_response(success=True, status_code=200)

        if query.payload and query.type == RequestType.REMOVE:
            delete_from_blacklist(query.payload)
            return cls._make_response(success=True, status_code=200)

        return cls._make_response(
            success=False,
            error=f"Invalid blacklist action '{query.type.value}'",
            status_code=400,
        )

    @classmethod
    def _handle_whitelist(cls, query: RequestQuery) -> Response:

        if query.type == RequestType.GET:
            return cls._make_response(success=True, payload=get_whitelist(), status_code=200)

        if query.payload and query.type == RequestType.ADD:
            add_to_whitelist(query.payload)
            return cls._make_response(success=True, status_code=200)

        if query.payload and query.type == RequestType.REMOVE:
            delete_from_whitelist(query.payload)
            return cls._make_response(success=True, status_code=200)

        return cls._make_response(
            success=False,
            error=f"Invalid whitelist action '{query.type.value}'",
            status_code=400,
        )

    @classmethod
    def _handle_dns(cls, query: RequestQuery) -> Response:
        if query.type == RequestType.GET and query.resource == RequestResource.HISTORY:
            return cls._make_response(success=True, payload=get_dns_history(), status_code=200)

        if query.type == RequestType.GET and query.resource == RequestResource.STATS:
            return cls._make_response(success=True, payload=get_dns_statistics(), status_code=200)

        if query.type == RequestType.CLEAR:
            DnsQueryHistoryDb.clear_history()
            return cls._make_response(success=True, status_code=200)

        return cls._make_response(
            success=False,
            error=f"Invalid DNS action '{query.type.value}'",
            status_code=400,
        )

    @classmethod
    def _handle_dhcp(cls, query: RequestQuery) -> Response:
        if query.type == RequestType.GET and query.resource == RequestResource.LEASES:
            return cls._make_response(success=True, payload=get_dhcp_leases(), status_code=200)

        if query.type == RequestType.GET and query.resource == RequestResource.STATS:
            return cls._make_response(success=True, payload=get_dhcp_statistics(), status_code=200)

        return cls._make_response(
            success=False,
            error=f"Invalid DHCP request",
            status_code=400,
        )

    @classmethod
    def _handle_metrics(cls, query: RequestQuery) -> Response:
        if query.type == RequestType.GET:
            return cls._make_response(success=True, payload=get_metrics(), status_code=200)

        return cls._make_response(
            success=False,
            error=f"Invalid metrics action '{query.type.value}'",
            status_code=400,
        )

    @classmethod
    def _handle_config(cls, query: RequestQuery) -> Response:
        if query.type == RequestType.GET:
            return cls._make_response(
                success=True,
                payload=dict(config.get_config()),
                status_code=200,
            )

        return cls._make_response(
            success=False,
            error=f"Invalid config action '{query.type.value}'",
            status_code=400,
        )

    @classmethod
    def _handle_logs(cls, query: RequestQuery) -> Response:
        if query.type == RequestType.GET:
            return cls._make_response(success=True, payload=get_system_logs(), status_code=200)

        if query.type == RequestType.CLEAR:
            return cls._make_response(success=clear_system_logs(), status_code=200)

        return cls._make_response(
            success=False,
            error=f"Invalid logs action '{query.type.value}'",
            status_code=400,
        )

    @classmethod
    def _handle_neural_net(cls, query: RequestQuery) -> Response:

        if query.type == RequestType.GET and query.resource == RequestResource.MODEL_AGE:
            return cls._make_response(
                success=True,
                payload={"timestamp": NNDomainClassifierService.get_model_age()},
                status_code=200,
            )

        if query.type == RequestType.TRAIN:

            def _stream_training() -> Generator[str, None, None]:
                try:
                    for training_progress in NNDomainClassifierService.train_new_model():
                        yield cls._make_response(
                            success=True, payload=training_progress.to_dict(), status_code=200
                        ).get_data(as_text=True) + "\n"
                except RuntimeError as err:
                    yield cls._make_response(
                        success=False, payload={"error": str(err)}, status_code=400
                    ).get_data(as_text=True) + "\n"

            return Response(
                stream_with_context(_stream_training()), mimetype="application/x-ndjson"
            )

        if query.payload and query.type == RequestType.PREDICT:
            try:
                return cls._make_response(
                    success=True,
                    payload={
                        "predictions": NNDomainClassifierService.predict_from_domains(
                            domains=query.payload
                        )
                    },
                    status_code=200,
                )
            except Exception as err:
                return cls._make_response(success=False, error=str(err), status_code=400)

        return cls._make_response(
            success=False,
            error=f"Invalid neural net request",
            status_code=400,
        )
