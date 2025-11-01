from typing import Any

from flask import Request, Response, jsonify, make_response, session, stream_with_context

from app.config.config import config
from app.services.dns.db import DnsQueryHistoryDb
from app.services.gui.auth import decode_and_verify_bearer_token
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

    @staticmethod
    def _make_response(
        success: bool, status_code: int, payload: Any = None, error: str | None = None
    ) -> Response:
        response_body = {
            "success": success,
            "payload": payload if payload is not None else {},
            "error": error,
        }
        return make_response(jsonify(response_body), status_code)

    @classmethod
    def handle_request(cls, request: Request) -> Response:

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return cls._make_response(
                success=False, error="Missing or invalid Authorization header", status_code=401
            )

        if not decode_and_verify_bearer_token(
            token=auth_header[7:].strip(), csrf_token=session.get("_csrf_token", "")
        ):
            return cls._make_response(success=False, error="Unauthorized", status_code=401)

        _req_data: Any | None = request.get_json(silent=True)
        if not _req_data:
            return cls._make_response(success=False, error="Empty or invalid JSON", status_code=400)

        _type = _req_data.get("type")
        _category = _req_data.get("category")
        _payload = _req_data.get("payload")

        # Dispatch by category
        handler_name = f"_handle_{_category.replace('-', '_')}" if _category else ""
        handler = getattr(cls, handler_name, None)
        if handler:
            return handler(_type, _payload)

        # Actions not bound to a category
        action_name = f"_action_{_type.replace('-', '_')}" if _type else ""
        action = getattr(cls, action_name, None)
        if action:
            return action(_payload)

        return cls._make_response(
            success=False,
            error=f"Invalid action: {_type} or category: {_category}",
            status_code=500,
        )

    # --- Category handlers ---
    @classmethod
    def _handle_blacklist(cls, _type: str, _payload: Any):
        if _type == "add":
            add_to_blacklist(_payload)
            return cls._make_response(success=True, status_code=200)
        if _type == "remove":
            delete_from_blacklist(_payload)
            return cls._make_response(success=True, status_code=200)
        if _type == "get":
            return cls._make_response(success=True, payload=get_blacklist(), status_code=200)
        return cls._make_response(
            success=False, error=f"Invalid blacklist action '{_type}'", status_code=400
        )

    @classmethod
    def _handle_whitelist(cls, _type: str, _payload: Any):
        if _type == "add":
            add_to_whitelist(_payload)
            return cls._make_response(success=True, status_code=200)
        if _type == "remove":
            delete_from_whitelist(_payload)
            return cls._make_response(success=True, status_code=200)
        if _type == "get":
            return cls._make_response(success=True, payload=get_whitelist(), status_code=200)
        return cls._make_response(
            success=False, error=f"Invalid whitelist action '{_type}'", status_code=400
        )

    @classmethod
    def _handle_dns_history(cls, _type: str, _payload: Any):
        if _type == "get":
            return cls._make_response(success=True, payload=get_dns_history(), status_code=200)
        if _type == "get-stats":
            return cls._make_response(success=True, payload=get_dns_statistics(), status_code=200)
        if _type == "clear":
            DnsQueryHistoryDb.clear_history()
            return cls._make_response(success=True, status_code=200)
        return cls._make_response(
            success=False, error=f"Invalid DNS history action '{_type}'", status_code=400
        )

    @classmethod
    def _handle_dhcp_leases(cls, _type: str, _payload: Any):
        if _type == "get":
            return cls._make_response(success=True, payload=get_dhcp_leases(), status_code=200)
        if _type == "get-stats":
            return cls._make_response(success=True, payload=get_dhcp_statistics(), status_code=200)
        return cls._make_response(
            success=False, error=f"Invalid DHCP leases action '{_type}'", status_code=400
        )

    @classmethod
    def _handle_metrics(cls, _type: str, _payload: Any):
        if _type == "get":
            return cls._make_response(success=True, payload=get_metrics(), status_code=200)
        return cls._make_response(
            success=False, error=f"Invalid metrics action '{_type}'", status_code=400
        )

    @classmethod
    def _handle_config(cls, _type: str, _payload: Any):
        if _type == "get":
            return cls._make_response(
                success=True,
                payload=dict(config.get_config()),
                status_code=200,
            )
        return cls._make_response(
            success=False, error=f"Invalid config action '{_type}'", status_code=400
        )

    @classmethod
    def _handle_logs(cls, _type: str, _payload: Any):
        if _type == "get":
            return cls._make_response(success=True, payload=get_system_logs(), status_code=200)
        if _type == "clear":
            return cls._make_response(success=clear_system_logs(), status_code=200)
        return cls._make_response(
            success=False, error=f"Invalid logs action '{_type}'", status_code=400
        )

    @classmethod
    def _handle_stats(cls, _type: str, _payload: Any):
        if _type == "get-system":
            return cls._make_response(
                success=True, payload=generate_system_stats(), status_code=200
            )
        return cls._make_response(
            success=False, error=f"Invalid stats action '{_type}'", status_code=200
        )

    @classmethod
    def _handle_neural_net(cls, type: str, payload: Any):

        if type == 'get-model-age':
            return cls._make_response(
                success=True,
                payload={"timestamp": NNDomainClassifierService.get_model_age()},
                status_code=200,
            )

        if type == 'train-new-model':

            def stream_training():
                try:
                    for training_progress in NNDomainClassifierService.train_new_model():
                        res = cls._make_response(
                            success=True, payload=training_progress.to_dict(), status_code=200
                        )
                        yield res.get_data(as_text=True) + "\n"
                except RuntimeError as e:
                    res = cls._make_response(
                        success=False, payload={"error": str(e)}, status_code=400
                    )
                    yield res.get_data(as_text=True) + "\n"

            return Response(stream_with_context(stream_training()), mimetype="application/x-ndjson")

        if type == 'predict':
            try:
                predictions = NNDomainClassifierService.predict_from_domains(domains=payload)
                print(predictions)
                return cls._make_response(
                    success=True, payload={"predictions": predictions}, status_code=200
                )
            except Exception as err:
                return cls._make_response(success=False, error=str(err), status_code=400)

    @classmethod
    def _action_get_network_interfaces(cls, _payload: Any):
        return cls._make_response(success=True, payload=get_network_interfaces(), status_code=200)

    @classmethod
    def _action_get_dashboard_cards(cls, _payload: Any):
        return cls._make_response(success=True, payload=generate_dashboard_cards(), status_code=200)
