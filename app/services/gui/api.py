from flask import Request, Response, session, stream_with_context

from app.services.dns.db import DnsQueryHistoryDb
from app.services.gui.auth import decode_and_verify_bearer_token
from app.services.gui.utils import (
    add_to_blacklist,
    add_to_whitelist,
    delete_from_blacklist,
    delete_from_whitelist,
    make_response,
)
from app.services.neural_net.neural_net import NNDomainClassifierService


def api_gateway(request: Request):
    """
    Intercept all API calls to /api (or other API endpoints if reused).
    Expects JSON with 'type', 'category', 'payload'.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return make_response(success=False, error="Missing or invalid Authorization header"), 401

    if not decode_and_verify_bearer_token(auth_header[7:].strip(), session.get("_csrf_token", "")):
        return make_response(success=False, error="Unauthorized"), 401

    data = request.get_json(silent=True)
    if not data:
        return make_response(success=False, error="Empty or invalid JSON")

    action = data.get("type")
    category = data.get("category")
    payload = data.get("payload")

    # Blacklist
    if category == "blacklist":
        if action == "add":
            success = add_to_blacklist(payload)
            return make_response(success=success)
        if action == "remove":
            success = delete_from_blacklist(payload)
            return make_response(success=success)

    # Whitelist
    if category == "whitelist":
        if action == "add":
            success = add_to_whitelist(payload)
            return make_response(success=success)
        if action == "remove":
            success = delete_from_whitelist(payload)
            return make_response(success=success)

    # DNS history clear
    if action == "clear-dns-history":
        success = DnsQueryHistoryDb.clear_history()
        return make_response(success=success)

    # Model timestamp
    if action == "get-model-age":
        timestamp = NNDomainClassifierService.get_model_age()
        return make_response(success=True, payload={"timestamp": timestamp})

    # Train new model (streaming)
    if action == "train-new-model":

        def stream_training():
            try:
                for status in NNDomainClassifierService.train_new_model():
                    res, _ = make_response(success=True, payload=status.to_dict())
                    yield res.get_data(as_text=True) + "\n"
            except RuntimeError as e:
                res, _ = make_response(success=False, payload={"error": str(e)})
                yield res.get_data(as_text=True) + "\n"

        return Response(stream_with_context(stream_training()), mimetype="application/x-ndjson")

    # Predictions
    if action == "predict":
        try:
            predictions = NNDomainClassifierService.predict_from_domains(domains=payload)
            return make_response(success=True, payload={"predictions": predictions})
        except Exception as e:
            return make_response(success=False, error=str(e))

    return make_response(success=False, error=f"Invalid action '{action}' or category '{category}'")
