#!/bin/bash

CERT_DIR="certificates"
CERT_FILE="$CERT_DIR/cert.pem"
KEY_FILE="$CERT_DIR/key.pem"

mkdir -p "$CERT_DIR" && \
openssl req \
  -x509 \
  -newkey rsa:4096 \
  -nodes \
  -keyout "$KEY_FILE" -out "$CERT_FILE" \
  -days 3650 -subj "/C=XX/ST=State/L=City/O=Organization/CN=localhost" && \
echo "Certificate and key created in: $CERT_DIR" || \
echo "Certificate and key created in: $CERT_DIR"

