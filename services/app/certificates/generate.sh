#!/bin/bash

CERT_DIR="./"
CERT_FILE="$CERT_DIR/cert.pem"
KEY_FILE="$CERT_DIR/key.pem"

mkdir -p "$CERT_DIR"

echo "Generating self-signed certificate..."

openssl req -x509 -newkey rsa:4096 \
  -keyout "$KEY_FILE" \
  -out "$CERT_FILE" \
  -days 3650 -nodes \
  -subj "/C=XX/ST=State/L=City/O=Organization/CN=localhost"

if [ $? -eq 0 ]; then
  echo "Certificate and key created in '$CERT_DIR/'"
else
  echo "Failed to generate certificate."
fi