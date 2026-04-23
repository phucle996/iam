#!/bin/bash
set -e

CA_DIR=".local/tls/ca"
CERT_DIR=".local/tls/postgres"
USER="aurora"

# Generate private key
openssl genrsa -out "${CERT_DIR}/client.key" 2048

# Generate CSR
openssl req -new -key "${CERT_DIR}/client.key" -out "${CERT_DIR}/client.csr" -subj "/CN=${USER}"

# Sign with CA
openssl x509 -req -in "${CERT_DIR}/client.csr" -CA "${CA_DIR}/ca.crt" -CAkey "${CA_DIR}/ca.key" -CAcreateserial -out "${CERT_DIR}/client.crt" -days 3650

# Cleanup
rm "${CERT_DIR}/client.csr"

echo "Generated client.crt and client.key for user ${USER}"
