#!/bin/bash
set -eo pipefail

# Default variables
ENV_FILE_PATH=""
INSTALL_BIN_PATH="/usr/local/bin/aurora-iam"
CONFIG_DIR="/etc/aurora-iam"
ENV_DEST_PATH="${CONFIG_DIR}/.env"
TLS_SRC_DIR=".local/tls"
TLS_DEST_DIR="${CONFIG_DIR}/tls"
SYSTEMD_SERVICE_DEST="/etc/systemd/system/aurora-iam.service"
ADMIN_API_TOKEN_PATH="/tmp/admin-api-token"

generate_master_key() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 32 | tr -d '\n'
        return
    fi

    head -c 32 /dev/urandom | base64 | tr -d '\n'
}

ensure_core_secret_master_key() {
    local current_key
    current_key="$(grep -E '^CORE_SECRET_MASTER_KEY=' "$ENV_FILE_PATH" | head -n1 | cut -d'=' -f2- | tr -d '"')"
    if [ -n "$current_key" ]; then
        return
    fi

    local generated_key
    generated_key="$(generate_master_key)"

    local tmp_file
    tmp_file="$(mktemp)"

    awk -v key="$generated_key" '
        BEGIN { replaced = 0 }
        /^CORE_SECRET_MASTER_KEY=/ {
            print "CORE_SECRET_MASTER_KEY=\"" key "\""
            replaced = 1
            next
        }
        { print }
        END {
            if (!replaced) {
                print "CORE_SECRET_MASTER_KEY=\"" key "\""
            }
        }
    ' "$ENV_FILE_PATH" > "$tmp_file"

    mv "$tmp_file" "$ENV_FILE_PATH"
    echo " Generated CORE_SECRET_MASTER_KEY in $ENV_FILE_PATH"
}

setup_database() {
    echo " Setting up PostgreSQL with mTLS..."
    
    # Extract DB config from env
    local db_name=$(grep -E '^PSQL_DBNAME=' "$ENV_FILE_PATH" | cut -d'=' -f2 | tr -d '"')
    local db_user=$(grep -E '^PSQL_USER=' "$ENV_FILE_PATH" | cut -d'=' -f2 | tr -d '"')
    local db_pass=$(grep -E '^PSQL_PASSWORD=' "$ENV_FILE_PATH" | cut -d'=' -f2 | tr -d '"')

    # Install if missing
    if ! command -v psql >/dev/null 2>&1; then
        sudo apt-get update && sudo apt-get install -y postgresql postgresql-contrib
    fi

    # Configure TLS
    local pg_conf=$(sudo find /etc/postgresql -name postgresql.conf | head -n1)
    if [ -z "$pg_conf" ]; then
        echo " Error: postgresql.conf not found."
        return 1
    fi
    local pg_dir=$(dirname "$pg_conf")
    local certs_dir="${pg_dir}/certs"

    sudo mkdir -p "$certs_dir"
    sudo cp "${TLS_SRC_DIR}/ca/ca.crt" "${certs_dir}/ca.crt"
    sudo cp "${TLS_SRC_DIR}/postgres/server.crt" "${certs_dir}/server.crt"
    sudo cp "${TLS_SRC_DIR}/postgres/server.key" "${certs_dir}/server.key"
    
    sudo chown postgres:postgres -R "$certs_dir"
    sudo chmod 600 "${certs_dir}/server.key"

    sudo sed -i "s/^#\?ssl =.*/ssl = on/" "$pg_conf"
    sudo sed -i "s|^#\?ssl_ca_file =.*|ssl_ca_file = '${certs_dir}/ca.crt'|" "$pg_conf"
    sudo sed -i "s|^#\?ssl_cert_file =.*|ssl_cert_file = '${certs_dir}/server.crt'|" "$pg_conf"
    sudo sed -i "s|^#\?ssl_key_file =.*|ssl_key_file = '${certs_dir}/server.key'|" "$pg_conf"

    sudo systemctl restart postgresql

    # Create DB and User
    sudo -u postgres psql -c "CREATE DATABASE ${db_name};" || true
    sudo -u postgres psql -c "CREATE USER ${db_user} WITH PASSWORD '${db_pass}';" || true
    sudo -u postgres psql -c "ALTER USER ${db_user} WITH PASSWORD '${db_pass}';" || true
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE ${db_name} TO ${db_user};" || true
    sudo -u postgres psql -d "${db_name}" -c "GRANT ALL ON SCHEMA public TO ${db_user};" || true
}

# Print usage function
usage() {
    echo "Usage: $0 -e <path-to-env-file>"
    echo "  -e    Path to the environment configuration file (required)"
    exit 1
}

# Parse arguments
while getopts "e:" opt; do
    case "$opt" in
        e)
            ENV_FILE_PATH="$OPTARG"
            ;;
        *)
            usage
            ;;
    esac
done

if [ -z "$ENV_FILE_PATH" ]; then
    echo "Error: Environment file is required."
    usage
fi

if [ ! -f "$ENV_FILE_PATH" ]; then
    echo "Error: Environment file not found at $ENV_FILE_PATH"
    exit 1
fi

ensure_core_secret_master_key

# Extract port from env file for final output
APP_HTTP_PORT=$(grep '^APP_HTTP_PORT=' "$ENV_FILE_PATH" | cut -d'=' -f2 | tr -d '"'\'' ')
APP_HTTP_PORT="${APP_HTTP_PORT:-8000}"

echo "=========================================="
echo " Starting Aurora IAM Installer"
echo "=========================================="

echo "[1/4] Building Go Binary..."
GO_BIN=$(command -v go || echo "/usr/local/go/bin/go")
$GO_BIN build -o bin/aurora-iam ./cmd/server

echo "[2/4] Setting up Database..."
setup_database

echo "[3/4] Setting up Service User..."
setup_service_user() {
    if ! getent group aurora >/dev/null; then
        sudo groupadd aurora
    fi
    if ! id aurora-iam >/dev/null 2>&1; then
        sudo useradd -r -s /bin/false -g aurora aurora-iam
    fi
}
setup_service_user

echo "[4/4] Installing and starting service..."
# Stop the running service first so the binary can be replaced safely.
sudo systemctl stop aurora-iam.service >/dev/null 2>&1 || true
# Clear previous bootstrap token outputs to avoid stale key print.
sudo rm -f "$ADMIN_API_TOKEN_PATH" >/dev/null 2>&1 || true

# Install the new binary atomically to avoid "Text file busy" errors.
sudo install -m 755 bin/aurora-iam "$INSTALL_BIN_PATH"

# Create config directory and copy env file
sudo mkdir -p "$CONFIG_DIR"
sudo cp "$ENV_FILE_PATH" "$ENV_DEST_PATH"
sudo chmod 600 "$ENV_DEST_PATH"
sudo chown -R aurora-iam:aurora "$CONFIG_DIR"

if [ -d "$TLS_SRC_DIR" ]; then
    sudo rm -rf "$TLS_DEST_DIR"
    sudo mkdir -p "$TLS_DEST_DIR"
    sudo cp -R "$TLS_SRC_DIR"/. "$TLS_DEST_DIR"/
    sudo chown -R aurora-iam:aurora "$TLS_DEST_DIR"
    sudo chmod 700 "$TLS_DEST_DIR"
    sudo find "$TLS_DEST_DIR" -type d -exec chmod 700 {} +
    sudo find "$TLS_DEST_DIR" -type f -name '*.crt' -exec chmod 644 {} +
    sudo find "$TLS_DEST_DIR" -type f -name '*.key' -exec chmod 600 {} +
fi

sudo cp package/aurora-iam.service "$SYSTEMD_SERVICE_DEST"
sudo systemctl daemon-reload
sudo systemctl enable aurora-iam.service
sudo systemctl restart aurora-iam.service

# Wait a moment for the application to bootstrap and write the token
sleep 2

ADMIN_API_KEY=""
if sudo test -s "$ADMIN_API_TOKEN_PATH"; then
    ADMIN_API_KEY="$(sudo cat "$ADMIN_API_TOKEN_PATH" | tr -d '\r\n')"
    sudo rm -f "$ADMIN_API_TOKEN_PATH"
fi

echo "=========================================="
echo " Service Status"
sudo systemctl status aurora-iam --no-pager -l
echo " Access URL: http://localhost:${APP_HTTP_PORT}"
if [ -n "$ADMIN_API_KEY" ]; then
    echo " Admin API key: ${ADMIN_API_KEY}"
fi
echo "=========================================="
