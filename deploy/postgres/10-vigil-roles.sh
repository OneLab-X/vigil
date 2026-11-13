#!/bin/bash
# Runs once, on first start of an empty data volume. Creates the two Vigil roles:
#   vigil_owner — owns tables, runs migrations and SECURITY DEFINER system functions (BYPASSRLS)
#   vigil_app   — runtime role; NOBYPASSRLS, so every query is confined by row-level security
set -euo pipefail
: "${VIGIL_OWNER_DB_PASSWORD:?}" "${VIGIL_APP_DB_PASSWORD:?}"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  -v owner_pw="$VIGIL_OWNER_DB_PASSWORD" -v app_pw="$VIGIL_APP_DB_PASSWORD" <<'SQL'
CREATE ROLE vigil_owner LOGIN PASSWORD :'owner_pw' NOSUPERUSER BYPASSRLS;
CREATE ROLE vigil_app LOGIN PASSWORD :'app_pw' NOSUPERUSER NOBYPASSRLS;
CREATE DATABASE vigil OWNER vigil_owner;
\c vigil
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
SQL
