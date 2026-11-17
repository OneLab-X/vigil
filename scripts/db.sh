#!/usr/bin/env bash
# Local dev Postgres cluster (isolated from any system Postgres). Port 54329.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PGDATA="$ROOT/.local/pg"
PORT="${VIGIL_PG_PORT:-54329}"
case "${1:-start}" in
  start)
    if [ ! -d "$PGDATA" ]; then
      mkdir -p "$ROOT/.local"
      initdb -D "$PGDATA" -U postgres --auth=trust -E UTF8 >/dev/null
      echo "listen_addresses='127.0.0.1'" >> "$PGDATA/postgresql.conf"
      echo "port=$PORT" >> "$PGDATA/postgresql.conf"
      echo "unix_socket_directories='$ROOT/.local'" >> "$PGDATA/postgresql.conf"
      # local dev only: password auth for app roles on TCP, trust for bootstrap superuser
      cat > "$PGDATA/pg_hba.conf" <<HBA
local all postgres trust
host  all postgres 127.0.0.1/32 trust
host  all all 127.0.0.1/32 scram-sha-256
HBA
    fi
    pg_ctl -D "$PGDATA" -l "$ROOT/.local/pg.log" -w status >/dev/null 2>&1 || pg_ctl -D "$PGDATA" -l "$ROOT/.local/pg.log" -w start
    psql -h 127.0.0.1 -p "$PORT" -U postgres -tc "select 1 from pg_roles where rolname='vigil_owner'" | grep -q 1 || psql -h 127.0.0.1 -p "$PORT" -U postgres -v ON_ERROR_STOP=1 <<SQL
create role vigil_owner login password 'vigil_owner_dev' nosuperuser bypassrls; -- migrator + SECURITY DEFINER system functions only; never used by the app
create role vigil_app login password 'vigil_app_dev' nosuperuser nobypassrls;
create database vigil owner vigil_owner;
create database vigil_test owner vigil_owner;
\c vigil
create extension if not exists vector;
create extension if not exists pgcrypto;
\c vigil_test
create extension if not exists vector;
create extension if not exists pgcrypto;
SQL
    echo "postgres ready on 127.0.0.1:$PORT";;
  eval)
    # Dedicated database for the VigilBench evaluation harness (docs/research/EVAL_HARNESS.md). Never the dev database.
    "$0" start >/dev/null
    psql -h 127.0.0.1 -p "$PORT" -U postgres -tc "select 1 from pg_database where datname='vigil_eval'" | grep -q 1 || psql -h 127.0.0.1 -p "$PORT" -U postgres -v ON_ERROR_STOP=1 <<SQL
create database vigil_eval owner vigil_owner;
\c vigil_eval
create extension if not exists vector;
create extension if not exists pgcrypto;
SQL
    VIGIL_OWNER_DATABASE_URL="postgres://vigil_owner:vigil_owner_dev@127.0.0.1:$PORT/vigil_eval" pnpm --dir "$ROOT" --filter @vigil/db migrate
    echo "evaluation database vigil_eval ready";;
  stop) pg_ctl -D "$PGDATA" -w stop;;
  reset) pg_ctl -D "$PGDATA" -w stop || true; rm -rf "$PGDATA"; "$0" start;;
esac
