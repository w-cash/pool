#!/usr/bin/env bash

set -Eeuo pipefail
set +x

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1091
source "$script_dir/common.sh"

require_root
require_command openssl
require_command psql
require_command runuser
require_command python3

[[ $# -eq 1 ]] || die "usage: provision-postgres.sh <settings>"
settings=$1
require_private_regular_file "$settings"

database=$(read_setting "$settings" POSTGRES_DATABASE)
migrator=$(read_setting "$settings" POSTGRES_MIGRATOR_ROLE)
runtime=$(read_setting "$settings" POSTGRES_RUNTIME_ROLE)
for item in "$database" "$migrator" "$runtime"; do
    [[ $item =~ ^[a-z_][a-z0-9_]{0,62}$ ]] || die "PostgreSQL identifier is unsafe"
done
[[ $migrator != "$runtime" ]] || die "PostgreSQL roles must be distinct"

install -d -o root -g root -m 0700 "$ZECWEC_CREDENTIAL_DIR"
migrator_password_file="$ZECWEC_CREDENTIAL_DIR/.database-migrator-password"
runtime_password_file="$ZECWEC_CREDENTIAL_DIR/.database-runtime-password"
for password_file in "$migrator_password_file" "$runtime_password_file"; do
    if [[ ! -e $password_file ]]; then
        temporary="${password_file}.new.$$"
        umask 077
        openssl rand -hex 32 >"$temporary"
        install -o root -g root -m 0600 "$temporary" "$password_file"
        rm -f -- "$temporary"
    fi
    require_private_regular_file "$password_file"
done

migrator_password=$(read_one_line_credential "$migrator_password_file" 128)
runtime_password=$(read_one_line_credential "$runtime_password_file" 128)
[[ $migrator_password =~ ^[0-9a-f]{64}$ && $runtime_password =~ ^[0-9a-f]{64}$ ]] \
    || die "database passwords must retain their generated hexadecimal representation"
trap 'unset migrator_password runtime_password' EXIT

runuser -u postgres -- psql --dbname=postgres --no-psqlrc --set=ON_ERROR_STOP=1 <<SQL
SELECT format(
    'CREATE ROLE %I LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
    '$migrator'
) WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '$migrator') \gexec
SELECT format(
    'ALTER ROLE %I WITH LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L',
    '$migrator', '$migrator_password'
) \gexec

SELECT format(
    'CREATE ROLE %I LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
    '$runtime'
) WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '$runtime') \gexec
SELECT format(
    'ALTER ROLE %I WITH LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L',
    '$runtime', '$runtime_password'
) \gexec

SELECT format(
    'CREATE DATABASE %I OWNER %I TEMPLATE template0 ENCODING %L',
    '$database', '$migrator', 'UTF8'
) WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = '$database') \gexec

SELECT format('ALTER DATABASE %I OWNER TO %I', '$database', '$migrator') \gexec
SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', '$database') \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', '$database', '$runtime') \gexec
\connect $database
SELECT format('ALTER SCHEMA public OWNER TO %I', '$migrator') \gexec
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
SELECT format('GRANT USAGE ON SCHEMA public TO %I', '$runtime') \gexec
SELECT format(
    'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %I',
    '$migrator', '$runtime'
) \gexec
SELECT format(
    'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO %I',
    '$migrator', '$runtime'
) \gexec
SQL

migrator_url=$(read_setting "$settings" DATABASE_MIGRATOR_URL_CREDENTIAL)
runtime_url=$(read_setting "$settings" DATABASE_RUNTIME_URL_CREDENTIAL)
require_absolute_path "$migrator_url"
require_absolute_path "$runtime_url"
[[ $migrator_url == "$ZECWEC_CREDENTIAL_DIR/database-url-migrator" ]] \
    || die "DATABASE_MIGRATOR_URL_CREDENTIAL does not match the reviewed deployment path"
[[ $runtime_url == "$ZECWEC_CREDENTIAL_DIR/database-url-runtime" ]] \
    || die "DATABASE_RUNTIME_URL_CREDENTIAL does not match the reviewed deployment path"

python3 - "$database" "$migrator" "$runtime" "$migrator_password_file" "$runtime_password_file" "$migrator_url" "$runtime_url" <<'PY'
import pathlib
import os
import sys
import tempfile
import urllib.parse

database, migrator, runtime, migrator_password_path, runtime_password_path, migrator_path, runtime_path = sys.argv[1:]
passwords = (
    pathlib.Path(migrator_password_path).read_text(encoding="ascii").strip(),
    pathlib.Path(runtime_password_path).read_text(encoding="ascii").strip(),
)
for role, password, destination in (
    (migrator, passwords[0], migrator_path),
    (runtime, passwords[1], runtime_path),
):
    encoded_role = urllib.parse.quote(role, safe="")
    encoded_password = urllib.parse.quote(password, safe="")
    encoded_database = urllib.parse.quote(database, safe="")
    value = f"postgresql://{encoded_role}:{encoded_password}@127.0.0.1:5432/{encoded_database}?sslmode=disable\n"
    target = pathlib.Path(destination)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.new.", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as output:
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
PY
chown root:root -- "$migrator_url" "$runtime_url"
chmod 0600 -- "$migrator_url" "$runtime_url"

log "PostgreSQL roles, database, default grants, and protected URLs are reconciled"
