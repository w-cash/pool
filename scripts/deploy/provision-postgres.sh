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
projector=$(read_setting "$settings" POSTGRES_PROJECTOR_ROLE)
payout=$(read_setting "$settings" POSTGRES_PAYOUT_ROLE)
for item in "$database" "$migrator" "$runtime" "$projector" "$payout"; do
    [[ $item =~ ^[a-z_][a-z0-9_]{0,62}$ ]] || die "PostgreSQL identifier is unsafe"
done
[[ $migrator != "$runtime" && $migrator != "$projector" && $migrator != "$payout" \
    && $runtime != "$projector" && $runtime != "$payout" && $projector != "$payout" ]] \
    || die "PostgreSQL roles must be distinct"
require_supported_postgres_server

install -d -o root -g root -m 0700 "$ZECWEC_CREDENTIAL_DIR"
migrator_password_file="$ZECWEC_CREDENTIAL_DIR/.database-migrator-password"
runtime_password_file="$ZECWEC_CREDENTIAL_DIR/.database-runtime-password"
projector_password_file="$ZECWEC_CREDENTIAL_DIR/.database-projector-password"
payout_password_file="$ZECWEC_CREDENTIAL_DIR/.database-payout-password"
for password_file in "$migrator_password_file" "$runtime_password_file" \
    "$projector_password_file" "$payout_password_file"; do
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
projector_password=$(read_one_line_credential "$projector_password_file" 128)
payout_password=$(read_one_line_credential "$payout_password_file" 128)
[[ $migrator_password =~ ^[0-9a-f]{64}$ && $runtime_password =~ ^[0-9a-f]{64}$ \
    && $projector_password =~ ^[0-9a-f]{64}$ \
    && $payout_password =~ ^[0-9a-f]{64}$ ]] \
    || die "database passwords must retain their generated hexadecimal representation"
trap 'unset migrator_password runtime_password projector_password payout_password' EXIT

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
    '$projector'
) WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '$projector') \gexec
SELECT format(
    'ALTER ROLE %I WITH LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L',
    '$projector', '$projector_password'
) \gexec

SELECT format(
    'CREATE ROLE %I LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
    '$payout'
) WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '$payout') \gexec
SELECT format(
    'ALTER ROLE %I WITH LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L',
    '$payout', '$payout_password'
) \gexec

SELECT format(
    'CREATE ROLE %I LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
    '$runtime'
) WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '$runtime') \gexec
SELECT format(
    'ALTER ROLE %I WITH LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L',
    '$runtime', '$runtime_password'
) \gexec

-- NOINHERIT does not prevent an explicit SET ROLE. Reconcile reused roles by
-- removing every prior membership before any service credential is accepted.
SELECT format('REVOKE %I FROM %I', granted_role.rolname, member_role.rolname)
  FROM pg_auth_members membership
  JOIN pg_roles granted_role ON granted_role.oid = membership.roleid
  JOIN pg_roles member_role ON member_role.oid = membership.member
 WHERE member_role.rolname IN ('$migrator', '$runtime', '$projector', '$payout')
\gexec

SELECT format(
    'CREATE DATABASE %I OWNER %I TEMPLATE template0 ENCODING %L',
    '$database', '$migrator', 'UTF8'
) WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = '$database') \gexec

SELECT format('ALTER DATABASE %I OWNER TO %I', '$database', '$migrator') \gexec
SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', '$database') \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', '$database', '$runtime') \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', '$database', '$projector') \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', '$database', '$payout') \gexec
\connect $database
SELECT format('ALTER SCHEMA public OWNER TO %I', '$migrator') \gexec
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
-- Upgrade safety: older packages persisted broad migrator default ACLs for
-- the Internet-facing role. Clear them before any later migration can create
-- another implicitly writable table or sequence.
SELECT format(
    'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE ALL PRIVILEGES ON TABLES FROM %I',
    '$migrator', role_name
) FROM (VALUES ('$runtime'), ('$projector'), ('$payout')) AS roles(role_name) \gexec
SELECT format(
    'ALTER DEFAULT PRIVILEGES FOR ROLE %I REVOKE ALL PRIVILEGES ON TABLES FROM %I',
    '$migrator', role_name
) FROM (VALUES ('$runtime'), ('$projector'), ('$payout')) AS roles(role_name) \gexec
SELECT format(
    'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE ALL PRIVILEGES ON SEQUENCES FROM %I',
    '$migrator', role_name
) FROM (VALUES ('$runtime'), ('$projector'), ('$payout')) AS roles(role_name) \gexec
SELECT format(
    'ALTER DEFAULT PRIVILEGES FOR ROLE %I REVOKE ALL PRIVILEGES ON SEQUENCES FROM %I',
    '$migrator', role_name
) FROM (VALUES ('$runtime'), ('$projector'), ('$payout')) AS roles(role_name) \gexec
SELECT format(
    'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC',
    '$migrator'
) \gexec
SELECT format(
    'ALTER DEFAULT PRIVILEGES FOR ROLE %I REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC',
    '$migrator'
) \gexec
SELECT format('GRANT USAGE ON SCHEMA public TO %I', '$runtime') \gexec
SELECT format('GRANT USAGE ON SCHEMA public TO %I', '$projector') \gexec
SELECT format('GRANT USAGE ON SCHEMA public TO %I', '$payout') \gexec
SQL

migrator_url=$(read_setting "$settings" DATABASE_MIGRATOR_URL_CREDENTIAL)
runtime_url=$(read_setting "$settings" DATABASE_RUNTIME_URL_CREDENTIAL)
projector_url=$(read_setting "$settings" DATABASE_PROJECTOR_URL_CREDENTIAL)
payout_url=$(read_setting "$settings" DATABASE_PAYOUT_URL_CREDENTIAL)
require_absolute_path "$migrator_url"
require_absolute_path "$runtime_url"
require_absolute_path "$projector_url"
require_absolute_path "$payout_url"
[[ $migrator_url == "$ZECWEC_CREDENTIAL_DIR/database-url-migrator" ]] \
    || die "DATABASE_MIGRATOR_URL_CREDENTIAL does not match the reviewed deployment path"
[[ $runtime_url == "$ZECWEC_CREDENTIAL_DIR/database-url-runtime" ]] \
    || die "DATABASE_RUNTIME_URL_CREDENTIAL does not match the reviewed deployment path"
[[ $projector_url == "$ZECWEC_CREDENTIAL_DIR/database-url-projector" ]] \
    || die "DATABASE_PROJECTOR_URL_CREDENTIAL does not match the reviewed deployment path"
[[ $payout_url == "$ZECWEC_CREDENTIAL_DIR/database-url-payout" ]] \
    || die "DATABASE_PAYOUT_URL_CREDENTIAL does not match the reviewed deployment path"

python3 - "$database" "$migrator" "$runtime" "$projector" "$payout" \
    "$migrator_password_file" "$runtime_password_file" "$projector_password_file" \
    "$payout_password_file" "$migrator_url" "$runtime_url" "$projector_url" \
    "$payout_url" <<'PY'
import pathlib
import os
import sys
import tempfile
import urllib.parse

(
    database,
    migrator,
    runtime,
    projector,
    payout,
    migrator_password_path,
    runtime_password_path,
    projector_password_path,
    payout_password_path,
    migrator_path,
    runtime_path,
    projector_path,
    payout_path,
) = sys.argv[1:]
passwords = (
    pathlib.Path(migrator_password_path).read_text(encoding="ascii").strip(),
    pathlib.Path(runtime_password_path).read_text(encoding="ascii").strip(),
    pathlib.Path(projector_password_path).read_text(encoding="ascii").strip(),
    pathlib.Path(payout_password_path).read_text(encoding="ascii").strip(),
)
for role, password, destination in (
    (migrator, passwords[0], migrator_path),
    (runtime, passwords[1], runtime_path),
    (projector, passwords[2], projector_path),
    (payout, passwords[3], payout_path),
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
chown root:root -- "$migrator_url" "$runtime_url" "$projector_url" "$payout_url"
chmod 0600 -- "$migrator_url" "$runtime_url" "$projector_url" "$payout_url"

log "PostgreSQL migration, public, projector, and isolated payout roles and protected URLs are reconciled"
