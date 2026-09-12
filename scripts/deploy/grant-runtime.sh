#!/usr/bin/env bash

set -Eeuo pipefail
set +x

die() {
    printf 'grant-runtime: %s\n' "$*" >&2
    exit 1
}

[[ $# -eq 2 ]] || die "usage: grant-runtime.sh <migrator-url-file> <runtime-role>"
url_file=$1
runtime_role=$2
[[ $url_file == /* && -f $url_file && ! -L $url_file ]] || die "migrator URL is unavailable"
[[ $runtime_role =~ ^[a-z_][a-z0-9_]{0,62}$ ]] || die "runtime role is unsafe"

IFS= read -r PGDATABASE <"$url_file" || [[ -n ${PGDATABASE:-} ]] || die "migrator URL is empty"
[[ -n $PGDATABASE && $PGDATABASE != *[$'\r\n\t']* ]] || die "migrator URL is invalid"
export PGDATABASE
trap 'unset PGDATABASE' EXIT

psql --no-psqlrc --set=ON_ERROR_STOP=1 --set="runtime=$runtime_role" <<'SQL'
GRANT USAGE ON SCHEMA public TO :"runtime";
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO :"runtime";
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO :"runtime";
SQL
