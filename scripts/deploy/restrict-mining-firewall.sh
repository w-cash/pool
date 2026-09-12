#!/usr/bin/env bash

set -Eeuo pipefail
set +x
export LC_ALL=C

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1091
source "$script_dir/common.sh"

require_root
require_command ufw
require_command python3

[[ $# -eq 3 ]] || die "usage: restrict-mining-firewall.sh <apply|check> <settings> <cidr-file>"
mode=$1
settings=$2
cidr_file=$3
[[ $mode == apply || $mode == check ]] || die "mode must be apply or check"
require_private_regular_file "$settings"
require_private_regular_file "$cidr_file"

stratum=$(read_setting "$settings" STRATUM_LISTEN)
plain_port=${stratum##*:}
tls_port=$(read_setting "$settings" STRATUM_TLS_PORT)
legacy_port=$(read_setting "$settings" LEGACY_STRATUM_PORT)
for port in "$plain_port" "$tls_port" "$legacy_port"; do
    if [[ ! $port =~ ^[0-9]{1,5}$ ]] || ((port < 1 || port > 65535)); then
        die "configured firewall port is invalid"
    fi
done
[[ $plain_port == 3333 && $tls_port == 3443 && $legacy_port == 28237 ]] \
    || die "firewall ports do not match the reviewed Testnet deployment contract"

cidrs=$(python3 - "$cidr_file" <<'PY'
import ipaddress
import pathlib
import sys

values = []
for raw in pathlib.Path(sys.argv[1]).read_text(encoding="ascii").splitlines():
    value = raw.strip()
    if not value or value.startswith("#"):
        continue
    network = ipaddress.ip_network(value, strict=False)
    if network.prefixlen == 0 or network.is_unspecified:
        raise SystemExit("world-open and unspecified mining CIDRs are forbidden")
    canonical = str(network)
    if canonical not in values:
        values.append(canonical)
if not 1 <= len(values) <= 32:
    raise SystemExit("provide between one and 32 explicit miner CIDRs")
print("\n".join(values))
PY
) || die "miner CIDR policy is invalid"

status=$(ufw status verbose)
grep -Fq 'Status: active' <<<"$status" || die "UFW must already be active"
grep -Fq 'Default: deny (incoming)' <<<"$status" || die "UFW incoming policy must already be deny"

if [[ $mode == apply ]]; then
    for port in "$plain_port" "$tls_port" "$legacy_port"; do
        while IFS= read -r number; do
            [[ -n $number ]] || continue
            ufw --force delete "$number" >/dev/null
        done < <(
            ufw status numbered | awk -v target="$port/tcp" '
                match($0, /^\[[[:space:]]*[0-9]+\]/) {
                    marker = substr($0, RSTART, RLENGTH)
                    body = substr($0, RSTART + RLENGTH)
                    sub(/^[[:space:]]+/, "", body)
                    split(body, fields, /[[:space:]]+/)
                    if (fields[1] == target) {
                        gsub(/[^0-9]/, "", marker)
                        print marker
                    }
                }
            ' | sort -rn
        )
    done
    while IFS= read -r cidr; do
        ufw allow proto tcp from "$cidr" to any port "$plain_port" comment 'ZecWec Testnet plaintext'
        ufw allow proto tcp from "$cidr" to any port "$tls_port" comment 'ZecWec Testnet TLS'
    done <<<"$cidrs"
fi

rules=$(ufw status)
if awk -v one="$plain_port/tcp" -v two="$tls_port/tcp" -v old="$legacy_port/tcp" '
    $1 == one || $1 == two || $1 == old {
        allowed = 0
        anywhere = 0
        for (field = 2; field <= NF; field += 1) {
            allowed = allowed || $field == "ALLOW"
            anywhere = anywhere || $field ~ /^Anywhere/
        }
        if (allowed && anywhere) {
            found = 1
        }
    }
    END { exit found ? 0 : 1 }
' <<<"$rules"; then
    die "a world-open current or legacy mining rule remains"
fi
if awk -v old="$legacy_port/tcp" '
    $1 == old {
        for (field = 2; field <= NF; field += 1) {
            if ($field == "ALLOW") {
                found = 1
            }
        }
    }
    END { exit found ? 0 : 1 }
' <<<"$rules"; then
    die "a legacy mining allow rule remains"
fi
for port in "$plain_port" "$tls_port"; do
    grep -Eq "^${port}/tcp[[:space:]]+ALLOW" <<<"$rules" \
        || grep -Eq "^${port}/tcp[[:space:]]+\(v6\)[[:space:]]+ALLOW" <<<"$rules" \
        || die "no source-restricted allow rule exists for port $port"
    while IFS= read -r cidr; do
        awk -v target="$port/tcp" -v source="$cidr" '
            $1 == target {
                allowed = 0
                matched = 0
                for (field = 2; field <= NF; field += 1) {
                    allowed = allowed || $field == "ALLOW"
                    matched = matched || $field == source
                }
                if (allowed && matched) {
                    found = 1
                }
            }
            END { exit found ? 0 : 1 }
        ' <<<"$rules" || die "configured source $cidr is not allowed on port $port"
    done <<<"$cidrs"
done

log "mining firewall is active, default-deny, source-restricted, and legacy-port closed"
