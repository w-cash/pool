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
require_command iptables
require_command ip6tables
require_command iptables-save
require_command ip6tables-save

[[ $# -eq 3 ]] \
    || die "usage: restrict-mining-firewall.sh <apply|close|check> <settings> <cidr-file>"
mode=$1
settings=$2
cidr_file=$3
[[ $mode == apply || $mode == close || $mode == check ]] \
    || die "mode must be apply, close, or check"
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

policy_output=$(
    python3 "$script_dir/parse-mining-firewall-policy.py" "$cidr_file"
) || die "mining ingress policy is invalid"
readarray -t policy_lines <<<"$policy_output"
firewall_policy=${policy_lines[0]}
cidrs=("${policy_lines[@]:1}")
[[ $firewall_policy == open || $firewall_policy == public ]] \
    || die "mining ingress policy mode is invalid"

readonly guard_chain=ZECWEC-MINING-GUARD

chain_has_unsupported_references() {
    local snapshot=${1:?ruleset snapshot is required}
    local chain=${2:?chain name is required}
    awk -v target="$chain" '
        $1 == "-A" {
            references = 0
            for (field = 3; field < NF; field += 1) {
                if (($field == "-j" || $field == "-g") && $(field + 1) == target) {
                    references = 1
                }
            }
            if (references && !(NF == 4 && $2 == "INPUT" && $3 == "-j" && $4 == target)) {
                unsafe = 1
            }
        }
        END { exit unsafe ? 0 : 1 }
    ' <<<"$snapshot"
}

remove_owned_guard_chain() {
    local firewall=${1:?firewall command is required}
    local save=${2:?save command is required}
    local chain=${3:?chain name is required}
    local snapshot

    snapshot=$($save -t filter) || die "$save could not inspect the filter ruleset"
    if chain_has_unsupported_references "$snapshot" "$chain"; then
        die "$chain has a reference outside its exact INPUT hook"
    fi
    while "$firewall" --wait 5 -t filter -C INPUT -j "$chain" >/dev/null 2>&1; do
        "$firewall" --wait 5 -t filter -D INPUT -j "$chain"
    done
    if "$firewall" --wait 5 -t filter -S "$chain" >/dev/null 2>&1; then
        "$firewall" --wait 5 -t filter -F "$chain"
        "$firewall" --wait 5 -t filter -X "$chain"
    fi
}

install_mining_guard() {
    local family=${1:?address family is required}
    local guard_mode=${2:?guard mode is required}
    local firewall save staging source port snapshot stale
    local -a stale_chains=()

    [[ $guard_mode == open || $guard_mode == public || $guard_mode == closed ]] \
        || die "invalid mining guard mode"
    case $family in
        4) firewall=iptables; save=iptables-save ;;
        6) firewall=ip6tables; save=ip6tables-save ;;
        *) die "invalid mining guard address family" ;;
    esac
    staging="ZECWEC-MG${family}-${BASHPID}"
    if "$firewall" --wait 5 -t filter -S "$staging" >/dev/null 2>&1; then
        die "temporary mining guard chain already exists"
    fi

    # Build the replacement without a hook. Inserting its hook at rule one is
    # the single activation step; the previous guard remains effective until
    # that point, and the new guard protects the managed ports during cleanup.
    "$firewall" --wait 5 -t filter -N "$staging"
    if [[ $guard_mode == open ]]; then
        if [[ $family == 4 ]]; then
            "$firewall" --wait 5 -t filter -A "$staging" \
                -i lo -s 127.0.0.1/32 -p tcp --dport "$plain_port" -j RETURN
        else
            "$firewall" --wait 5 -t filter -A "$staging" \
                -i lo -s ::1/128 -p tcp --dport "$plain_port" -j RETURN
        fi
        for source in "${cidrs[@]}"; do
            if [[ $family == 4 && $source == *:* ]] \
                || [[ $family == 6 && $source != *:* ]]; then
                continue
            fi
            for port in "$plain_port" "$tls_port"; do
                "$firewall" --wait 5 -t filter -A "$staging" \
                    -s "$source" -p tcp --dport "$port" -j RETURN
            done
        done
    elif [[ $guard_mode == public ]]; then
        for port in "$plain_port" "$tls_port"; do
            "$firewall" --wait 5 -t filter -A "$staging" \
                -p tcp --dport "$port" -j RETURN
        done
    fi
    for port in "$plain_port" "$tls_port" "$legacy_port"; do
        "$firewall" --wait 5 -t filter -A "$staging" \
            -p tcp --dport "$port" -j DROP
    done
    "$firewall" --wait 5 -t filter -A "$staging" -j RETURN
    "$firewall" --wait 5 -t filter -I INPUT 1 -j "$staging"

    remove_owned_guard_chain "$firewall" "$save" "$guard_chain"
    "$firewall" --wait 5 -t filter -E "$staging" "$guard_chain"

    # An interrupted earlier invocation can leave one of our uniquely named
    # staging chains behind. The stable guard is now rule one, so these owned
    # remnants can be removed without opening a managed port.
    snapshot=$($save -t filter) || die "$save could not inspect the filter ruleset"
    readarray -t stale_chains < <(
        awk -v prefix=":ZECWEC-MG${family}-" \
            '$1 ~ ("^" prefix) { print substr($1, 2) }' <<<"$snapshot"
    )
    for stale in "${stale_chains[@]}"; do
        [[ -n $stale ]] || continue
        remove_owned_guard_chain "$firewall" "$save" "$stale"
    done
}

# Mutating modes first put a closed guard at the first INPUT position in both
# address families. UFW reconciliation therefore cannot expose a managed port,
# and any later error leaves a closed guard in place.
if [[ $mode == apply || $mode == close ]]; then
    install_mining_guard 4 closed
    install_mining_guard 6 closed
fi

status=$(ufw status verbose)
grep -Fq 'Status: active' <<<"$status" || die "UFW must already be active"
grep -Fq 'Default: deny (incoming)' <<<"$status" || die "UFW incoming policy must already be deny"

if [[ $mode == apply || $mode == close ]]; then
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
    # UFW is permitted to reload its owned chains while deleting persisted
    # rules. Reassert the closed rule-one guard before either returning closed
    # or installing the reviewed restricted/public policy.
    install_mining_guard 4 closed
    install_mining_guard 6 closed
    if [[ $mode == apply ]]; then
        if [[ $firewall_policy == public ]]; then
            ufw allow proto tcp to any port "$plain_port" comment 'ZecWec public Testnet plaintext'
            ufw allow proto tcp to any port "$tls_port" comment 'ZecWec public Testnet TLS'
        else
            for cidr in "${cidrs[@]}"; do
                ufw allow proto tcp from "$cidr" to any port "$plain_port" comment 'ZecWec Testnet plaintext'
                ufw allow proto tcp from "$cidr" to any port "$tls_port" comment 'ZecWec Testnet TLS'
            done
        fi
        install_mining_guard 4 "$firewall_policy"
        install_mining_guard 6 "$firewall_policy"
    fi
fi

rules=$(ufw status)
if [[ $firewall_policy != public ]] && awk -v one="$plain_port/tcp" -v two="$tls_port/tcp" '
    $1 == one || $1 == two {
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
    die "a world-open current mining rule remains outside public policy"
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
if [[ $mode == close ]]; then
    for port in "$plain_port" "$tls_port"; do
        if awk -v target="$port/tcp" '
            $1 == target {
                for (field = 2; field <= NF; field += 1) {
                    if ($field == "ALLOW") {
                        found = 1
                    }
                }
            }
            END { exit found ? 0 : 1 }
        ' <<<"$rules"; then
            die "a mining allow rule remains after closing port $port"
        fi
    done
    raw_mode=closed
else
    raw_mode=$firewall_policy
fi
iptables-save -t filter \
    | python3 "$script_dir/verify-mining-firewall.py" \
        ipv4 "$raw_mode" "$plain_port" "$tls_port" "$legacy_port" \
        "${cidrs[@]}"
ip6tables-save -t filter \
    | python3 "$script_dir/verify-mining-firewall.py" \
        ipv6 "$raw_mode" "$plain_port" "$tls_port" "$legacy_port" \
        "${cidrs[@]}"
if [[ $mode == close ]]; then
    log "mining firewall is closed for every current and legacy Stratum port"
    exit 0
fi
for port in "$plain_port" "$tls_port"; do
    grep -Eq "^${port}/tcp[[:space:]]+ALLOW" <<<"$rules" \
        || grep -Eq "^${port}/tcp[[:space:]]+\(v6\)[[:space:]]+ALLOW" <<<"$rules" \
        || die "no mining allow rule exists for port $port"
    if [[ $firewall_policy == public ]]; then
        awk -v target="$port/tcp" '
            $1 == target {
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
        ' <<<"$rules" || die "public Testnet access is not allowed on port $port"
    else
        for cidr in "${cidrs[@]}"; do
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
        done
    fi
done

if [[ $firewall_policy == public ]]; then
    log "mining firewall is active, default-deny, public on current Testnet ports, and legacy-port closed"
else
    log "mining firewall is active, default-deny, source-restricted, and legacy-port closed"
fi
