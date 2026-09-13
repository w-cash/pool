#!/usr/bin/env bash

# This file is sourced by the custody ceremony after common.sh.

systemctl_value() {
    local unit=$1
    local property=$2
    local value

    value=$(systemctl show --property="$property" --value "$unit") \
        || die "could not inspect $property for $unit"
    [[ -n $value ]] || die "systemd returned an empty $property for $unit"
    printf '%s\n' "$value"
}

stop_loaded_custody_unit() {
    local unit=$1
    local allow_not_found=$2
    local load_state

    load_state=$(systemctl_value "$unit" LoadState)
    case $load_state in
        loaded)
            systemctl stop "$unit" || die "could not stop $unit before sealing custody"
            ;;
        not-found)
            [[ $allow_not_found == true ]] \
                || die "$unit must be installed before sealing custody"
            ;;
        *)
            die "$unit has unexpected systemd load state: $load_state"
            ;;
    esac
}

require_inactive_custody_unit() {
    local unit=$1

    [[ $(systemctl_value "$unit" ActiveState) == inactive \
        && $(systemctl_value "$unit" SubState) == dead ]] \
        || die "$unit is not fully inactive before sealing custody"

    require_inactive_unit_process_state "$unit"
}

stop_custody_units_for_sealing() {
    # Stop every asynchronous supervisor before changing custody ownership.
    # Otherwise a queued cookie refresh or boot/start oneshot can revive the
    # payout identities after the ceremony has proved them inactive.
    stop_loaded_custody_unit zecwec-testnet-pool-start.service true
    stop_loaded_custody_unit wcash-pool-health.timer true
    stop_loaded_custody_unit zecwec-cookie-refresh.path true
    stop_loaded_custody_unit zecwec-cookie-refresh.service true
    stop_loaded_custody_unit zecwec-testnet-pool.target true
    stop_loaded_custody_unit wcash-pool.service true
    stop_loaded_custody_unit wcash-pool-projector.service true
    stop_loaded_custody_unit wcash-payout-worker.service true
    stop_loaded_custody_unit wcash-pool-wallet-init.service false
    for supervisor in zecwec-testnet-pool-start.service wcash-pool-health.timer \
        zecwec-cookie-refresh.path zecwec-cookie-refresh.service; do
        load_state=$(systemctl_value "$supervisor" LoadState)
        [[ $load_state == not-found ]] || require_inactive_custody_unit "$supervisor"
    done
    require_inactive_custody_unit zecwec-testnet-pool.target
    require_inactive_custody_unit wcash-pool.service
    require_inactive_custody_unit wcash-pool-projector.service
    require_inactive_custody_unit wcash-payout-worker.service
    require_inactive_custody_unit wcash-pool-wallet-init.service
}
