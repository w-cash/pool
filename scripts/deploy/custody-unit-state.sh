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
        && $(systemctl_value "$unit" SubState) == dead \
        && $(systemctl_value "$unit" MainPID) == 0 \
        && $(systemctl_value "$unit" ControlPID) == 0 ]] \
        || die "$unit is not fully inactive before sealing custody"
}

stop_custody_units_for_sealing() {
    stop_loaded_custody_unit wcash-pool.service true
    stop_loaded_custody_unit wcash-pool-wallet-init.service false
    require_inactive_custody_unit wcash-pool.service
    require_inactive_custody_unit wcash-pool-wallet-init.service
}
