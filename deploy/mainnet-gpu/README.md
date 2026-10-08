# GPU/CPU Mainnet listener

`mainnet.zecwec.com:3338` is the low-difficulty entry point for Equihash
GPU and CPU miners. It uses the same accounts, workers, PPLNS accounting,
merged-mining jobs, and payout ledger as the ASIC listener on port 3336.

The public adapter maps bounded short job IDs to the firewall-isolated pool on
port 3339. The internal listener starts at target `000f…` (about one share per
4,096 Equihash solutions) and permits Vardiff to ease as far as `003f…`. Share
credit is calculated from the exact target stored with each accepted share, so
lower-difficulty shares do not receive the same weight as ASIC shares.

The listener has its own pool instance and nonce namespace (`4`). This prevents
nonce-prefix overlap with the base listener (`2`) and ASIC listener (`3`).

## Install

```sh
install -o root -g zecwec-pool -m 0640 \
  deploy/mainnet-gpu/pool-gpu.toml \
  /etc/zecwec-pool-staging/pool-gpu.toml
install -o root -g root -m 0644 \
  deploy/mainnet-gpu/zecwec-pool-gpu.service \
  deploy/mainnet-gpu/zecwec-gpu-proxy.service \
  /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now zecwec-pool-gpu.service zecwec-gpu-proxy.service
```

Expose TCP 3338 to miners. The runtime binds internal port 3339 as required by
Mainnet policy; keep it and portal port 18082 blocked from the public Internet.

## Verify

```sh
systemctl is-active zecwec-pool-gpu.service zecwec-gpu-proxy.service
ss -ltn '( sport = :3338 or sport = :3339 or sport = :18082 )'
journalctl -u zecwec-pool-gpu.service -u zecwec-gpu-proxy.service --since '10 minutes ago'
```
