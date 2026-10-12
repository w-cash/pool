# GPU/CPU Mainnet listener

`mainnet.zecwec.com:3338` is the low-difficulty entry point for Equihash
GPU and CPU miners. It uses the same accounts, workers, PPLNS accounting,
merged-mining jobs, and payout ledger as the ASIC listener on port 3336.

The public adapter maps bounded short job IDs to the firewall-isolated pool on
port 3339. The internal listener starts at the backend-enforced `0007…` ceiling
(about one share per 8,192 Equihash solutions, or roughly 55 seconds at
150 Sol/s). Share credit is calculated from the exact target stored with each
accepted share, so lower-difficulty shares do not receive ASIC share weight.

The listener has its own pool instance and nonce namespace (`4`). This prevents
nonce-prefix overlap with the base listener (`2`) and ASIC listener (`3`).

## Install

Before release, verify that the selected node binary's `getblockhash 0` equals
the expected public genesis for each chain. Preserve the exact source revisions,
build inputs, and binary digests; a copied source tree alone does not establish
the running binary's provenance.

For an existing installation, upgrade the shared adapter script and its service
units first. Run `systemctl daemon-reload`, then restart every installed public
adapter (`zecwec-gpu-proxy.service` and, if installed,
`zecwec-godminer-proxy.service`). Confirm that each running adapter enforces 64
total connections and 8 per peer before installing the new internal pool TOML
or restarting the internal pool services with `maximum_miners_per_ip = 64`.
Raising that internal limit while an old adapter is running removes the previous
eight-session protection. Verify that the firewall and NAT rules isolate
internal ports 3337 and 3339 before raising the limit. `systemctl enable --now`
below does not restart an already running service.

```sh
install -o root -g root -m 0755 \
  deploy/godminer_zip301_proxy.py \
  /opt/zecwec-pool-staging/bin/godminer_zip301_proxy.py
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

The public adapter admits at most 64 connections, with at most 8 from each
TCP peer IP. Excess connections close immediately without opening an upstream
connection. Miner messages cannot change the source quota. The internal pool
allows all 64 adapter connections from loopback; it has no knowledge of the
external peer IP. Keep port 3339 inaccessible to external clients, including
through NAT forwarding, so clients cannot bypass the public adapter's limits.
Miners behind the same NAT share the eight-connection peer limit. A forwarding
proxy that replaces their TCP source address also combines them into one bucket.

## Verify

```sh
python3 -B scripts/test-godminer-zip301-proxy.py
systemctl is-active zecwec-pool-gpu.service zecwec-gpu-proxy.service
ss -ltn '( sport = :3338 or sport = :3339 or sport = :18082 )'
journalctl -u zecwec-pool-gpu.service -u zecwec-gpu-proxy.service --since '10 minutes ago'
```
