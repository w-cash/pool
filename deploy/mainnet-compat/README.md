# GodMiner Mainnet compatibility listener

This directory records the non-secret runtime configuration used for the
GodMiner/Z15 Pro compatibility path on `mainnet.zecwec.com:3336`.

The public adapter shortens the pool's 64-character ZIP-301 job identifiers
for miners that store shorter identifiers. It expands those identifiers again
before forwarding `mining.submit` to the normal `wcash-poold` listener on
loopback port 3337. Accounting, worker identities, share validation, merged
mining, and payouts remain in the shared Mainnet backend.

This remains the ASIC endpoint. GPU and CPU miners use the separate
low-difficulty listener on public port 3338 documented in `../mainnet-gpu/`.

## Files

- `pool-z15pro-compat.toml` is the deployed non-secret pool configuration.
- `zecwec-pool-z15pro-compat.service` runs the internal pool listener.
- `zecwec-godminer-proxy.service` exposes the public compatibility listener.
- `../godminer_zip301_proxy.py` implements the bounded job-ID translation.

The referenced database URL, RPC cookies, portal pepper, and TOTP key are
runtime credential files from the base Mainnet deployment. Their contents are
not stored in this repository.

## Install or recover

Before release, verify that the selected node binary's `getblockhash 0` equals
the expected public genesis for each chain. Preserve the exact source revisions,
build inputs, and binary digests; a copied source tree alone does not establish
the running binary's provenance.

For an existing installation, upgrade the adapter script and its service units
first. Run `systemctl daemon-reload`, then restart every installed public adapter
(`zecwec-godminer-proxy.service` and, if installed, `zecwec-gpu-proxy.service`).
Confirm that each running adapter enforces 64 total connections and 8 per peer
before installing the new internal pool TOML or restarting the internal pool
services with `maximum_miners_per_ip = 64`. Raising that internal limit while an
old adapter is running removes the previous eight-session protection. Verify
that the firewall and NAT rules isolate internal ports 3337 and 3339 before
raising the limit. `systemctl enable --now` below does not restart an already
running service.

Install the adapter and configuration using the paths embedded in the units:

```sh
install -o root -g root -m 0755 \
  deploy/godminer_zip301_proxy.py \
  /opt/zecwec-pool-staging/bin/godminer_zip301_proxy.py
install -o root -g zecwec-pool -m 0640 \
  deploy/mainnet-compat/pool-z15pro-compat.toml \
  /etc/zecwec-pool-staging/pool-z15pro-compat.toml
install -o root -g root -m 0644 \
  deploy/mainnet-compat/zecwec-pool-z15pro-compat.service \
  deploy/mainnet-compat/zecwec-godminer-proxy.service \
  /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now zecwec-pool-z15pro-compat.service
systemctl enable --now zecwec-godminer-proxy.service
```

Expose TCP 3336 to miners. Port 3337 is an upstream implementation detail and
must remain blocked by the host firewall. The base Mainnet listener on 3334
continues independently.

The public adapter admits at most 64 connections, with at most 8 from each
TCP peer IP. Excess connections close immediately without opening an upstream
connection. Miner messages cannot change the source quota. The internal pool
allows all 64 adapter connections from loopback; it has no knowledge of the
external peer IP. Keep port 3337 inaccessible to external clients, including
through NAT forwarding, so clients cannot bypass the public adapter's limits.
Miners behind the same NAT share the eight-connection peer limit. A forwarding
proxy that replaces their TCP source address also combines them into one bucket.

## Verify

```sh
python3 deploy/godminer_zip301_proxy.py \
  --listen 127.0.0.1:3336 --upstream 127.0.0.1:3337 --self-test
python3 -B scripts/test-godminer-zip301-proxy.py
systemctl is-active \
  zecwec-pool-z15pro-compat.service \
  zecwec-godminer-proxy.service
ss -ltn '( sport = :3336 or sport = :3337 )'
journalctl -u zecwec-godminer-proxy.service --since '10 minutes ago'
```

On the wire, `mining.notify` must expose an eight-character alias such as
`00000001`. Accepted shares must appear under the miner's existing canonical
worker login in the shared accounting database.
