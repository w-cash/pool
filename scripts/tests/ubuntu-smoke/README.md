# Ubuntu deployment smoke tests

Run `bash scripts/tests/ubuntu-smoke/run.sh` from the repository with a working
Docker engine. It creates and removes one disposable privileged Ubuntu 22.04
container. The repository is mounted read-only. It does not modify the host's
services, wallet material, existing containers or databases.

The checks use real systemd 249 and nginx. A non-root binary fixture verifies
that the packaged startup entrypoint retains read-only systemd credentials
through config-check, preflight and serve, as well as payout-config-check and
payout-worker, and stops on earlier failures. nginx
tests exercise the rendered portal config with temporary mutual-TLS certificates,
the exact UI asset allowlist, method restrictions and unknown-path rejection.
They also prove that HTTP serves only GET requests for an exact ACME token file:
existing files return 200, missing files return 404, and other methods, paths
and API requests close without a response. HTTPS APIs still require origin mTLS.

Docker's private `/run` mount must be shared inside this disposable container
for systemd 249's credential helper to propagate its mount. The checker applies
that setting only after checking the disposable-image marker.

These fixtures verify deployment boundaries. They do not replace the complete
regtest pool, real wallet transactions or external production acceptance.
