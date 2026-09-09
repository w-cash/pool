# Wcash Pool

The Wcash pool is the miner-facing service for Equihash merged mining across
Wcash and Zcash. It is designed to keep public ZIP-301 sessions, worker
authentication, variable difficulty, and accounting outside the consensus
node.

The repository is under active testnet development. It is not ready for public
mining or funds of value.

## Design boundary

The pool does not implement Equihash, AuxPoW, block-template construction, or
network-target validation. Those consensus-sensitive operations remain in the
Wcash node's `wcash-merge-miner` backend. The pool accepts a share only after
that backend has validated it and durably recorded its attribution.

See [SECURITY.md](SECURITY.md) before deploying or reporting a vulnerability.

## License

Licensed under either the Apache License, Version 2.0 or the MIT License, at
your option.
