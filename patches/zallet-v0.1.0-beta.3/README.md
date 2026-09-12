# Zallet beta.3 testnet patch set

The ZecWec Testnet collector uses the Zaino backend from upstream Zallet
`v0.1.0-beta.3`, commit
`987382f67e622915228686e9f956c6a9c9a7514c`. The published binary cannot be
used on small hosts: four long-lived sync tasks retain four database handles,
while Deadpool's default capacity is `2 * available_parallelism`. On a two-vCPU
host that leaves no handle for any RPC.

The ordered patch set is deliberately small:

1. Reserve eight database handles at minimum and bound pool checkout to 30
   seconds. Four handles remain available beyond the four sync owners. The
   timeout converts any future saturation or nested-acquisition defect into a
   visible RPC failure instead of an infinite wait.
2. Backport upstream commit
   `1d5a012931675caeed01c29aef30dcea829788ae`, which signals the data-request
   worker only after chain writes are stored. This closes upstream issue #817
   without taking unrelated unreleased changes.

The capacity patch is not a substitute for upstream's broader RPC
resource-ordering work in pull request #716. ZecWec serializes collector
mutations through one process-wide signer mutex and an exclusive journal lock,
retains bounded RPC deadlines, and keeps the pool private while that work
remains unreleased. The deployment must not add another independent Zallet
mutation client. A future Zallet upgrade must re-audit and either drop or rebase
both patches.

Build the pinned backend with `scripts/build-zallet-testnet.sh`. The script
fetches only the exact base commit, checks both patches before applying them,
runs the low-core capacity regressions and sync tests, builds with both
`rpc-cli` and `zcashd-import`, and writes a non-secret provenance record beside
the output binary. One successful build is a private Testnet candidate only.
Public deployment remains blocked until two clean builds from distinct roots
produce the same binary digest under the pinned, remapped build environment.
