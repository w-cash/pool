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
3. Remove two build-host path leaks. Exclude `shadow-rs`'s unused
   `CARGO_MANIFEST_DIR` and `CARGO_TREE` constants, and patch the exact
   `zewif-zcashd` 0.1.0-rc.5 crate so its vendored `db_dump` location is stored
   relative to the release executable rather than as Cargo's absolute
   `OUT_DIR`. Installed releases retain the existing system-`PATH` fallback
   when the build-tree helper is not shipped.
4. Replace the flaky request-based shutdown assertion tracked by upstream issue
   #766 with a narrow test observer. The observer captures the spawned batch
   task's `AbortHandle` only after the abort-on-drop guard owns it, then checks
   bounded eventual task completion directly. It never injects reload requests
   that can keep the engine queue ready and mask Tokio cancellation. The normal
   production entry point uses a no-op observer and retains the same task
   ownership and return contract. This is the local deterministic signal/barrier
   resolution described as option 1 in issue #766; it is not the reload-polling
   workaround proposed by the still-open pull request #768.

The capacity patch is not a substitute for upstream's broader RPC
resource-ordering work in pull request #716. ZecWec serializes collector
mutations through one process-wide signer mutex and an exclusive journal lock,
retains bounded RPC deadlines, and keeps the pool private while that work
remains unreleased. The deployment must not add another independent Zallet
mutation client. A future Zallet upgrade must re-audit and either drop or rebase
all patches.

Build the pinned backend with `scripts/build-zallet-testnet.sh`. The script
fetches only the exact base commit, checks all patches before applying them,
runs the low-core capacity regressions and sync tests, builds with both
`rpc-cli` and `zcashd-import`, and writes a non-secret provenance record beside
the output binary. One successful build is a private Testnet candidate only.
Public deployment remains blocked until two clean builds on independent
reviewed hosts produce the same binary digest under the pinned, remapped build
environment. Required CI also performs two sequential clean builds and compares
their exact checksum records.
The build downloads `zewif-zcashd` from its pinned crates.io archive, verifies
the archive digest before safe extraction, resolves the unchanged Cargo lock,
and byte-compares Cargo's private registry source with that archive. It applies
the recorded dependency patch only inside the build-private registry, while
retaining the crate's locked registry identity. Because Cargo hashes canonical
workspace paths before rustc remapping, compilation is serialized in one fixed,
ownership-checked build root on every host. The final gate rejects a binary that
still embeds that build root.
