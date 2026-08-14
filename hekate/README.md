# Hekate: Keccak (inline chiplet)

Benchmarks [Hekate](https://github.com/oumuamua-labs/hekate) (Oumuamua Labs) with the
csp-benchmarks harness, input sizes, and metric schema. This integration lives on a fork and its
numbers are published independently by Oumuamua Labs. They are **not official csp-benchmarks
results**. Upstream accepts only fully open-source systems, and Hekate's prover is a closed-source
signed cdylib, which disqualifies it from the official suite.

## System

GF(2^128) binary tower field, hand-written AIR tables with a chiplet architecture, ZeroCheck
sumcheck + LogUp buses, Brakedown-style PCS (MDS Reed–Solomon row code over the additive
binary-field FFT subspace chain), blake3 Merkle commitments. Published crates pinned exactly at
0.33.0 (`hekate-keccak` 0.6.0, `hekate-math` 0.10.0), prover cdylib 0.11.0.

## Benchmarked construction

The `keccak_inline` construction: the Keccak-f[1600] chiplet AIR is injected into the main trace
(27 CPU link columns + 30 physical Keccak columns, virtually expanded to 1688 = 27 + 1661), giving
one commitment and one merged ZeroCheck instead of a separate chiplet trace.

Terminology note: Hekate's own "inline" means this single-trace packing. Under the csp-benchmarks
taxonomy the benchmark is labeled `acceleration: "precompile"`, because the operation is proved by
a vendor-shipped dedicated chiplet implementation with a registered prover kernel, not by
VM-instruction inlining (Hekate is not a VM).

The statement proven is `keccak256(msg) == digest`: the four digest lanes are public inputs pinned
by boundary constraints on the last output row of the sponge chain. Witness generation (sponge
execution and trace construction) runs inside the timed proving closure, and the RAM binary
measures preprocessing + proving including witness generation.

## Trace-size floor

`Config::prod()` demands ≥128-bit soundness with `support >= num_queries` (176), which requires a
committed grid of at least 256 columns. The prover enforces this at runtime, and every proof
therefore runs on at least 2^8 trace rows: inputs of 128–1024 bytes all prove at 256 rows, 2048
bytes at 512. Proving cost is near-flat across the smaller input sizes. That is the real floor
cost of Hekate's production security gate, not a measurement artifact.

## Closed-source prover

The verifier, SDK, and all chiplet AIRs are open source (Apache-2.0). The prover ships as a
prebuilt cdylib fetched at build time from `releases.oumuamua.dev` and verified against a pinned
manifest (SHA-256 + Ed25519 + ML-DSA-65). Supported targets are aarch64 only (macOS, Linux glibc,
Android, iOS); x86_64 does not build.

Benchmarked variant: `public` (variable-time table-math). Upstream documentation states it "leaks
witness via timing if used with private data"; a constant-time `ct` variant exists and is the
recommended mode for private witnesses. Every system in this suite benchmarks a variable-time
prover; numbers here are comparable on that basis.

## Metadata notes

- `security_bits: 128`: `min(-log2((1-δ)^q), 128)` with q = 176 and δ the exact Singleton
  distance of the chosen geometry (fractional support, or the full-half fallback with δ = 0.5 for
  small grids). Enforced per table at runtime by both prover and verifier (`Config::check_security`).
  Hekate is not FRI-based; the repo's STARK-FRI re-estimation does not apply.
- `is_zk: false`: conservative per the upstream policy. Hiding of the LDT openings is provable
  (uniform randomizable support, `support >= num_queries`), but a formal zero-knowledge argument
  for the full protocol is pending; `false` here means "not sufficiently established", not "leaks".
- `preprocessing_size`: Hekate has no proving key, verifying key, or trusted setup. The reported
  artifact is the witness-free serialized program bundle the prover consumes
  (`serialize_bundle_header`), which is what a real application persists between runs.
- `num_constraints`: constraint AST roots (the zerocheck polynomials): 1664 = 1662 Keccak chiplet
  roots + 2 CPU link roots.
- `proof_size`: canonical wire format (v4) via `serialize_proof_bytes`; Hekate's own published
  figures use bincode and differ slightly.

## Results

Local cross-system Keccak-256 measurements (Apple M3 Max, 16 cores, 48 GB) are in `RESULTS.md`,
including the prove/verify timings that the JSON artifacts do not persist. These are not official
csp-benchmarks results; the published ones were measured on an M1 with 8 cores and 16 GB.

## Comparison methodology

A prove-time comparison is only meaningful if every system does the same work inside the timed
region. The boundary that matters is witness generation: a system that builds its witness in
untimed setup will look faster than one that does it while the clock runs. All five systems in
`RESULTS.md` generate the witness inside the timed prove call.

| System | Witness generation | Where |
|---|---|---|
| hekate | timed | sponge execution + trace build in `prove_keccak` |
| flock | timed | `generate_witness_with_ab_packed_and_lincheck` in `full_keccak::prove` |
| binius64 | timed | `populate_witness` + `populate_wire_witness` in `prove` |
| stark-v | timed | `vm.prove` runs guest execution and witness generation |
| plonky2 | timed | `data.prove(pw)` runs the generator pass; only input bits are pre-set |

Circuit construction, proving-key setup and PCS parameter generation are outside the timed region
for every system, which is what `preprocessing_size` accounts for separately.

Two systems in the table prove a different kind of statement. stark-v and plonky2 are
general-purpose (a RISC-V zkVM and a hand-built circuit over a general framework), while hekate,
flock and binius64 are fixed-function Keccak provers. Comparing them is legitimate but the
construction column in `RESULTS.md` is not decoration; read it before drawing conclusions.

Three things will differ if you rerun this and should not be read as tampering. Hekate's proof
size is not deterministic; a fresh `OsRng` blinding seed per proof moves it by roughly ±1.5%.
plonky2 was only run at 128 B and 256 B. Verify times are recorded as a range across input sizes
rather than per size, and your per-size output will not line up cell for cell.

## Running

The crate is excluded from the workspace: `hekate-prover-sys` needs `keccak 0.2.0` (via its
ML-DSA signature verification) while ProveKit pins `keccak =0.2.0-rc.2`. One resolver cannot hold
both (the binius64 situation). Build and bench from inside `hekate/`; the crate has its own
`Cargo.lock`.

```bash
cd hekate
cargo test --lib
BENCH_INPUT_PROFILE=reduced cargo bench   # 128 B and 256 B; full = all five sizes
```

That is the whole recipe for this crate: no toolchain installs, no code generation step, no
external prover CLI. `.cargo/config.toml` redirects `target-dir` to `../target`, which makes the
RAM binary the harness compiles the same file it executes. Without the redirect those are two
different files and the memory numbers describe whichever stale build was last copied across.

**Two hard requirements, and they rule out most machines.** The prover is a prebuilt cdylib
fetched from `releases.oumuamua.dev` on first build, which requires network access. It is
published for aarch64 only, and **x86_64 does not build at all**. If you are on an x86 host you
cannot reproduce Hekate's row by any means. That is a real limit of benchmarking a closed-source
prover, stated here rather than buried.

### Reproducing the rest of the table

The four comparison systems are plain cargo. None of them need `nargo`, `rzup`, `bb` or the jolt
CLI, which are what block the systems absent from `RESULTS.md`. There is no single command for the
whole table. Run each from the repository root, one at a time, because concurrent runs contaminate
each other's timings:

```bash
(cd flock    && BENCH_INPUT_PROFILE=reduced cargo bench --bench keccak)        # workspace member
(cd plonky2  && BENCH_INPUT_PROFILE=reduced cargo bench --bench keccak)        # workspace member
(cd binius64 && BENCH_INPUT_PROFILE=reduced cargo bench --bench keccak_bench)  # excluded crate
(cd stark-v  && BENCH_INPUT_PROFILE=reduced cargo bench --bench keccak)        # excluded crate
```

binius64 and stark-v build their RAM binary into their own `target/` while the harness executes
`../target/release/`; upstream CI bridges that with an explicit copy step. Check the two match
before trusting a peak-memory figure, or you will measure a stale binary.

The root workspace as a whole pulls in OpenMPI, LLVM/LLD and protobuf for systems unrelated to
this table. Building only these four is expected not to need them, but that is untested. If you
hit it, see below.

## Corrections welcome

If a system here is configured worse than its maintainers would run it, open an issue or a PR and
it will be merged, including when it narrows Hekate's lead. The standard is the system's own
documented recommended configuration for this workload, not hand-tuning, and not a build the
project would not endorse. Numbers that only survive a favourable setup are not worth publishing.

## CI

`lints.yml` builds, formats, and clippies this crate through `EXCLUDED_CRATES`, which gates it
like any other crate. It is deliberately absent from `rust_benchmarks_parallel.yml`: that
workflow publishes into the shared results pipeline, and these numbers are not official
csp-benchmarks results. Benchmark runs are manual, on stated hardware, and recorded in
`RESULTS.md`.
