# Hekate: Keccak-256 and SHA-256

Hekate verifies a Keccak-256 proof in 3.5 ms and a SHA-256 proof in 3.7 ms, the fastest on this
board for both hashes, and holds that within 2 ms as the message grows 120x. It proves Keccak-256
faster than any other system above roughly 91 permutations.

These are **not official csp-benchmarks results**. Upstream accepts only fully open-source
systems, and Hekate's prover is a closed-source signed cdylib. This integration lives on a fork,
the numbers are published independently by Oumuamua Labs, and they must not be merged with the
EF-published rows in `results/`, which were collected on an M1 / 8 cores / 16 GB.

## Measured

Apple M3 Max, 16 cores, 48 GiB, arm64. Hekate crates pinned at 0.37.0 (`hekate-keccak` 0.10.0,
`hekate-sha2` 0.3.0, `hekate-math` 0.12.0), prover cdylib 0.15.0, `public` variant, `Config::prod()`
with `zero_knowledge` set. Criterion medians.

Prove and verify durations exist **only in this file**. Every system writes a `proof_duration: 0`
placeholder and the real timings go to criterion stdout; the JSON artifacts are gitignored. Proof
sizes, constraint counts and preprocessing sizes come from those artifacts.

Proof size is not deterministic for provers that draw a fresh blinding seed per call, and repeat
runs of the same input vary by roughly ±1.5%. Preprocessing size and constraint count are
deterministic.

flock is pinned at `succinctlabs/flock` rev `4af7a4d`, which ships the keccak R1CS gadget at
`crates/flock-prover/src/r1cs_hashes/keccak.rs`. That gadget is absent from flock's `main`, and
the row reproduces at the pinned revision only.

## Keccak-256

| System | 128 B | 256 B | 512 B | 1024 B | 2048 B | Construction |
|---|---|---|---|---|---|---|
| flock | 9.1 | 10.0 | 11.8 | 14.4 | 20.2 | fixed-function keccak R1CS + BaseFold |
| hekate | 41.9 | 42.7 | 42.6 | 42.9 | 47.3 | inline keccak-f chiplet AIR + Brakedown |
| binius64 | 99.7 | 109.4 | 109.6 | 110.3 | 120.5 | explicit word-level circuit |
| stark-v | 890 | 870 | 891 | 956 | 1164 | RISC-V zkVM |
| plonky2 | 1984 | 3362 | n/a | n/a | n/a | explicit circuit (partial run) |

Prove time, ms. Verify, peak RAM and proof size at the same sizes:

| System | Verify (ms) | Peak RAM (MiB) | Proof (KiB) |
|---|---|---|---|
| hekate | 3.48 – 3.62 | 36.8 – 57.6 | 353 – 358 |
| flock | 4.06 – 4.55 | 24.6 – 29.1 | 502 – 518 |
| stark-v | 11.2 – 13.5 | 1911 – 2173 | 1723 – 1728 |
| binius64 | 78.3 – 106.0 | 486.9 – 604.5 | 407 – 436 |
| plonky2 | 51 – 86 | 1647 – 2754 | 151 – 158 |

### Real workload

The sizes above stop at 16 permutations, where every system still pays mostly fixed protocol
cost. plonky2 is excluded at 3.4 s for 256 B, and stark-v caps at 4092 B.

| System | 2 KiB | 4 KiB | 8 KiB | 16 KiB | 32 KiB | 256 KiB |
|---|---|---|---|---|---|---|
| *permutations* | *16* | *31* | *61* | *121* | *241* | *1928* |
| flock | 20.2 | 23.3 | 43.9 | 87.2 | 161.1 | 1250.5 |
| hekate | 46.5 | 54.9 | 61.7 | 69.4 | 81.0 | **260.1** |
| binius64 | 120.5 | 130.3 | 159.1 | 193.9 | 272.8 | 1238.6 |

Prove time, ms. Verify at 2 KiB and 256 KiB: hekate 3.58 and 5.52, flock 4.55 and 35.23,
binius64 89.4 and 482.5. Peak RAM and proof size at 256 KiB: hekate 238 MiB / 1137 KiB, flock
534 MiB / 1270 KiB, binius64 5806 MiB / 589 KiB.

## SHA-256

Every length is a multiple of the 64-byte block, which puts SHA-256's padding and its 64-bit
length field in a block of their own.

| System | 128 B | 256 B | 512 B | 1024 B | 2048 B |
|---|---|---|---|---|---|
| flock | 27.6 | 27.4 | 28.0 | 28.3 | 28.6 |
| hekate | 42.3 | 44.0 | 43.7 | 49.0 | 53.6 |
| binius64 | 104.9 | 104.6 | 104.0 | 107.7 | 108.6 |
| stark-v | 834 | 859 | 872 | 930 | 1027 |
| plonky2 | 1931 | 3410 | 3540 | 6523 | 12108 |

Prove time, ms. Verify, peak RAM and proof size at the same sizes:

| System | Verify (ms) | Peak RAM (MiB) | Proof (KiB) |
|---|---|---|---|
| hekate | 3.65 – 3.75 | 39 – 75 | 422 – 487 |
| flock | 4.44 – 4.91 | 47 – 54 | 381 – 526 |
| stark-v | 10.8 – 10.9 | 1919 – 2081 | 1719 – 1723 |
| plonky2 | 50.4 – 336.3 | 1616 – 10608 | 151 – 178 |
| binius64 | 73.6 – 82.9 | 503 – 578 | 401 – 423 |

## What the numbers say

**Verify is where Hekate separates.** 3.48 ms at one Keccak permutation and 5.52 ms at 1928, a
2 ms spread across a 120x instance. binius64 runs 78 to 482 ms over the same span and plonky2 50
to 336 ms over a 16x SHA-256 span. A verifier whose cost barely moves with the statement is the
property an onchain consumer pays for.

**Prove splits by size.** flock owns the small end on both hashes: a purpose-built prover with no
hiding, 9.1 ms at 128 B of Keccak. The two cross between 61 and 121 permutations, near 91
(~12 KiB), above which Hekate's fixed cost stops mattering and it finishes 4.8x ahead at 256 KiB.
Against binius64, the other binary-field hiding system, Hekate leads by 2.4x at 128 B and 4.8x at
256 KiB on Keccak, and by 2.0x to 2.5x on SHA-256.

**Hekate's cost is a floor, then a slope.** Keccak-256 uses 25 trace rows per permutation with a
256-row minimum, which puts 128 to 1024 B on the same grid: the 41.9 to 42.9 ms spread there is
run noise. Doubling to 512 rows costs 4.5 ms, giving a fixed term near 38 ms and a marginal cost
of 0.106 ms per permutation. binius64's marginal cost is 0.573.

**Preprocessing separates the board further than any timing column.** Hekate persists 641 KB for
SHA-256 and 751 KB for Keccak. plonky2 persists 327 MB, a 510x difference in what a deployment
carries between runs.

**RAM is the binary-field divide.** Hekate peaks at 238 MiB on a 256 KiB Keccak message where
binius64 reaches 5.8 GiB, 24x more, on the same field and the same class of commitment.

## What is being proven

Both statements bind a public digest to a private preimage of the benchmarked length, which is
what `CONTRIBUTING.md` requires of a hash benchmark.

**Keccak-256.** The four digest lanes are public inputs pinned on the last output row. The CPU
link columns carry the sponge: capacity pinned to zero at the first absorb, capacity carried
across every block seam, pad10*1 pinned on the last.

**SHA-256.** The IV is pinned at row 0, the chaining value is carried across every block, the
final block's padding and 64-bit length are pinned word by word, and the eight digest words are
published.

In both circuits the emit selector is a fixed column rather than a witness one. The circuit
declares its shape through `Circuit::fix` and the verifier recomputes it, which is what forces
the hash chain to exist and to sit where the digest pin reads it. Negative tests in `src/lib.rs`
and `src/sha256.rs` cover each pin.

Witness generation runs inside the timed proving closure for all five systems, which is the
boundary that makes a prove-time comparison meaningful. For Hekate that is sponge or compression
execution plus trace construction inside `prove_keccak` and `prove_sha256`; for flock
`generate_witness_with_ab_packed_and_lincheck`, for binius64 `populate_witness` plus
`populate_wire_witness`, for stark-v guest execution inside `vm.prove`, for plonky2 the generator
pass inside `data.prove(pw)`. Circuit construction and PCS parameter generation sit outside the
timed region for every system, which is what `preprocessing_size` accounts for.

stark-v and plonky2 are general-purpose, a RISC-V zkVM and a hand-built circuit over a general
framework. The other three are fixed-function hash provers. The construction column is not
decoration.

## Zero-knowledge is not uniform

The proof-size and verify columns cannot be read without it.

| System | Zero-knowledge |
|---|---|
| hekate | yes, `Config::prod()` sets `zero_knowledge`, and that is the mode measured |
| binius64 | yes, upstream `ZKProver` / `ZKVerifier` on the benchmarked path |
| plonky2 | yes, by construction |
| flock | no |
| stark-v | no |

flock and stark-v carry no hiding cost. Comparing their proof sizes against the other three
compares different guarantees.

## Metadata

- `security_bits: 100`. `Config::prod()` runs 287 queries over 288 support cells and enforces
  `MIN_PRODUCTION_BITS = 100` per table at runtime, in prover and verifier
  (`Config::check_security`). 128 proven bits are unreachable over GF(2^128) at any query count,
  because every additive soundness term has the form `n / |F|` and queries shrink none of them;
  see `docs/postmortem-0.35.md` in the hekate repository. The board reads flock 100, hekate 100,
  plonky2 97, binius64 96, stark-v 94. Hekate is not FRI-based, and the repo's STARK-FRI
  re-estimation does not apply.
- `is_zk: true`. The hiding argument is `docs/zk-ring-switching.pdf` in the hekate repository,
  which states the simulator and its Fiat-Shamir compilation.
- `preprocessing_size`. Hekate has no proving key, verifying key or trusted setup. The reported
  artifact is the witness-free serialized program bundle the prover consumes
  (`serialize_bundle_header`), which is what an application persists between runs.
- `num_constraints`. Constraint-AST roots. Keccak: 1625 structural, 8 capacity-carry, one per
  padding lane at the final seam, running 1633 to 1649 non-monotonically as the message fills the
  last block. SHA-256: 2488 at every size, because its padding lands in boundary constraints
  rather than roots.
- `proof_size`. Canonical wire format v7 via `serialize_proof_bytes`. Hekate's own published
  figures use bincode and differ slightly.
- `acceleration: "precompile"`. A chiplet is ordinary AIR constraints over 1600 virtual bit
  columns linked to the caller by a LogUp bus; what is specialized is the prover's sumcheck
  evaluator for those roots, which changes how fast the same polynomial is evaluated and not what
  the verifier checks. The taxonomy offers `precompile`, `inline`, or omission. `inline` is for VM
  instruction sets. This row reports `precompile`, the label risc0 uses for its guest precompile,
  while flock and binius64 omit the field for their own fixed-function implementations, and that
  omission is the better precedent.

The Keccak construction injects the Keccak-f[1600] chiplet AIR into the main trace, 28 CPU link
columns plus 28 physical chiplet columns, virtually expanded to 1687, giving one commitment and
one merged ZeroCheck. Hekate supports a separate-trace form through `chiplet_defs()`; this
benchmark uses `inline_chiplets()`.

## Building and running

The crate is excluded from the workspace: `hekate-prover-sys` needs `keccak 0.2.0` through its
ML-DSA signature verification while ProveKit pins `keccak =0.2.0-rc.2`, and one resolver cannot
hold both. Build from inside `hekate/`, which has its own `Cargo.lock`.

```bash
cd hekate
cargo test --lib
BENCH_INPUT_PROFILE=reduced cargo bench --bench keccak   # 128 B and 256 B
BENCH_INPUT_PROFILE=full    cargo bench --bench sha256   # all five sizes
```

No toolchain installs, no code generation, no external prover CLI. `.cargo/config.toml` redirects
`target-dir` to `../target`, which makes the RAM binary the harness compiles the same file it
executes.

**Two hard requirements rule out most machines.** The prover is a prebuilt cdylib fetched from
`releases.oumuamua.dev` on first build, verified against a pinned manifest (SHA-256 + Ed25519 +
ML-DSA-65). The build needs network access. It is published for aarch64 only (macOS, Linux glibc,
Android, iOS) and **x86_64 does not build at all**. On an x86 host Hekate's row cannot be
reproduced by any means.

The verifier, SDK and all chiplet AIRs are open source (Apache-2.0). The benchmarked `public`
variant uses variable-time table-math, which upstream documents as leaking witness via timing if
used with private data; a constant-time `ct` variant is the recommended mode for private
witnesses. Every system in this suite benchmarks a variable-time prover.

## Reproducing the comparison

Run one at a time from the repository root. Concurrent runs contend for cores and contaminate
each other's timings.

```bash
export BENCH_INPUT_PROFILE=full

cargo bench -p flock            --bench keccak
cargo bench -p plonky2_circuits --bench sha256
(cd hekate   && cargo bench --bench keccak && cargo bench --bench sha256)
(cd binius64 && cargo bench --bench keccak_bench && cargo bench --bench sha256_bench)
(cd stark-v  && cargo bench --bench keccak && cargo bench --bench sha256)
```

The Keccak real-workload row uses `BENCH_BYTE_INPUTS=2048,4096,8192,16384,32768,262144`, which
overrides the size list directly. `BENCH_INPUT_PROFILE=real-workload` is the named profile and
covers 32768, 262144 and 1048576.

binius64 and stark-v build their RAM binary into their own `target/` while the harness executes
`../target/release/`. Copy it across first, or the peak-memory figure describes a stale build.

## Limits

**stark-v stops at 4092 B.** Its guest linker script fixes a 4 KiB input region
(`__input_len = 0x00001000`), and the harness prepends a 4-byte length, which makes 4096 B fail
with `Input length 4100 exceeds input capacity 4096`. Raising it means forking the VM memory map
in `ClementWalter/stark-v`, which would no longer measure stark-v as shipped. It also vendors
`stwo` and `stwo-constraint-framework` v2.1.0 inside its own repository and layers an RV32IM
zkVM on top; the Circle STARK / M31 / Circle-PCS fields describe that vendored backend.

**plonky2's Keccak row is partial**, 128 B and 256 B only. Its SHA-256 row is complete.

**1048576 B is unmeasured.** At 4x the 256 KiB instance the estimate is ~40 minutes wall clock,
and binius64 needed 84 GB against 48 GiB physical on an earlier attempt. Every system has shown
its asymptote by 256 KiB.

**Not run:** halo2, which has a Keccak bench and is BN254 with a trusted setup, a different
weight class from this board.

**Blocked on a missing toolchain:** provekit and provekit-groth16 (nargo), circom (zkey
toolchain), jolt (jolt CLI), risc0 (rzup), barretenberg (bb).

**No hash target at all:** cairo-m, ligetron, miden, polyhedra-expander, rookie-numbers,
spartan2.

## Corrections welcome

If a system here is configured worse than its maintainers would run it, open an issue or a PR and
it will be merged, including when it narrows Hekate's lead. The standard is the system's own
documented recommended configuration for this workload.

## CI

`lints.yml` builds, formats and clippies this crate through `EXCLUDED_CRATES`. It is absent from
`rust_benchmarks_parallel.yml`, which publishes into the shared results pipeline. Benchmark runs
here are manual, on the hardware stated above.
