# Keccak-256 measurements: local run

Measured 2026-08-14 on one machine, one harness, sequential runs. These are **not official
csp-benchmarks results** (see `README.md`); they are a local cross-system comparison used to
position Hekate. Do not merge these rows with the EF-published results in `results/`. That
data was collected on an M1 / 8 cores / 16 GB and the two sets are not comparable.

## Host

Apple M3 Max, 16 cores, 48 GiB, macOS 26.5.2, arm64. `BENCH_INPUT_PROFILE=full`.

## Provenance

Proof sizes are from the JSON artifacts (`<system>/keccak_<size>_<system>_metrics.json`). Prove
and verify durations exist **only here**, because every system writes `proof_duration: 0`
placeholders and the real timings go to criterion stdout. That is why this file exists. The JSON
artifacts are gitignored (`*.json`), and nothing else in the repo persists any of this.

Hekate's row is a single clean `cargo bench` run against the current source. An earlier run was
discarded: the harness compiles the RAM binary into the crate's target dir but executes
`../target/release/`, and before `.cargo/config.toml` redirected `target-dir` those were two
different files, which meant the memory figures described a stale build. Rows for the other four
systems predate that fix and were never affected by it. The split only ever touched Hekate, and
binius64 and stark-v were verified byte-identical at both paths.

Proof size is **not deterministic**: `prove_keccak` draws a fresh `OsRng` blinding seed per call,
and repeat runs of the same input vary by roughly ±1.5% (e.g. 512 B produced 184224 and 179408
bytes on two runs). Treat a single figure as one sample, not a constant. Preprocessing size and
constraint count are deterministic.

All five systems generate their witness inside the timed prove call, which makes the prove column
compare like with like. The per-system evidence is in `README.md` under "Comparison methodology",
which also covers what differs between fixed-function and general-purpose systems here.

## Prove time (ms)

| System | 128 B | 256 B | 512 B | 1024 B | 2048 B | Construction |
|---|---|---|---|---|---|---|
| flock | 11.0 | 12.5 | 14.9 | 20.8 | 31.5 | fixed-function keccak R1CS + BaseFold |
| hekate | 51.2 | 53.8 | 52.1 | 52.8 | 58.1 | inline chiplet AIR, Brakedown (precompile) |
| binius64 | 73.7 | 81.5 | 78.8 | 82.8 | 86.3 | explicit word-level circuit |
| stark-v | 827 | 869 | 870 | 921 | 1067 | RISC-V zkVM |
| plonky2 | 1984 | 3362 | n/a | n/a | n/a | explicit circuit (partial run) |

## Verify time, peak RAM, proof size

Verify times are per-system ranges across the measured sizes. RAM and proof size are exact,
from the artifacts.

| System | Verify (ms) | Peak RAM | Proof size |
|---|---|---|---|
| hekate | 3.6–3.9 | 26.4–50.5 MiB | 175.2–217.2 KiB |
| flock | 4.2–4.5 | 24.2–29.2 MiB | 502.7–517.9 KiB |
| binius64 | 23–36 | 159.6–219.6 MiB | 370.9–400.1 KiB |
| stark-v | 11–12 | 1888–2164 MiB | 1.68–1.69 MiB |
| plonky2 | 51–86 | 1647–2754 MiB | 151.3–157.5 KiB |

### Exact per-size figures

Peak RAM (bytes) / proof size (bytes):

| System | 128 B | 256 B | 512 B | 1024 B | 2048 B |
|---|---|---|---|---|---|
| hekate | 27652915 / 182224 | 27643084 / 184264 | 27790540 / 179408 | 27957657 / 183480 | 52943257 / 222400 |
| flock | 25413222 / 514772 | 25750732 / 515220 | 25829376 / 515652 | 25914572 / 516644 | 30634803 / 530308 |
| binius64 | 167364198 / 379792 | 174406041 / 387280 | 170565632 / 394768 | 209577574 / 402256 | 230252544 / 409744 |
| stark-v | 1979809792 / 1767161 | 2047996723 / 1763851 | 2093714636 / 1766980 | 2133422899 / 1769382 | 2268966092 / 1765414 |
| plonky2 | 1726791680 / 154892 | 2887729152 / 161292 | n/a | n/a | n/a |

Hekate `preprocessing_size` is 737232 bytes and `num_constraints` is 1664 at every input size.
Both are properties of the AIR, not the message.

### Head to head at one size

Sorted by prove time. Prove, peak RAM and proof size are exact for that input. Verify is
reported the same way for every system, as the observed range across all measured inputs, because
that is the resolution at which it was recorded for the whole board, Hekate included.

#### Keccak-256, 128 B input

Apple M3 Max, 16 cores, 48 GB · csp-benchmarks harness · not official Ethproofs results

| System | Prove | Verify (range, all sizes) | Peak RAM | Proof size | Construction |
|---|---|---|---|---|---|
| flock | 11.0 ms | 4.2–4.5 ms | 24.2 MiB | 502.7 KiB | fixed-function R1CS + BaseFold |
| hekate | 51.2 ms | 3.6–3.9 ms | 26.4 MiB | 178.0 KiB | chiplet AIR + Brakedown |
| binius64 | 73.7 ms | 23–36 ms | 159.6 MiB | 370.9 KiB | word-level circuit |
| stark-v | 827 ms | 11–12 ms | 1.84 GiB | 1.69 MiB | RISC-V zkVM (general-purpose) |
| plonky2 | 1984 ms | 51–86 ms | 1.61 GiB | 151.3 KiB | explicit circuit (general-purpose) |

#### Keccak-256, 256 B input

Apple M3 Max, 16 cores, 48 GB · csp-benchmarks harness · not official Ethproofs results

| System | Prove | Verify (range, all sizes) | Peak RAM | Proof size | Construction |
|---|---|---|---|---|---|
| flock | 12.5 ms | 4.2–4.5 ms | 24.6 MiB | 503.1 KiB | fixed-function R1CS + BaseFold |
| hekate | 53.8 ms | 3.6–3.9 ms | 26.4 MiB | 179.9 KiB | chiplet AIR + Brakedown |
| binius64 | 81.5 ms | 23–36 ms | 166.3 MiB | 378.2 KiB | word-level circuit |
| stark-v | 869 ms | 11–12 ms | 1.91 GiB | 1.68 MiB | RISC-V zkVM (general-purpose) |
| plonky2 | 3362 ms | 51–86 ms | 2.69 GiB | 157.5 KiB | explicit circuit (general-purpose) |

plonky2's verify range spans only 128 B and 256 B; every other system's spans all five inputs.

## Cost model

Keccak-256 rate is 136 bytes, which makes the five input sizes 1, 2, 4, 8 and 16 permutations.
Hekate uses 25 trace rows per permutation with a 256-row floor, placing 128–1024 B on a 256-row
grid and stepping 2048 B to 512 rows.

**Hekate** is flat inside a grid tier and steps between them. The 51.2–53.8 ms spread across
1→8 permutations is run noise, not work, because those four inputs all prove the same 256-row
grid, mean 52.5 ms. Doubling the grid to 512 rows costs 5.6 ms. Fitting `fixed + c·rows` gives
`c = 5.6 ms / 256 rows` and `fixed ≈ 46.9 ms`, reproducing both tiers (52.5 and 58.1).

**Flock** is genuinely linear in permutations: `9.5 ms + 1.37 ms per permutation` reproduces
11.0 at n=1 and 31.4 at n=16.

The marginal keccak work is therefore ~3× cheaper in Hekate (~0.46 ms/permutation averaged across
the range, and ~0 within a tier), and the entire 4.7×→1.8× gap at small inputs is Hekate's fixed
~47 ms of protocol overhead: 176-query opening machinery, transcript, FFI, serialization.

**Untested extrapolation.** Those two models cross near 60 permutations (~8 KiB of message),
where flock's linear slope overtakes Hekate's stepped grid cost. This assumes Brakedown +
sumcheck cost is linear in rows, which two grid tiers cannot establish. Measure at 4 KiB and
8 KiB before claiming a crossover.

## Reading it

Flock owns small inputs. It is a purpose-built keccak prover and 11–32 ms is the payoff; the
price is 2.4–2.9× Hekate's proof size. Hekate wins everything else in its weight class:
smallest proofs of the hash-based group, fastest verification on the board, and RAM an order of
magnitude under binius64. Against binius64, the other binary-field system, Hekate leads on
every axis at every size. stark-v and plonky2 are different weight classes.

## Not measured

plonky2 is partial: 128 B and 256 B only, captured during a smoke run. The remaining three
sizes are ~30 minutes.

Blocked on a missing toolchain: provekit and provekit-groth16 (nargo), circom (zkey toolchain),
jolt (jolt CLI), risc0 (rzup), barretenberg (bb).

No keccak target at all: sp1, miden, spartan2, polyhedra-expander, openvm, nexus, cairo-m,
rookie-numbers, ligetron.
