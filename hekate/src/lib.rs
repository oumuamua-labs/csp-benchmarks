use std::borrow::Cow;

use hekate_core::config::Config;
use hekate_core::errors;
use hekate_core::proofs::InnerProof;
use hekate_core::trace::{ColumnTrace, ColumnType, TraceBuilder};
use hekate_crypto::transcript::Transcript;
use hekate_crypto::DefaultHasher;
use hekate_keccak::{
    generate_keccak_trace, CpuKeccakColumns, KeccakCall, KeccakChiplet, KeccakSpongeNative,
};
use hekate_math::{Bit, Block128, Block64, TowerField};
use hekate_program::chiplet::ChipletDef;
use hekate_program::circuit::{Circuit, CircuitProgram, Col};
use hekate_program::digest::program_id;
use hekate_program::{FixedShape, ProgramInstance, ProgramWitness};
use hekate_verifier::HekateVerifier;
use rand::rngs::OsRng;
use rand::TryRngCore;
use utils::harness::{AuditStatus, BenchProperties};

mod sha256;

pub use sha256::*;
use zeroize::Zeroizing;

type F = Block128;
type H = DefaultHasher;

const TRANSCRIPT_LABEL: &[u8] = b"csp-benchmarks-hekate-keccak";
const KECCAK256_RATE_BYTES: usize = 136;
const KECCAK256_RATE_LANES: usize = KECCAK256_RATE_BYTES / 8;
const KECCAK256_DOMAIN_SEP: u8 = 0x01;
const STATE_LANES: usize = 25;
const DIGEST_LANES: usize = 4;

const OUT_GATE: usize = CpuKeccakColumns::NUM_COLUMNS;
const PAD_SEAM: usize = CpuKeccakColumns::NUM_COLUMNS + 1;

/// Row floor. `Config::prod()` clears its security gate
/// only on a committed grid of at least 256 columns.
const MIN_NUM_VARS: usize = 8;

/// `Config::prod()` sets `zero_knowledge`; the hiding
/// argument is `docs/zk-ring-switching.pdf` in the hekate
/// repository, per the `CONTRIBUTING.md` reference rule.
pub const HEKATE_BENCH_PROPERTIES: BenchProperties = BenchProperties {
    proving_system: Cow::Borrowed("Hekate"),
    field_curve: Cow::Borrowed("F2^128"),
    iop: Cow::Borrowed("Sumcheck + LogUp"),
    pcs: Some(Cow::Borrowed("Brakedown")),
    arithm: Cow::Borrowed("AIR"),
    is_zk: true,
    is_zkvm: false,
    security_bits: 100,
    is_pq: true,
    is_maintained: true,
    is_audited: AuditStatus::NotAudited,
    isa: None,
};

fn pad_seam_row(num_blocks: usize) -> usize {
    KeccakChiplet::BLOCK_ROWS * (num_blocks - 1) - 1
}

/// Keccak-256 keeps the `0x01` suffix, not SHA3-256's `0x06`.
fn pad_lanes(msg_len: usize) -> impl Iterator<Item = (usize, u64)> {
    let remainder = msg_len % KECCAK256_RATE_BYTES;

    assert_eq!(
        remainder % 8,
        0,
        "pad10*1 lands mid-lane; CPU lanes are B64 pass-through and cannot be pinned per byte"
    );

    let first = remainder / 8;

    (first..KECCAK256_RATE_LANES).map(move |lane| {
        let mut value = 0u64;

        if lane == first {
            value |= KECCAK256_DOMAIN_SEP as u64;
        }

        if lane == KECCAK256_RATE_LANES - 1 {
            value |= 0x80u64 << 56;
        }

        (lane, value)
    })
}

fn build_program(
    num_rows: usize,
    num_blocks: usize,
    msg_len: usize,
) -> errors::Result<CircuitProgram<F>> {
    let mut cx = Circuit::<F>::new("csp-benchmarks-keccak256", num_rows)?;

    let cpu = cx.schema(&CpuKeccakColumns::build_layout());

    let selector = cpu.at(CpuKeccakColumns::SELECTOR);

    let lane = |i: usize| cpu.at(CpuKeccakColumns::LANES + i);

    let call_values: Vec<Col> = (0..STATE_LANES).map(lane).collect();
    cx.call(&KeccakChiplet::service(), &call_values, selector)?;

    let stride = KeccakChiplet::BLOCK_ROWS;
    cx.fix(
        selector,
        KeccakChiplet::host_selector_shape(stride, num_blocks),
    );

    let emit_output = cx.column(ColumnType::Bit);
    cx.fix(
        emit_output,
        FixedShape::Cadence {
            stride,
            count: num_blocks,
            origin: 0,
            values: (0..stride)
                .map(|off| match off == stride - 1 {
                    true => F::ONE,
                    false => F::ZERO,
                })
                .collect(),
        },
    );

    let seam = cx.column(ColumnType::Bit);

    let seam_rows = match num_blocks {
        1 => Vec::new(),
        _ => vec![(pad_seam_row(num_blocks), F::ONE)],
    };

    cx.fix(seam, FixedShape::Sparse(seam_rows));

    cx.mount(ChipletDef::from_air(&KeccakChiplet::new(
        num_rows, num_blocks,
    ))?);

    for i in KECCAK256_RATE_LANES..STATE_LANES {
        cx.boundary(lane(i), 0, F::ZERO);
    }

    let cs = cx.cs();
    let carry = cs.col(emit_output.index());

    for i in KECCAK256_RATE_LANES..STATE_LANES {
        let col = lane(i).index();
        cs.assert_zero_when(carry, cs.next(col) + cs.col(col));
    }

    match num_blocks {
        1 => {
            for (i, value) in pad_lanes(msg_len) {
                cx.boundary(lane(i), 0, F::from(Block64::from(value)));
            }
        }
        _ => {
            let cs = cx.cs();
            let gate = cs.col(seam.index());

            for (i, value) in pad_lanes(msg_len) {
                let value = cs.constant(F::from(Block64::from(value)));
                let col = lane(i).index();

                cs.assert_zero_when(gate, cs.next(col) + cs.col(col) + value);
            }
        }
    }

    let last_output_row = KeccakChiplet::BLOCK_ROWS * num_blocks - 1;
    for i in 0..DIGEST_LANES {
        cx.publish(lane(i), last_output_row);
    }

    cx.compile()
}

pub struct PreparedKeccak {
    message: Vec<u8>,
    air: CircuitProgram<F>,
    pinned_id: [u8; 32],
    instance: ProgramInstance<F>,
    config: Config,
    num_rows: usize,
}

pub struct KeccakProof(InnerProof<F>);

fn cpu_layout() -> Vec<ColumnType> {
    let mut cols = CpuKeccakColumns::build_layout();
    cols.push(ColumnType::Bit);
    cols.push(ColumnType::Bit);

    cols
}

fn sponge_calls(message: &[u8]) -> Zeroizing<Vec<KeccakCall>> {
    let mut sponge = KeccakSpongeNative::new();
    sponge.absorb(message, KECCAK256_RATE_BYTES, KECCAK256_DOMAIN_SEP);

    sponge.into_calls()
}

fn digest_lanes(calls: &[KeccakCall]) -> [u64; DIGEST_LANES] {
    let (_, final_state) = calls.last().expect("at least one permutation");

    [
        final_state[0],
        final_state[1],
        final_state[2],
        final_state[3],
    ]
}

fn digest_bytes(lanes: [u64; DIGEST_LANES]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (chunk, lane) in out.chunks_exact_mut(8).zip(lanes) {
        chunk.copy_from_slice(&lane.to_le_bytes());
    }

    out
}

fn public_inputs(lanes: [u64; DIGEST_LANES]) -> Vec<F> {
    lanes.map(|lane| F::from(Block64::from(lane))).to_vec()
}

fn build_trace(calls: &[KeccakCall], num_rows: usize) -> errors::Result<ColumnTrace> {
    let num_vars = num_rows.trailing_zeros() as usize;

    let mut tb = TraceBuilder::new_secret(&cpu_layout(), num_vars)?;
    let mut row = 0;

    for (input, output) in calls {
        let output_row = row + KeccakChiplet::BLOCK_ROWS - 1;

        for (i, &lane) in input.iter().enumerate() {
            tb.set_b64(i, row, Block64::from(lane))?;
        }

        tb.set_bit(CpuKeccakColumns::SELECTOR, row, Bit::ONE)?;

        for (i, &lane) in output.iter().enumerate() {
            tb.set_b64(i, output_row, Block64::from(lane))?;
        }

        tb.set_bit(CpuKeccakColumns::SELECTOR, output_row, Bit::ONE)?;
        tb.set_bit(OUT_GATE, output_row, Bit::ONE)?;

        row = output_row + 1;
    }

    let (_, last_output) = calls.last().expect("at least one permutation");
    for (lane, &value) in last_output.iter().enumerate().skip(KECCAK256_RATE_LANES) {
        tb.set_b64(lane, row, Block64::from(value))?;
    }

    if calls.len() > 1 {
        tb.set_bit(PAD_SEAM, pad_seam_row(calls.len()), Bit::ONE)?;
    }

    let mut trace = tb.build();

    let inputs: Vec<[Block64; STATE_LANES]> = calls
        .iter()
        .map(|(input, _)| input.map(Block64::from))
        .collect();

    for col in generate_keccak_trace(&inputs, num_rows)?.into_columns() {
        trace.add_column(col)?;
    }

    Ok(trace)
}

pub fn prepare_keccak(input_size: usize) -> PreparedKeccak {
    let (message, expected_digest) = utils::generate_keccak_input(input_size);

    assert_eq!(
        message.len() % 8,
        0,
        "input size {} is not a multiple of 8; pad10*1 would land mid-lane \
         and the CPU lanes are B64 pass-through, which cannot be pinned per byte",
        message.len()
    );

    let calls = sponge_calls(&message);
    let num_blocks = calls.len();
    let num_rows = (KeccakChiplet::BLOCK_ROWS * num_blocks)
        .next_power_of_two()
        .max(1 << MIN_NUM_VARS);

    let lanes = digest_lanes(&calls);

    assert_eq!(
        digest_bytes(lanes).as_slice(),
        expected_digest.as_slice(),
        "hekate sponge disagrees with the reference Keccak-256 digest"
    );

    let air = build_program(num_rows, num_blocks, message.len()).expect("keccak circuit");
    let pinned_id = program_id(&air).expect("program id");
    let instance = ProgramInstance::new(num_rows, public_inputs(lanes));

    PreparedKeccak {
        message,
        air,
        pinned_id,
        instance,
        config: Config::default(),
        num_rows,
    }
}

/// Re-runs the sponge rather than caching it in `PreparedKeccak`:
/// witness generation belongs inside the timed region.
pub fn prove_keccak(prepared: &PreparedKeccak) -> KeccakProof {
    let calls = sponge_calls(&prepared.message);
    let trace = build_trace(&calls, prepared.num_rows).expect("keccak trace construction");
    let witness = ProgramWitness::new(trace);

    let mut seed = [0u8; 32];
    OsRng.try_fill_bytes(&mut seed).expect("OS entropy");

    let proof = hekate_prover_sys::prove(
        TRANSCRIPT_LABEL,
        &prepared.air,
        &prepared.instance,
        &witness,
        &prepared.config,
        seed,
        None,
    )
    .expect("hekate prover");

    KeccakProof(proof)
}

pub fn verify_keccak(prepared: &PreparedKeccak, proof: &KeccakProof) {
    let mut transcript = Transcript::<H>::new(TRANSCRIPT_LABEL);
    let valid = HekateVerifier::<F, H>::verify(
        &prepared.pinned_id,
        &prepared.air,
        &prepared.instance,
        &proof.0,
        &mut transcript,
        &prepared.config,
    )
    .expect("hekate verifier");

    assert!(valid, "hekate proof rejected");
}

pub fn num_constraints_keccak(prepared: &PreparedKeccak) -> usize {
    use hekate_program::Air;

    prepared.air.constraint_ast().roots.len()
}

/// Hekate has no proving key or trusted setup; the
/// persisted artifact is the witness-free program bundle.
pub fn preprocessing_size_keccak(prepared: &PreparedKeccak) -> usize {
    hekate_sdk::serialize_bundle_header(&prepared.air, &prepared.instance, &prepared.config)
        .expect("bundle header serialization")
        .len()
}

pub fn proof_size_keccak(proof: &KeccakProof) -> usize {
    hekate_sdk::serialize_proof_bytes(&proof.0).len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hekate_keccak::KeccakWitness;

    const TEST_SEED: [u8; 32] = [0xA5; 32];

    fn keccak_f(mut state: [u64; STATE_LANES]) -> [u64; STATE_LANES] {
        for &rc in &KeccakChiplet::ROUND_CONSTANTS {
            state = KeccakWitness::keccak_f_round(state, rc);
        }

        state
    }

    /// Takes a chain `prepare_keccak` cannot express.
    /// A refusal anywhere counts as rejection.
    fn accepts_chain(calls: &[KeccakCall], msg_len: usize) -> bool {
        let num_blocks = calls.len();
        let num_rows = (KeccakChiplet::BLOCK_ROWS * num_blocks)
            .next_power_of_two()
            .max(1 << MIN_NUM_VARS);

        let air = build_program(num_rows, num_blocks, msg_len).expect("keccak circuit");
        let pinned_id = program_id(&air).expect("program id");

        let instance = ProgramInstance::new(num_rows, public_inputs(digest_lanes(calls)));
        let witness = ProgramWitness::new(build_trace(calls, num_rows).expect("trace"));
        let config = Config::default();

        let proof = match hekate_prover_sys::prove(
            TRANSCRIPT_LABEL,
            &air,
            &instance,
            &witness,
            &config,
            TEST_SEED,
            None,
        ) {
            Ok(proof) => proof,
            Err(e) => {
                println!("prover refused: {e:?}");
                return false;
            }
        };

        let mut transcript = Transcript::<H>::new(TRANSCRIPT_LABEL);

        HekateVerifier::<F, H>::verify(
            &pinned_id,
            &air,
            &instance,
            &proof,
            &mut transcript,
            &config,
        )
        .unwrap_or_else(|e| {
            println!("verifier error: {e:?}");
            false
        })
    }

    #[test]
    fn reduced_keccak_roundtrip() {
        let prepared = prepare_keccak(128);

        let proof = prove_keccak(&prepared);
        verify_keccak(&prepared, &proof);

        assert!(num_constraints_keccak(&prepared) > 1000);
        assert!(proof_size_keccak(&proof) > 0);
        assert!(preprocessing_size_keccak(&prepared) > 0);
    }

    #[test]
    fn multi_block_keccak_roundtrip() {
        let prepared = prepare_keccak(512);
        assert_eq!(prepared.num_rows, 1 << MIN_NUM_VARS);

        let proof = prove_keccak(&prepared);
        verify_keccak(&prepared, &proof);
    }

    #[test]
    fn largest_input_steps_past_the_row_floor() {
        assert_eq!(prepare_keccak(2048).num_rows, 512);
    }

    #[test]
    fn honest_chain_accepted() {
        let calls = sponge_calls(&utils::generate_keccak_input(256).0);

        assert_eq!(calls.len(), 2);
        assert!(accepts_chain(&calls, 256));
    }

    /// Isolates the zero-capacity pin: one correct
    /// permutation, correctly padded, nonzero capacity.
    #[test]
    fn nonzero_initial_capacity_rejected() {
        let mut input = [0u64; STATE_LANES];
        input[KECCAK256_RATE_LANES - 1] = 0x8000_0000_0000_0001;
        input[KECCAK256_RATE_LANES] = 1;

        assert!(!accepts_chain(&[(input, keccak_f(input))], 128));
    }

    /// Isolates the pad10*1 gate: two correct permutations,
    /// capacity zeroed and carried, final block unpadded.
    #[test]
    fn missing_final_padding_rejected() {
        let mut first = [0u64; STATE_LANES];
        first[0] = 0xdead_beef;

        let first_out = keccak_f(first);

        let mut second = first_out;
        second[0] ^= 0xfeed;

        let calls = [(first, first_out), (second, keccak_f(second))];

        assert!(!accepts_chain(&calls, 256));
    }

    #[test]
    fn tampered_digest_rejected() {
        let prepared = prepare_keccak(128);
        let proof = prove_keccak(&prepared);

        let mut lanes = digest_lanes(&sponge_calls(&prepared.message));
        lanes[0] ^= 1;

        let bad_instance = ProgramInstance::new(prepared.num_rows, public_inputs(lanes));

        let mut transcript = Transcript::<H>::new(TRANSCRIPT_LABEL);
        let accepted = HekateVerifier::<F, H>::verify(
            &prepared.pinned_id,
            &prepared.air,
            &bad_instance,
            &proof.0,
            &mut transcript,
            &prepared.config,
        )
        .unwrap_or(false);

        assert!(!accepted, "verifier accepted a tampered digest");
    }
}
