use std::borrow::Cow;
use std::sync::OnceLock;

use hekate_core::config::Config;
use hekate_core::errors;
use hekate_core::proofs::InnerProof;
use hekate_core::trace::{ColumnTrace, ColumnType, TraceBuilder};
use hekate_crypto::transcript::Transcript;
use hekate_crypto::DefaultHasher;
use hekate_keccak::{
    generate_keccak_trace, CpuKeccakColumns, CpuKeccakUnit, KeccakCall, KeccakChiplet,
    KeccakColumns, KeccakSpongeNative,
};
use hekate_math::{Bit, Block128, Block64, TowerField};
use hekate_program::chiplet::ChipletDef;
use hekate_program::constraint::builder::ConstraintSystem;
use hekate_program::constraint::{BoundaryConstraint, ConstraintAst};
use hekate_program::expander::VirtualExpander;
use hekate_program::permutation::PermutationCheckSpec;
use hekate_program::{Air, InlineKernelHint, Program, ProgramInstance, ProgramWitness};
use hekate_verifier::HekateVerifier;
use rand::rngs::OsRng;
use rand::TryRngCore;
use utils::harness::{AuditStatus, BenchProperties};

type F = Block128;
type H = DefaultHasher;

const TRANSCRIPT_LABEL: &[u8] = b"csp-benchmarks-hekate-keccak";
const KECCAK256_RATE_BYTES: usize = 136;
const KECCAK256_DOMAIN_SEP: u8 = 0x01;
const ROWS_PER_PERMUTATION: usize = 25;
const DIGEST_LANES: usize = 4;
const KECCAK_OFFSET: usize = CpuKeccakColumns::NUM_COLUMNS;

// Config::prod() enforces support >= num_queries (176),
// which requires a committed grid of >= 256 columns;
// smaller traces fail the security gate inside the prover.
// See Config::table_geom.
const MIN_NUM_VARS: usize = 8;

pub const HEKATE_BENCH_PROPERTIES: BenchProperties = BenchProperties {
    proving_system: Cow::Borrowed("Hekate"), // https://github.com/oumuamua-labs/hekate
    field_curve: Cow::Borrowed("F2^128"), // binary tower field: https://github.com/oumuamua-labs/hekate#readme
    iop: Cow::Borrowed("Sumcheck + LogUp"), // https://github.com/oumuamua-labs/hekate#readme
    pcs: Some(Cow::Borrowed("Brakedown")), // MDS RS tensor code: https://github.com/oumuamua-labs/hekate/blob/main/docs/postmortem-0.32.md
    arithm: Cow::Borrowed("AIR"),
    // blinding is on by default but no public formal hiding argument
    // exists for the benchmarked mode; conservative per CONTRIBUTING.md
    is_zk: false,
    is_zkvm: false,
    // min(-log2((1-delta)^q), 128), q = 176;
    // enforced per table by the verifier:
    // hekate-core/src/config.rs (MIN_PRODUCTION_BITS)
    security_bits: 128,
    // hash-based Merkle commitments over a linear code;
    // no discrete-log assumptions
    is_pq: true,
    is_maintained: true,
    is_audited: AuditStatus::NotAudited, // https://github.com/oumuamua-labs/hekate#readme security disclaimer
    isa: None,
};

/// Keccak-256 over the inline-chiplet construction:
/// the Keccak-f[1600] chiplet AIR shares one trace
/// and one commitment with the CPU link columns.
#[derive(Clone)]
pub struct KeccakBenchProgram {
    num_rows: usize,
    num_blocks: usize,
}

impl Air<F> for KeccakBenchProgram {
    fn num_columns(&self) -> usize {
        CpuKeccakColumns::NUM_COLUMNS + KeccakColumns::NUM_COLUMNS
    }

    fn boundary_constraints(&self) -> Vec<BoundaryConstraint<F>> {
        // The digest lives on the last output row of
        // the real sponge chain; capacity padding rows
        // above it must stay unpinned.
        let last_output_row = ROWS_PER_PERMUTATION * self.num_blocks - 1;

        (0..DIGEST_LANES)
            .map(|i| BoundaryConstraint::with_public_input(i, last_output_row, i))
            .chain([CpuKeccakUnit::direction_boundary(0)])
            .collect()
    }

    fn column_layout(&self) -> &[ColumnType] {
        static LAYOUT: OnceLock<Vec<ColumnType>> = OnceLock::new();

        LAYOUT.get_or_init(|| {
            let mut cols = cpu_layout().to_vec();
            cols.extend_from_slice(KeccakChiplet::physical_layout());

            cols
        })
    }

    fn permutation_checks(&self) -> Vec<(String, PermutationCheckSpec)> {
        let cpu_spec = CpuKeccakUnit::linking_spec();

        let mut keccak_spec = KeccakChiplet::linking_spec();
        keccak_spec.shift_column_indices(KECCAK_OFFSET);

        // Both endpoints must share the bus id, otherwise
        // LogUp cross-bus cancellation cannot pair them.
        vec![
            (KeccakChiplet::BUS_ID.into(), cpu_spec),
            (KeccakChiplet::BUS_ID.into(), keccak_spec),
        ]
    }

    fn virtual_expander(&self) -> Option<&VirtualExpander> {
        static EXPANDER: OnceLock<VirtualExpander> = OnceLock::new();

        Some(EXPANDER.get_or_init(|| {
            let cpu = VirtualExpander::new()
                .pass_through(25, ColumnType::B64)
                .control_bits(2);

            KeccakChiplet::expand_into(cpu, KECCAK_OFFSET)
                .build()
                .expect("keccak inline expander")
        }))
    }

    fn constraint_ast(&self) -> ConstraintAst<F> {
        let cs = ConstraintSystem::<F>::new();
        CpuKeccakUnit::constrain(&cs, 0);

        let mut ast = cs.build();

        let mut keccak_ast = KeccakChiplet::new(self.num_rows).constraint_ast();
        keccak_ast.arena.shift_cells(KECCAK_OFFSET);
        ast.merge(keccak_ast);

        ast
    }

    fn inline_chiplets(&self) -> errors::Result<Vec<ChipletDef<F>>> {
        Ok(vec![ChipletDef::from_air(&KeccakChiplet::new(
            self.num_rows,
        ))?])
    }

    fn inline_chiplet_kernels(&self) -> Vec<InlineKernelHint> {
        vec![InlineKernelHint {
            chiplet_idx: 0,
            root_offset: CpuKeccakUnit::NUM_ROOTS,
            column_offset: KECCAK_OFFSET,
        }]
    }
}

impl Program<F> for KeccakBenchProgram {
    fn num_public_inputs(&self) -> usize {
        DIGEST_LANES
    }
}

pub struct PreparedKeccak {
    message: Vec<u8>,
    air: KeccakBenchProgram,
    instance: ProgramInstance<F>,
    config: Config,
}

pub struct KeccakProof(InnerProof<F>);

fn cpu_layout() -> &'static [ColumnType] {
    static CPU_LAYOUT: OnceLock<Vec<ColumnType>> = OnceLock::new();

    CPU_LAYOUT.get_or_init(CpuKeccakColumns::build_layout)
}

fn sponge_calls(message: &[u8]) -> Vec<KeccakCall> {
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

    let mut tb = TraceBuilder::new(cpu_layout(), num_vars)?;
    let mut row = 0;

    for (input, output) in calls {
        for (i, &lane) in input.iter().enumerate() {
            tb.set_b64(i, row, Block64::from(lane))?;
        }

        tb.set_bit(CpuKeccakColumns::SELECTOR, row, Bit::ONE)?;

        for r in row + 1..=row + 24 {
            tb.set_bit(CpuKeccakColumns::IS_OUTPUT, r, Bit::ONE)?;
        }

        row += 24;

        for (i, &lane) in output.iter().enumerate() {
            tb.set_b64(i, row, Block64::from(lane))?;
        }

        tb.set_bit(CpuKeccakColumns::SELECTOR, row, Bit::ONE)?;

        row += 1;
    }

    let mut trace = tb.build();

    let inputs: Vec<[Block64; 25]> = calls
        .iter()
        .map(|(input, _)| input.map(Block64::from))
        .collect();
    let pairs: Vec<(u32, u32)> = (0..calls.len() as u32)
        .map(|k| (25 * k, 25 * k + 24))
        .collect();

    for col in generate_keccak_trace(&inputs, Some(&pairs), num_rows)?.into_columns() {
        trace.add_column(col)?;
    }

    Ok(trace)
}

pub fn prepare_keccak(input_size: usize) -> PreparedKeccak {
    let (message, expected_digest) = utils::generate_keccak_input(input_size);

    let calls = sponge_calls(&message);
    let num_blocks = calls.len();
    let num_rows = (ROWS_PER_PERMUTATION * num_blocks)
        .next_power_of_two()
        .max(1 << MIN_NUM_VARS);

    let lanes = digest_lanes(&calls);

    assert_eq!(
        digest_bytes(lanes).as_slice(),
        expected_digest.as_slice(),
        "hekate sponge disagrees with the reference Keccak-256 digest"
    );

    let air = KeccakBenchProgram {
        num_rows,
        num_blocks,
    };
    let instance = ProgramInstance::new(num_rows, public_inputs(lanes));

    PreparedKeccak {
        message,
        air,
        instance,
        config: Config::default(),
    }
}

pub fn prove_keccak(prepared: &PreparedKeccak) -> KeccakProof {
    // Sponge execution is re-run rather than cached in `PreparedKeccak`:
    // witness generation must stay inside the timed region.
    let calls = sponge_calls(&prepared.message);
    let trace = build_trace(&calls, prepared.air.num_rows).expect("keccak trace construction");
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
    prepared.air.constraint_ast().roots.len()
}

pub fn preprocessing_size_keccak(prepared: &PreparedKeccak) -> usize {
    // Hekate has no proving key or trusted setup;
    // the persisted circuit artifact is the witness-free
    // program bundle the prover consumes.
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

    #[test]
    fn reduced_keccak_roundtrip() {
        let prepared = prepare_keccak(128);
        assert_eq!(prepared.air.num_blocks, 1);

        let proof = prove_keccak(&prepared);
        verify_keccak(&prepared, &proof);

        assert!(num_constraints_keccak(&prepared) > 1000);
        assert!(proof_size_keccak(&proof) > 0);
        assert!(preprocessing_size_keccak(&prepared) > 0);
    }

    #[test]
    fn multi_block_keccak_roundtrip() {
        let prepared = prepare_keccak(512);

        assert_eq!(prepared.air.num_blocks, 4);
        assert_eq!(prepared.air.num_rows, 1 << MIN_NUM_VARS);

        let proof = prove_keccak(&prepared);
        verify_keccak(&prepared, &proof);
    }

    #[test]
    fn largest_input_steps_past_the_row_floor() {
        let prepared = prepare_keccak(2048);

        assert_eq!(prepared.air.num_blocks, 16);
        assert_eq!(prepared.air.num_rows, 512);
    }

    #[test]
    fn tampered_digest_rejected() {
        let prepared = prepare_keccak(128);
        let proof = prove_keccak(&prepared);

        let mut lanes = digest_lanes(&sponge_calls(&prepared.message));
        lanes[0] ^= 1;

        let bad_instance = ProgramInstance::new(prepared.air.num_rows, public_inputs(lanes));

        let mut transcript = Transcript::<H>::new(TRANSCRIPT_LABEL);
        let accepted = HekateVerifier::<F, H>::verify(
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
