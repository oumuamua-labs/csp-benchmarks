use hekate_core::config::Config;
use hekate_core::errors;
use hekate_core::proofs::InnerProof;
use hekate_core::trace::{ColumnTrace, ColumnType, TraceBuilder};
use hekate_crypto::transcript::Transcript;
use hekate_math::{Bit, TowerField};
use hekate_program::circuit::{Circuit, CircuitProgram};
use hekate_program::digest::program_id;
use hekate_program::{FixedShape, ProgramInstance, ProgramWitness};
use hekate_sha2::{
    digest_bytes, pad_message, CpuSha256Block, Sha256Call, Sha256Chiplet, BLOCK_WORDS, IV, ROUNDS,
    STATE_WORDS,
};
use hekate_verifier::HekateVerifier;
use rand::rngs::OsRng;
use rand::TryRngCore;
use zeroize::Zeroizing;

use crate::{F, H, MIN_NUM_VARS};

const TRANSCRIPT_LABEL: &[u8] = b"csp-benchmarks-hekate-sha256";
const ROUNDS_PER_ROW: usize = 4;
const ROWS_PER_BLOCK: usize = ROUNDS / ROUNDS_PER_ROW;
const BLOCK_BYTES: usize = BLOCK_WORDS * 4;

const CPU_ACTIVE: usize = CpuSha256Block::COLUMNS;
const CPU_CARRY: usize = CPU_ACTIVE + 1;
const CPU_CHAIN: usize = CPU_CARRY + 1;

fn padding_block(msg_len: usize) -> [u32; BLOCK_WORDS] {
    assert_eq!(
        msg_len % BLOCK_BYTES,
        0,
        "input size {msg_len} is not a multiple of {BLOCK_BYTES}; the final block would carry \
         message bytes and the padding pin would be wrong"
    );

    let mut words = [0u32; BLOCK_WORDS];
    let bits = msg_len as u64 * 8;

    words[0] = 0x8000_0000;
    words[BLOCK_WORDS - 2] = (bits >> 32) as u32;
    words[BLOCK_WORDS - 1] = bits as u32;

    words
}

fn num_blocks_for(msg_len: usize) -> usize {
    msg_len / BLOCK_BYTES + 1
}

fn cpu_layout() -> Vec<ColumnType> {
    let mut layout = CpuSha256Block::layout().to_vec();
    layout.extend([ColumnType::Bit; 3]);

    layout
}

struct Circuitry {
    program: CircuitProgram<F>,
    block: CpuSha256Block,
}

fn build_program(chiplet: &Sha256Chiplet<F>, msg_len: usize) -> errors::Result<Circuitry> {
    let num_blocks = num_blocks_for(msg_len);
    let num_rows = chiplet.num_rows();

    let mut cx = Circuit::<F>::new("csp-benchmarks-sha256", num_rows)?;

    let block = CpuSha256Block::declare(&mut cx, 0);

    let active = cx.column(ColumnType::Bit);
    let carry = cx.column(ColumnType::Bit);
    let chain = cx.column(ColumnType::Bit);

    block.connect(&mut cx, active)?;

    let cadence = |count: usize, pred: &dyn Fn(usize) -> bool| FixedShape::Cadence {
        stride: ROWS_PER_BLOCK,
        count,
        origin: 0,
        values: (0..ROWS_PER_BLOCK)
            .map(|off| match pred(off) {
                true => F::ONE,
                false => F::ZERO,
            })
            .collect(),
    };

    cx.fix(active, cadence(num_blocks, &|off| off == 0));
    cx.fix(carry, cadence(num_blocks, &|off| off + 1 < ROWS_PER_BLOCK));
    cx.fix(
        chain,
        cadence(num_blocks - 1, &|off| off + 1 == ROWS_PER_BLOCK),
    );

    for (i, &word) in IV.iter().enumerate() {
        cx.boundary(block.h_in_words.at(i), 0, F::from(u128::from(word)));
    }

    {
        let cs = cx.cs();

        let carry = cs.col(carry.index());
        let chain = cs.col(chain.index());

        for i in 0..STATE_WORDS {
            let h_out = cs.col(block.h_out_words.at(i).index());

            cs.assert_zero_when(carry, cs.next(block.h_out_words.at(i).index()) + h_out);
            cs.assert_zero_when(chain, cs.next(block.h_in_words.at(i).index()) + h_out);
        }
    }

    let final_row = (num_blocks - 1) * ROWS_PER_BLOCK;
    for (i, &word) in padding_block(msg_len).iter().enumerate() {
        cx.boundary(block.msg.at(i), final_row, F::from(u128::from(word)));
    }

    for i in 0..STATE_WORDS {
        cx.publish(block.h_out_words.at(i), final_row);
    }

    cx.mount(chiplet.def()?);

    Ok(Circuitry {
        program: cx.compile()?,
        block,
    })
}

fn sha256_calls(message: &[u8]) -> Zeroizing<Vec<Sha256Call>> {
    let blocks = pad_message(message);

    let mut calls = Zeroizing::new(Vec::with_capacity(blocks.len()));
    let mut h = IV;

    for block in blocks.iter() {
        let call = Sha256Call {
            h_in: h,
            block: *block,
        };

        h = call.h_out();

        calls.push(call);
    }

    calls
}

fn digest_words(calls: &[Sha256Call]) -> [u32; STATE_WORDS] {
    calls.last().expect("at least one block").h_out()
}

fn public_inputs(words: [u32; STATE_WORDS]) -> Vec<F> {
    words.iter().map(|&w| F::from(u128::from(w))).collect()
}

fn build_trace(
    chiplet: &Sha256Chiplet<F>,
    block: &CpuSha256Block,
    calls: &[Sha256Call],
) -> errors::Result<ColumnTrace> {
    let num_rows = chiplet.num_rows();
    let num_vars = num_rows.trailing_zeros() as usize;
    let last = calls.len() - 1;

    let mut tb = TraceBuilder::new_secret(&cpu_layout(), num_vars)?;

    for (b, call) in calls.iter().enumerate() {
        let first_row = b * ROWS_PER_BLOCK;

        for row in first_row..first_row + ROWS_PER_BLOCK {
            block.write(&mut tb, row, call)?;
        }

        tb.set_bit(CPU_ACTIVE, first_row, Bit::ONE)?;

        for row in first_row..first_row + ROWS_PER_BLOCK - 1 {
            tb.set_bit(CPU_CARRY, row, Bit::ONE)?;
        }

        if b < last {
            tb.set_bit(CPU_CHAIN, first_row + ROWS_PER_BLOCK - 1, Bit::ONE)?;
        }
    }

    let mut trace = tb.build();

    for col in chiplet.trace(calls)?.into_columns() {
        trace.add_column(col)?;
    }

    Ok(trace)
}

pub struct PreparedSha256 {
    message: Zeroizing<Vec<u8>>,
    chiplet: Sha256Chiplet<F>,
    program: CircuitProgram<F>,
    block: CpuSha256Block,
    pinned_id: [u8; 32],
    instance: ProgramInstance<F>,
    config: Config,
}

pub struct Sha256Proof(InnerProof<F>);

pub fn prepare_sha256(input_size: usize) -> PreparedSha256 {
    let (message, expected_digest) = utils::generate_sha256_input(input_size);
    let message = Zeroizing::new(message);

    let num_blocks = num_blocks_for(message.len());
    let num_rows = (num_blocks * ROWS_PER_BLOCK)
        .next_power_of_two()
        .max(1 << MIN_NUM_VARS);

    let chiplet =
        Sha256Chiplet::<F>::new(num_rows, num_blocks, ROUNDS_PER_ROW).expect("sha256 chiplet");

    let calls = sha256_calls(&message);
    let words = digest_words(&calls);

    assert_eq!(
        digest_bytes(&words).as_slice(),
        expected_digest.as_slice(),
        "hekate sha256 disagrees with the reference digest"
    );

    let built = build_program(&chiplet, message.len()).expect("sha256 circuit");
    let pinned_id = program_id(&built.program).expect("program id");
    let instance = ProgramInstance::new(num_rows, public_inputs(words));

    PreparedSha256 {
        message,
        chiplet,
        program: built.program,
        block: built.block,
        pinned_id,
        instance,
        config: Config::default(),
    }
}

/// Re-runs padding and compression rather than caching them in `PreparedSha256`:
/// witness generation belongs inside the timed region.
pub fn prove_sha256(prepared: &PreparedSha256) -> Sha256Proof {
    let calls = sha256_calls(&prepared.message);
    let trace =
        build_trace(&prepared.chiplet, &prepared.block, &calls).expect("sha256 trace construction");
    let witness = ProgramWitness::new(trace);

    let mut seed = Zeroizing::new([0u8; 32]);
    OsRng.try_fill_bytes(&mut *seed).expect("OS entropy");

    let proof = hekate_prover_sys::prove(
        TRANSCRIPT_LABEL,
        &prepared.program,
        &prepared.instance,
        &witness,
        &prepared.config,
        *seed,
        None,
    )
    .expect("hekate prover");

    Sha256Proof(proof)
}

pub fn verify_sha256(prepared: &PreparedSha256, proof: &Sha256Proof) {
    let mut transcript = Transcript::<H>::new(TRANSCRIPT_LABEL);
    let valid = HekateVerifier::<F, H>::verify(
        &prepared.pinned_id,
        &prepared.program,
        &prepared.instance,
        &proof.0,
        &mut transcript,
        &prepared.config,
    )
    .expect("hekate verifier");

    assert!(valid, "hekate proof rejected");
}

pub fn num_constraints_sha256(prepared: &PreparedSha256) -> usize {
    use hekate_program::Air;

    prepared.program.constraint_ast().roots.len()
}

pub fn preprocessing_size_sha256(prepared: &PreparedSha256) -> usize {
    hekate_sdk::serialize_bundle_header(&prepared.program, &prepared.instance, &prepared.config)
        .expect("bundle header serialization")
        .len()
}

pub fn proof_size_sha256(proof: &Sha256Proof) -> usize {
    hekate_sdk::serialize_proof_bytes(&proof.0).len()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED: [u8; 32] = [0x5A; 32];

    /// Takes a chain `prepare_sha256` cannot express.
    /// A refusal anywhere counts as rejection.
    fn accepts(calls: &[Sha256Call], msg_len: usize) -> bool {
        let num_blocks = num_blocks_for(msg_len);
        let num_rows = (num_blocks * ROWS_PER_BLOCK)
            .next_power_of_two()
            .max(1 << MIN_NUM_VARS);

        let chiplet =
            Sha256Chiplet::<F>::new(num_rows, num_blocks, ROUNDS_PER_ROW).expect("chiplet");
        let built = build_program(&chiplet, msg_len).expect("circuit");
        let pinned_id = program_id(&built.program).expect("program id");

        let instance = ProgramInstance::new(num_rows, public_inputs(digest_words(calls)));
        let trace = build_trace(&chiplet, &built.block, calls).expect("trace");
        let witness = ProgramWitness::new(trace);
        let config = Config::default();

        let proof = match hekate_prover_sys::prove(
            TRANSCRIPT_LABEL,
            &built.program,
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
            &built.program,
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

    fn chain_from(h_start: [u32; STATE_WORDS], blocks: &[[u32; BLOCK_WORDS]]) -> Vec<Sha256Call> {
        let mut h = h_start;
        let mut calls = Vec::new();

        for block in blocks {
            let call = Sha256Call {
                h_in: h,
                block: *block,
            };

            h = call.h_out();

            calls.push(call);
        }

        calls
    }

    #[test]
    fn reduced_sha256_roundtrip() {
        let prepared = prepare_sha256(128);

        let proof = prove_sha256(&prepared);
        verify_sha256(&prepared, &proof);

        assert!(num_constraints_sha256(&prepared) > 100);
        assert!(proof_size_sha256(&proof) > 0);
        assert!(preprocessing_size_sha256(&prepared) > 0);
    }

    #[test]
    fn multi_block_sha256_roundtrip() {
        let prepared = prepare_sha256(2048);
        assert_eq!(num_blocks_for(2048), 33);

        let proof = prove_sha256(&prepared);
        verify_sha256(&prepared, &proof);
    }

    #[test]
    fn padding_block_encodes_bit_length() {
        let words = padding_block(128);

        assert_eq!(words[0], 0x8000_0000);
        assert_eq!(words[BLOCK_WORDS - 1], 1024);
        assert!(words[1..BLOCK_WORDS - 2].iter().all(|&w| w == 0));
    }

    #[test]
    fn honest_chain_accepted() {
        let calls = sha256_calls(&utils::generate_sha256_input(128).0);

        assert_eq!(calls.len(), 3);
        assert!(accepts(&calls, 128));
    }

    #[test]
    fn nonstandard_iv_rejected() {
        let mut h = IV;
        h[0] ^= 1;

        let blocks = pad_message(&utils::generate_sha256_input(128).0);

        assert!(!accepts(&chain_from(h, &blocks), 128));
    }

    #[test]
    fn wrong_length_padding_rejected() {
        let blocks = pad_message(&utils::generate_sha256_input(128).0);
        let mut tampered = blocks.to_vec();
        let last = tampered.len() - 1;

        tampered[last][BLOCK_WORDS - 1] = 512;

        assert!(!accepts(&chain_from(IV, &tampered), 128));
    }

    #[test]
    fn tampered_digest_rejected() {
        let prepared = prepare_sha256(128);
        let proof = prove_sha256(&prepared);

        let mut words = digest_words(&sha256_calls(&prepared.message));
        words[0] ^= 1;

        let bad = ProgramInstance::new(prepared.chiplet.num_rows(), public_inputs(words));

        let mut transcript = Transcript::<H>::new(TRANSCRIPT_LABEL);
        let accepted = HekateVerifier::<F, H>::verify(
            &prepared.pinned_id,
            &prepared.program,
            &bad,
            &proof.0,
            &mut transcript,
            &prepared.config,
        )
        .unwrap_or(false);

        assert!(!accepted, "verifier accepted a tampered digest");
    }
}
