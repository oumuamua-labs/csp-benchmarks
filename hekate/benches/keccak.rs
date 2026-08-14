use hekate::{
    num_constraints_keccak, prepare_keccak, preprocessing_size_keccak, proof_size_keccak,
    prove_keccak, verify_keccak, HEKATE_BENCH_PROPERTIES,
};
use utils::harness::ProvingSystem;

utils::define_benchmark_harness!(
    BenchTarget::Keccak,
    ProvingSystem::Hekate,
    None,
    "keccak_mem_hekate",
    HEKATE_BENCH_PROPERTIES,
    |_| Some(utils::bench::Acceleration::Precompile),
    prepare_keccak,
    num_constraints_keccak,
    prove_keccak,
    verify_keccak,
    preprocessing_size_keccak,
    proof_size_keccak
);
