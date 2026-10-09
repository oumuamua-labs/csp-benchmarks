use hekate::{
    num_constraints_sha256, prepare_sha256, preprocessing_size_sha256, proof_size_sha256,
    prove_sha256, verify_sha256, HEKATE_BENCH_PROPERTIES,
};
use utils::harness::ProvingSystem;

utils::define_benchmark_harness!(
    BenchTarget::Sha256,
    ProvingSystem::Hekate,
    None,
    "sha256_mem_hekate",
    HEKATE_BENCH_PROPERTIES,
    |_| Some(utils::bench::Acceleration::Precompile),
    prepare_sha256,
    num_constraints_sha256,
    prove_sha256,
    verify_sha256,
    preprocessing_size_sha256,
    proof_size_sha256
);
