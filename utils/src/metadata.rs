const BYTE_INPUTS_REDUCED: [usize; 2] = [128, 256];
const BYTE_INPUTS_FULL: [usize; 5] = [128, 256, 512, 1024, 2048];

// Sizes where per-byte cost separates from fixed cost.
// Rows here are not comparable to another system's `full` row.
const BYTE_INPUTS_REAL_WORKLOAD: [usize; 3] = [32768, 262144, 1048576];

const FIELD_ELEMENT_INPUTS_REDUCED: [usize; 2] = [2, 8];
const FIELD_ELEMENT_INPUTS_FULL: [usize; 5] = [2, 4, 8, 12, 16];

pub fn selected_byte_inputs() -> Vec<usize> {
    if let Some(sizes) = override_from_env("BENCH_BYTE_INPUTS") {
        return sizes;
    }

    match std::env::var("BENCH_INPUT_PROFILE").ok().as_deref() {
        Some("reduced") => BYTE_INPUTS_REDUCED.to_vec(),
        Some("real-workload") => BYTE_INPUTS_REAL_WORKLOAD.to_vec(),
        Some("full") | None => BYTE_INPUTS_FULL.to_vec(),
        Some(other) => {
            panic!("BENCH_INPUT_PROFILE={other:?}: expected reduced, full or real-workload")
        }
    }
}

pub fn selected_field_element_inputs() -> Vec<usize> {
    if let Some(sizes) = override_from_env("BENCH_FIELD_ELEMENT_INPUTS") {
        return sizes;
    }

    match std::env::var("BENCH_INPUT_PROFILE").ok().as_deref() {
        Some("reduced") => FIELD_ELEMENT_INPUTS_REDUCED.to_vec(),
        Some("full") | None => FIELD_ELEMENT_INPUTS_FULL.to_vec(),
        Some("real-workload") => panic!(
            "BENCH_INPUT_PROFILE=real-workload sizes byte inputs only; \
             set BENCH_FIELD_ELEMENT_INPUTS to choose sizes explicitly"
        ),
        Some(other) => {
            panic!("BENCH_INPUT_PROFILE={other:?}: expected reduced, full or real-workload")
        }
    }
}

fn override_from_env(var: &str) -> Option<Vec<usize>> {
    let raw = std::env::var(var).ok()?;

    Some(
        raw.split(',')
            .map(|size| {
                size.trim().parse().unwrap_or_else(|_| {
                    panic!("{var}: expected comma-separated sizes, got {raw:?}")
                })
            })
            .collect(),
    )
}
