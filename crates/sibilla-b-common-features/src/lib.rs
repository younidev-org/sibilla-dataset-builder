use sha2::{Digest, Sha256};
use sibilla_b_schema::CommonFeatures;
const BLOCK_SIZE: usize = 4096;
/// Compute normalized byte frequencies, using zeros for empty input.
fn histogram(bytes: &[u8]) -> Vec<f64> {
    let mut counts = vec![0.0; 256];
    for &b in bytes {
        counts[b as usize] += 1.0;
    }
    if !bytes.is_empty() {
        for n in &mut counts {
            *n /= bytes.len() as f64;
        }
    }
    counts
}
/// Compute Shannon entropy in bits per byte from normalized frequencies.
fn entropy(hist: &[f64]) -> f64 {
    -hist
        .iter()
        .filter(|&&p| p > 0.0)
        .map(|p| p * p.log2())
        .sum::<f64>()
}
/// Compute SHA-256 and finite byte, histogram and block-entropy statistics.
pub fn extract(bytes: &[u8]) -> CommonFeatures {
    let hist = histogram(bytes);
    let blocks: Vec<_> = bytes
        .chunks(BLOCK_SIZE)
        .map(|b| entropy(&histogram(b)))
        .collect();
    let n = blocks.len().max(1) as f64;
    let mean = blocks.iter().sum::<f64>() / n;
    let ratio = |count: usize| count as f64 / bytes.len().max(1) as f64;
    CommonFeatures {
        sha256: format!("{:x}", Sha256::digest(bytes)),
        size_bytes: bytes.len() as u64,
        entropy_global: entropy(&hist),
        entropy_block_mean: mean,
        entropy_block_min: blocks.iter().copied().reduce(f64::min).unwrap_or(0.0),
        entropy_block_max: blocks.iter().copied().reduce(f64::max).unwrap_or(0.0),
        entropy_block_std: (blocks.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n).sqrt(),
        high_entropy_block_ratio: blocks.iter().filter(|&&x| x > 7.5).count() as f64 / n,
        zero_byte_ratio: ratio(bytes.iter().filter(|&&b| b == 0).count()),
        ascii_ratio: ratio(bytes.iter().filter(|b| b.is_ascii()).count()),
        printable_ratio: ratio(bytes.iter().filter(|&&b| (32..=126).contains(&b)).count()),
        byte_histogram: hist,
    }
}

#[cfg(test)]
mod tests {
    /// Verify empty/uniform byte statistics and the standard SHA-256 test vector.
    #[test]
    fn byte_statistics_handle_empty_and_uniform_input() {
        let empty = super::extract(&[]);
        assert_eq!(empty.size_bytes, 0);
        assert_eq!(empty.entropy_global, 0.0);
        assert_eq!(empty.byte_histogram.iter().sum::<f64>(), 0.0);
        let uniform = super::extract(&(0..=255).collect::<Vec<u8>>());
        assert_eq!(uniform.entropy_global, 8.0);
        assert_eq!(uniform.byte_histogram.iter().sum::<f64>(), 1.0);
        assert_eq!(
            super::extract(b"abc").sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
