//! Throughput benchmarks for `fast_md5` against `md-5` (RustCrypto) and
//! AWS-LC (via `aws-lc-sys` FFI — `aws-lc-rs` deliberately does not
//! expose MD5 in its public API). Run with `cargo bench`.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use md5::Digest as _;

/// Thin safe wrapper around the AWS-LC one-shot `MD5()` C entrypoint.
fn aws_lc_md5(data: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    // SAFETY: `MD5` reads `len` bytes from `data` and writes exactly
    // 16 bytes to `out`. Both buffers are valid for the duration of
    // the call.
    unsafe {
        aws_lc_sys::MD5(data.as_ptr(), data.len(), out.as_mut_ptr());
    }
    out
}

const SIZES: &[usize] = &[
    64, // single MD5 block
    256,
    1024,        // 1 KiB
    4 * 1024,    // 4 KiB
    16 * 1024,   // 16 KiB
    64 * 1024,   // 64 KiB
    1024 * 1024, // 1 MiB
];

fn make_input(n: usize) -> Vec<u8> {
    // Deterministic, non-trivial pattern so the compiler can't
    // const-fold and so each input is distinct.
    let mut v = vec![0u8; n];
    for (i, b) in v.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(0x9b).wrapping_add(0x37);
    }
    v
}

fn bench_md5(c: &mut Criterion) {
    // Cross-check: all three implementations must agree on a sample
    // input before we trust the timing numbers.
    let sample = make_input(4096);
    let a = fast_md5::digest(&sample);
    let mut h = md5::Md5::new();
    h.update(&sample);
    let b: [u8; 16] = h.finalize().into();
    let c_dig = aws_lc_md5(&sample);
    assert_eq!(a, b, "fast_md5 vs rustcrypto disagree");
    assert_eq!(a, c_dig, "fast_md5 vs aws-lc disagree");

    let mut group = c.benchmark_group("md5");
    for &size in SIZES {
        let input = make_input(size);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("fast_md5", size), &input, |b, data| {
            b.iter(|| {
                let d = fast_md5::digest(black_box(data.as_slice()));
                black_box(d)
            });
        });

        group.bench_with_input(BenchmarkId::new("rustcrypto", size), &input, |b, data| {
            b.iter(|| {
                let mut h = md5::Md5::new();
                h.update(black_box(data.as_slice()));
                let d: [u8; 16] = h.finalize().into();
                black_box(d)
            });
        });

        group.bench_with_input(BenchmarkId::new("aws_lc", size), &input, |b, data| {
            b.iter(|| {
                let d = aws_lc_md5(black_box(data.as_slice()));
                black_box(d)
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_md5);
criterion_main!(benches);
