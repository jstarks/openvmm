// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Performance tests.

// UNSAFETY: testing unsafe interfaces
#![expect(unsafe_code)]
#![expect(missing_docs)]

use sparse_mmap::initialize_try_copy;
use std::hint::black_box;

criterion::criterion_main!(benches);

criterion::criterion_group!(benches, bench_access);

fn bench_access(c: &mut criterion::Criterion) {
    initialize_try_copy();
    c.bench_function("try-read-8", |b| {
        // SAFETY: passing a valid src.
        b.iter(|| unsafe {
            let n = 0u8;
            sparse_mmap::try_read_volatile(&n).unwrap();
        });
    })
    .bench_function("read-8", |b| {
        // SAFETY: passing a valid src.
        b.iter(|| unsafe {
            let n = 0u8;
            std::ptr::read_volatile(black_box(&n));
        })
    })
    .bench_function("try-copy-1", |b| try_copy_n::<1>(b))
    .bench_function("try-copy-32", |b| try_copy_n::<32>(b))
    .bench_function("try-copy-256", |b| try_copy_n::<256>(b))
    .bench_function("try-copy-4096", |b| try_copy_n::<4096>(b))
    .bench_function("try-set-1", |b| try_set_n::<1>(b))
    .bench_function("try-set-32", |b| try_set_n::<32>(b))
    .bench_function("try-set-256", |b| try_set_n::<256>(b))
    .bench_function("try-set-4096", |b| try_set_n::<4096>(b));
}

fn try_copy_n<const N: usize>(b: &mut criterion::Bencher<'_>) {
    let src = [0u8; N];
    let mut dest = [0u8; N];
    // SAFETY: passing valid src and dest.
    b.iter(|| unsafe {
        sparse_mmap::try_copy(black_box(src.as_ptr()), black_box(dest.as_mut_ptr()), N).unwrap();
    })
}

fn try_set_n<const N: usize>(b: &mut criterion::Bencher<'_>) {
    let mut dest = [0u8; N];
    // SAFETY: passing valid dest.
    b.iter(|| unsafe {
        sparse_mmap::try_write_bytes(black_box(dest.as_mut_ptr()), 0u8, N).unwrap();
    })
}
