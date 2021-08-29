use criterion::{black_box, criterion_group, criterion_main, Criterion};

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut state = Default::default();
    let data = [[0u8; 64]];
    c.bench_function("sha256", |b| {
        b.iter(|| sha2_asm::compress256(black_box(&mut state), black_box(&data)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
