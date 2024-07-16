criterion::criterion_main!(benches);

criterion::criterion_group!(benches, bench_channel);

fn bench_channel(c: &mut criterion::Criterion) {
    c.bench_function("channel_init_and_drop", |b| {
        b.iter(|| {
            mesh_channel::channel::<()>();
        })
    })
    .bench_function("oneshot_init_and_drop", |b| {
        b.iter(|| {
            mesh_channel::oneshot::<()>();
        })
    })
    .bench_function("mpsc_init_and_drop", |b| {
        b.iter(|| {
            mesh_channel::mpsc_channel::<()>();
        })
    })
    .bench_function("send_recv_u32", |b| {
        let (send, mut recv) = mesh_channel::channel::<u32>();
        b.iter(|| {
            send.send(5);
            recv.try_recv().unwrap();
        })
    });
}
