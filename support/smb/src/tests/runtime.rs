// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite, FutureExt};
use pal_async::DefaultPool;
use std::collections::VecDeque;
use std::sync::atomic::AtomicUsize;
use task_control::TaskControl;
use test_with_tracing::test;

#[derive(Clone)]
struct GatedFs {
    memory: MemoryFs,
    started: async_channel::Sender<u64>,
    release: async_channel::Receiver<()>,
    cancellable: bool,
    writes: Arc<AtomicUsize>,
    closes: Arc<AtomicUsize>,
    flushes: Arc<AtomicUsize>,
    fail_close: Arc<AtomicBool>,
}

impl GatedFs {
    fn new(
        cancellable: bool,
    ) -> (
        Self,
        async_channel::Receiver<u64>,
        async_channel::Sender<()>,
    ) {
        let (started, starts) = async_channel::bounded(64);
        let (release, releases) = async_channel::bounded(64);
        (
            Self {
                memory: MemoryFs::new(1024, 16),
                started,
                release: releases,
                cancellable,
                writes: Arc::new(AtomicUsize::new(0)),
                closes: Arc::new(AtomicUsize::new(0)),
                flushes: Arc::new(AtomicUsize::new(0)),
                fail_close: Arc::new(AtomicBool::new(false)),
            },
            starts,
            release,
        )
    }
}

impl Inspect for GatedFs {
    fn inspect(&self, req: inspect::Request<'_>) {
        req.respond()
            .field("memory", &self.memory)
            .field("writes", self.writes.load(Ordering::Relaxed))
            .field("closes", self.closes.load(Ordering::Relaxed));
    }
}

#[async_trait]
impl FileSystem for GatedFs {
    type File = memory::MemoryFile;

    async fn open(
        &self,
        name: &str,
        options: OpenOptions,
        r: &RequestContext,
    ) -> Result<(Self::File, u32), Status> {
        self.memory.open(name, options, r).await
    }
    async fn close(&self, file: &Self::File, r: &RequestContext) -> Result<(), Status> {
        self.closes.fetch_add(1, Ordering::Relaxed);
        if self.fail_close.swap(false, Ordering::Relaxed) {
            return Err(Status::ACCESS_DENIED);
        }
        self.memory.close(file, r).await
    }
    async fn metadata(&self, file: &Self::File, r: &RequestContext) -> Result<Metadata, Status> {
        self.memory.metadata(file, r).await
    }
    async fn read(
        &self,
        file: &Self::File,
        offset: u64,
        length: usize,
        r: &RequestContext,
    ) -> Result<Vec<u8>, Status> {
        self.memory.read(file, offset, length, r).await
    }
    async fn write(
        &self,
        file: &Self::File,
        offset: u64,
        data: &[u8],
        r: &RequestContext,
    ) -> Result<usize, Status> {
        self.started.try_send(r.id()).unwrap();
        if self.cancellable {
            let mut release = std::pin::pin!(self.release.recv().fuse());
            let mut cancel = std::pin::pin!(r.cancelled().fuse());
            futures::select! {
                release = release => release.unwrap(),
                () = cancel => return Err(Status::CANCELLED),
            }
        } else {
            self.release.recv().await.unwrap();
        }
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.memory.write(file, offset, data, r).await
    }
    async fn flush(&self, file: &Self::File, r: &RequestContext) -> Result<(), Status> {
        self.flushes.fetch_add(1, Ordering::Relaxed);
        self.memory.flush(file, r).await
    }
    async fn list(&self, file: &Self::File, r: &RequestContext) -> Result<Vec<Metadata>, Status> {
        self.memory.list(file, r).await
    }
    async fn set_len(
        &self,
        file: &Self::File,
        length: u64,
        r: &RequestContext,
    ) -> Result<(), Status> {
        self.memory.set_len(file, length, r).await
    }
    async fn set_delete_on_close(
        &self,
        file: &Self::File,
        delete: bool,
        r: &RequestContext,
    ) -> Result<(), Status> {
        self.memory.set_delete_on_close(file, delete, r).await
    }
}

fn close_body(file: FileId) -> CloseRequest {
    let mut body = CloseRequest::new_zeroed();
    body.structure_size = 24.into();
    body.file_id = file;
    body
}

fn admitted<B: FileSystem>(client: &mut Client<B>, command: Command, body: &[u8]) -> Request<B> {
    let packet = request(command, body, client.session, client.tree, client.message);
    client.message += 1;
    client.connection.request(packet).unwrap()
}

#[test]
fn close_drains_uncancellable_writes_without_blocking_other_opens() {
    block_on(async {
        let (fs, starts, release) = GatedFs::new(false);
        let server = Server::new("memory", fs.clone()).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("target", 2, 0).await;
        let other = client.open("other", 2, 0).await;
        let first = admitted(
            &mut client,
            Command::WRITE,
            &Client::write_body(file, 0, b"one"),
        )
        .execute();
        let second = admitted(
            &mut client,
            Command::WRITE,
            &Client::write_body(file, 3, b"two"),
        )
        .execute();
        let mut first = std::pin::pin!(first);
        let mut second = std::pin::pin!(second);
        assert!(futures::poll!(&mut first).is_pending());
        assert!(futures::poll!(&mut second).is_pending());
        assert_ne!(starts.recv().await.unwrap(), starts.recv().await.unwrap());
        let mut body = close_body(file);
        body.flags = 1.into();
        let close = admitted(&mut client, Command::CLOSE, body.as_bytes()).execute();
        let mut close = std::pin::pin!(close);
        assert!(futures::poll!(&mut close).is_pending());
        assert_eq!(fs.closes.load(Ordering::Relaxed), 0);
        assert_eq!(
            response_status(&client.read(file, 0, 1).await),
            Status::FILE_CLOSED
        );
        assert_eq!(
            response_status(&client.read(other, 0, 0).await),
            Status::SUCCESS
        );
        release.send(()).await.unwrap();
        release.send(()).await.unwrap();
        let (first, second, close) = futures::join!(first, second, close);
        assert_eq!(response_status(&first.unwrap()), Status::SUCCESS);
        assert_eq!(response_status(&second.unwrap()), Status::SUCCESS);
        let close = close.unwrap();
        assert_eq!(response_status(&close), Status::SUCCESS);
        assert_eq!(u64::from_le_bytes(close[112..120].try_into().unwrap()), 6);
        assert_eq!(fs.writes.load(Ordering::Relaxed), 2);
        assert_eq!(fs.closes.load(Ordering::Relaxed), 1);
        let reopened = client.open("target", 1, 0).await;
        assert_eq!(&client.read(reopened, 0, 6).await[80..], b"onetwo");
    });
}

#[test]
fn close_cancels_pending_io_and_cancel_races_are_harmless() {
    block_on(async {
        let (fs, starts, _release) = GatedFs::new(true);
        let server = Server::new("memory", fs.clone()).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("target", 2, 0).await;
        let message = client.message;
        let write = admitted(
            &mut client,
            Command::WRITE,
            &Client::write_body(file, 0, b"data"),
        )
        .execute();
        let mut write = std::pin::pin!(write);
        assert!(futures::poll!(&mut write).is_pending());
        starts.recv().await.unwrap();
        let close = admitted(&mut client, Command::CLOSE, close_body(file).as_bytes()).execute();
        let (write, close) = futures::join!(write, close);
        assert_eq!(response_status(&write.unwrap()), Status::CANCELLED);
        assert_eq!(response_status(&close.unwrap()), Status::SUCCESS);
        let cancel = request(
            Command::CANCEL,
            SimpleBody {
                structure_size: 4.into(),
                reserved: 0.into(),
            }
            .as_bytes(),
            client.session,
            client.tree,
            message,
        );
        client.connection.cancel(&cancel).unwrap();
        assert_eq!(fs.writes.load(Ordering::Relaxed), 0);
        assert_eq!(fs.closes.load(Ordering::Relaxed), 1);
    });
}

#[test]
fn flush_orders_earlier_and_later_writes_on_the_same_open() {
    block_on(async {
        let (fs, starts, release) = GatedFs::new(false);
        let server = Server::new("memory", fs.clone()).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("target", 2, 0).await;
        let first = admitted(
            &mut client,
            Command::WRITE,
            &Client::write_body(file, 0, b"a"),
        )
        .execute();
        let flush = admitted(&mut client, Command::FLUSH, close_body(file).as_bytes()).execute();
        let second = admitted(
            &mut client,
            Command::WRITE,
            &Client::write_body(file, 1, b"b"),
        )
        .execute();
        let mut first = std::pin::pin!(first);
        let mut flush = std::pin::pin!(flush);
        let mut second = std::pin::pin!(second);
        assert!(futures::poll!(&mut first).is_pending());
        assert!(futures::poll!(&mut flush).is_pending());
        assert!(futures::poll!(&mut second).is_pending());
        starts.recv().await.unwrap();
        assert!(starts.try_recv().is_err());
        assert_eq!(fs.flushes.load(Ordering::Relaxed), 0);
        release.send(()).await.unwrap();
        assert_eq!(response_status(&first.await.unwrap()), Status::SUCCESS);
        assert_eq!(response_status(&flush.await.unwrap()), Status::SUCCESS);
        assert_eq!(fs.flushes.load(Ordering::Relaxed), 1);
        assert!(futures::poll!(&mut second).is_pending());
        starts.recv().await.unwrap();
        release.send(()).await.unwrap();
        assert_eq!(response_status(&second.await.unwrap()), Status::SUCCESS);
    });
}

#[derive(Default)]
struct StreamState {
    input: VecDeque<u8>,
    output: Vec<u8>,
    read: usize,
    write_limit: usize,
    repeat_echo: Option<(u64, u32, u64)>,
}

#[derive(Clone)]
struct TestStream {
    state: Arc<Mutex<StreamState>>,
    reader: Arc<futures::task::AtomicWaker>,
    writer: Arc<futures::task::AtomicWaker>,
    changed: Arc<Event>,
}

impl TestStream {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(StreamState::default())),
            reader: Arc::new(futures::task::AtomicWaker::new()),
            writer: Arc::new(futures::task::AtomicWaker::new()),
            changed: Arc::new(Event::new()),
        }
    }
    fn input(&self, bytes: &[u8]) {
        self.state.lock().input.extend(bytes);
        self.reader.wake();
    }
    fn writable(&self, length: usize) {
        self.state.lock().write_limit = length;
        self.writer.wake();
    }
    async fn until(&self, condition: impl Fn(&StreamState) -> bool) {
        loop {
            let listener = self.changed.listen();
            if condition(&self.state.lock()) {
                return;
            }
            listener.await;
        }
    }
}

impl AsyncRead for TestStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        self.reader.register(cx.waker());
        let mut state = self.state.lock();
        if state.input.is_empty() {
            if let Some((session, tree, message)) = state.repeat_echo {
                let body = SimpleBody {
                    structure_size: 4.into(),
                    reserved: 0.into(),
                };
                state.input.extend(frame(&request(
                    Command::ECHO,
                    body.as_bytes(),
                    session,
                    tree,
                    message,
                )));
                state.repeat_echo = Some((session, tree, message + 1));
            }
        }
        if state.input.is_empty() {
            return Poll::Pending;
        }
        let length = out.len().min(state.input.len());
        for byte in &mut out[..length] {
            *byte = state.input.pop_front().unwrap();
        }
        state.read += length;
        self.changed.notify(usize::MAX);
        Poll::Ready(Ok(length))
    }
}

impl AsyncWrite for TestStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.writer.register(cx.waker());
        let mut state = self.state.lock();
        let length = state
            .write_limit
            .saturating_sub(state.output.len())
            .min(bytes.len())
            .min(3);
        if length == 0 {
            return Poll::Pending;
        }
        state.output.extend_from_slice(&bytes[..length]);
        self.changed.notify(usize::MAX);
        Poll::Ready(Ok(length))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn frame(packet: &[u8]) -> Vec<u8> {
    let mut frame = (packet.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(packet);
    frame
}

async fn inspect_text(path: &str, object: impl inspect::InspectMut) -> String {
    let mut inspection = inspect::inspect(path, object);
    inspection.resolve().await;
    inspection.results().to_string()
}

#[test]
fn task_pause_and_inspection_preserve_partial_frames_pending_io_and_responses() {
    DefaultPool::run_with(async |driver| {
        let (fs, starts, release) = GatedFs::new(false);
        let server = Server::new("memory", fs.clone()).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("target", 2, 0).await;
        let packet = request(
            Command::WRITE,
            &Client::write_body(file, 0, b"data"),
            client.session,
            client.tree,
            client.message,
        );
        let write_frame = frame(&packet);
        let stream = TestStream::new();
        let mut task = TaskControl::new(tcp::ConnectionTask::new(
            client.connection.clone(),
            stream.clone(),
        ));
        task.insert(driver, "smb-runtime-test", ());
        stream.input(&write_frame[..2]);
        task.start();
        stream.until(|s| s.read == 2).await;
        task.stop().await;
        assert_eq!(inspect_text("receive_prefix_bytes", &task).await, "2");
        task.start();
        stream.input(&write_frame[2..11]);
        stream.until(|s| s.read == 11).await;
        task.stop().await;
        assert_eq!(inspect_text("receive_body_bytes", &task).await, "7");
        task.start();
        stream.input(&write_frame[11..]);
        starts.recv().await.unwrap();
        let close = frame(&request(
            Command::CLOSE,
            close_body(file).as_bytes(),
            client.session,
            client.tree,
            client.message + 1,
        ));
        stream.input(&close);
        stream
            .until(|s| s.read == write_frame.len() + close.len())
            .await;
        assert_eq!(inspect_text("active_requests", &task).await, "2");
        assert_eq!(
            inspect_text(
                &format!("connection/opens/{}/closing", file.volatile.get()),
                &task
            )
            .await,
            "true"
        );
        task.stop().await;
        assert_eq!(fs.writes.load(Ordering::Relaxed), 0);
        release.send(()).await.unwrap();
        assert_eq!(fs.writes.load(Ordering::Relaxed), 0);
        stream.writable(9);
        task.start();
        stream.until(|s| s.output.len() == 9).await;
        task.stop().await;
        assert_eq!(fs.writes.load(Ordering::Relaxed), 1);
        assert_eq!(inspect_text("transmit_offset", &task).await, "9");
        assert_eq!(inspect_text("queued_responses", &task).await, "2");
        stream.writable(usize::MAX);
        task.start();
        stream.until(|s| s.output.len() == 212).await;
        assert_eq!(inspect_text("queued_responses", &task).await, "0");
        task.stop().await;
        let bytes = stream.state.lock().output.clone();
        assert_eq!(bytes.len(), 212);
        assert_eq!(response_status(&bytes[4..]), Status::SUCCESS);
        assert_eq!(response_status(&bytes[88..]), Status::SUCCESS);
        assert_eq!(fs.writes.load(Ordering::Relaxed), 1);
        task.task_mut().shutdown().await.unwrap();
        assert_eq!(fs.closes.load(Ordering::Relaxed), 1);
    });
}

#[test]
fn cancel_is_processed_when_every_request_slot_is_occupied() {
    DefaultPool::run_with(async |driver| {
        let (fs, starts, _release) = GatedFs::new(true);
        let server = Server::new("memory", fs.clone()).unwrap();
        let mut client = Client::new(&server).await;
        let file = client.open("target", 2, 0).await;
        let stream = TestStream::new();
        stream.writable(usize::MAX);
        let mut task = TaskControl::new(tcp::ConnectionTask::new(
            client.connection.clone(),
            stream.clone(),
        ));
        task.insert(driver, "smb-full-test", ());
        let first_message = client.message;
        for _ in 0..MAX_REQUESTS {
            stream.input(&frame(&request(
                Command::WRITE,
                &Client::write_body(file, 0, b"x"),
                client.session,
                client.tree,
                client.message,
            )));
            client.message += 1;
        }

        task.start();
        for _ in 0..MAX_REQUESTS {
            starts.recv().await.unwrap();
        }
        assert_eq!(
            inspect_text("active_requests", &task).await,
            MAX_REQUESTS.to_string()
        );
        let cancel = request(
            Command::CANCEL,
            SimpleBody {
                structure_size: 4.into(),
                reserved: 0.into(),
            }
            .as_bytes(),
            client.session,
            client.tree,
            first_message,
        );
        stream.input(&frame(&cancel));
        stream.until(|s| s.output.len() >= 4).await;
        task.stop().await;
        assert_eq!(fs.writes.load(Ordering::Relaxed), 0);
        task.task_mut().shutdown().await.unwrap();
        assert_eq!(fs.closes.load(Ordering::Relaxed), 1);
    });
}

#[test]
fn continuously_ready_traffic_still_allows_inspection_and_pause() {
    DefaultPool::run_with(async |driver| {
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let client = Client::new(&server).await;
        let stream = TestStream::new();
        stream.writable(usize::MAX);
        stream.state.lock().repeat_echo = Some((client.session, client.tree, client.message));
        let mut task = TaskControl::new(tcp::ConnectionTask::new(
            client.connection.clone(),
            stream.clone(),
        ));
        task.insert(driver, "smb-ready-test", ());
        let (finished, done) = async_channel::bounded(1);
        let control = std::thread::spawn(move || {
            block_on(async {
                task.start();
                stream.until(|s| s.read >= 4).await;
                assert_eq!(
                    inspect_text("request_limit", &task).await,
                    MAX_REQUESTS.to_string()
                );
                assert!(task.stop().await);
                task.task_mut().shutdown().await.unwrap();
                finished.send(()).await.unwrap();
            })
        });
        done.recv().await.unwrap();
        control.join().unwrap();
    });
}

#[test]
fn tcp_service_pause_preserves_existing_connections() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    DefaultPool::run_with(async |driver| {
        use futures::{AsyncReadExt, AsyncWriteExt};
        let server = Server::new("memory", MemoryFs::new(1024, 16)).unwrap();
        let mut client = pal_async::socket::PolledSocket::new(&driver, client).unwrap();
        let mut service = tcp::Server::new(driver, listener, server).unwrap();
        assert_eq!(inspect_text("running", &service).await, "false");
        assert!(service.start());
        client
            .write_all(&frame(&request(
                Command::NEGOTIATE,
                &negotiate_body(),
                0,
                0,
                0,
            )))
            .await
            .unwrap();
        let mut prefix = [0; 4];
        client.read_exact(&mut prefix).await.unwrap();
        let mut response = vec![0; u32::from_be_bytes(prefix) as usize];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response_status(&response), Status::SUCCESS);
        assert!(service.stop().await);
        assert_eq!(inspect_text("running", &service).await, "false");
        let echo = SimpleBody {
            structure_size: 4.into(),
            reserved: 0.into(),
        };
        client
            .write_all(&frame(&request(Command::ECHO, echo.as_bytes(), 0, 0, 1)))
            .await
            .unwrap();
        assert!(service.start());
        client.read_exact(&mut prefix).await.unwrap();
        response.resize(u32::from_be_bytes(prefix) as usize, 0);
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response_status(&response), Status::SUCCESS);
        service.shutdown().await.unwrap();
        assert!(!service.start());
    });
}

#[test]
fn shutdown_closes_other_opens_and_retains_failed_close_for_retry() {
    block_on(async {
        let (fs, _starts, _release) = GatedFs::new(false);
        let server = Server::new("memory", fs.clone()).unwrap();
        let mut client = Client::new(&server).await;
        client.open("first", 2, 0).await;
        client.open("second", 2, 0).await;
        fs.fail_close.store(true, Ordering::Relaxed);
        assert!(matches!(
            client.connection.shutdown().await,
            Err(Error::Backend(Status::ACCESS_DENIED))
        ));
        assert_eq!(inspect_text("opens", &fs.memory).await, "1");
        client.connection.shutdown().await.unwrap();
        assert_eq!(inspect_text("opens", &fs.memory).await, "0");
    });
}
