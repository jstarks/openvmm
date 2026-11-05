// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resumable Direct TCP framing and a controllable loopback test server.

use crate::spec::{
    Command, HEADER_SIZE, Header,
    tcp::{DirectTcpHeader, SESSION_MESSAGE},
};
use crate::{Connection, Error, MAX_MESSAGE_SIZE, MAX_REQUESTS, provider::FileSystem};
use futures::{AsyncRead, AsyncWrite, FutureExt, Stream};
use inspect::Inspect;
use pal_async::{DefaultDriver, socket::PolledSocket};
use std::collections::{BTreeMap, VecDeque};
use std::future::{Future, poll_fn};
use std::net::{TcpListener, TcpStream};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use task_control::{AsyncRun, Cancelled, InspectTask, StopTask, TaskControl};
use unicycle::FuturesUnordered;
use zerocopy::{FromBytes, IntoBytes};

type Operation = Pin<Box<dyn Future<Output = Result<(), Error>> + Send>>;

struct Response {
    bytes: Vec<u8>,
    offset: usize,
}

/// Persistent state for one connection, usable with TaskControl or directly.
///
/// The task owns every accepted future. Stop and inspection only interrupt
/// polling, never the underlying operations or partially transmitted frames.
pub struct ConnectionTask<B: FileSystem, S> {
    connection: Connection<B>,
    stream: S,
    prefix: [u8; size_of::<DirectTcpHeader>()],
    prefix_len: usize,
    packet: Vec<u8>,
    packet_len: usize,
    requests: FuturesUnordered<Operation>,
    responses: VecDeque<Response>,
    response_sender: async_channel::Sender<Vec<u8>>,
    response_receiver: Pin<Box<async_channel::Receiver<Vec<u8>>>>,
    eof: bool,
    failure: Option<Error>,
    cleanup: Option<Pin<Box<dyn Future<Output = Result<(), Error>> + Send>>>,
    cleanup_complete: bool,
    result: Option<Result<(), Error>>,
}

impl<B: FileSystem, S> ConnectionTask<B, S> {
    /// Create a connection without spawning an executor or starting work.
    pub fn new(connection: Connection<B>, stream: S) -> Self {
        let (response_sender, response_receiver) = async_channel::bounded(MAX_REQUESTS);
        Self {
            connection,
            stream,
            prefix: [0; size_of::<DirectTcpHeader>()],
            prefix_len: 0,
            packet: Vec::new(),
            packet_len: 0,
            requests: FuturesUnordered::new(),
            responses: VecDeque::new(),
            response_sender,
            response_receiver: Box::pin(response_receiver),
            eof: false,
            failure: None,
            cleanup: None,
            cleanup_complete: false,
            result: None,
        }
    }

    /// Take the terminal result after the worker finishes.
    pub fn take_result(&mut self) -> Option<Result<(), Error>> {
        self.result.take()
    }

    fn disconnect(&mut self, error: Option<Error>) {
        self.eof = true;
        if self.failure.is_none() {
            self.failure = error;
        }
        self.connection.cancel_all();
        if self.failure.is_some() {
            self.responses.clear();
        }
    }

    fn response(&mut self, bytes: Vec<u8>) -> Result<(), Error> {
        let header = DirectTcpHeader::new(bytes.len()).ok_or(Error::InvalidFrame)?;
        let mut frame = Vec::with_capacity(bytes.len() + size_of::<DirectTcpHeader>());
        frame.extend_from_slice(header.as_bytes());
        frame.extend_from_slice(&bytes);
        self.responses.push_back(Response {
            bytes: frame,
            offset: 0,
        });
        Ok(())
    }

    /// Destructive shutdown does not wait for a client to read responses.
    pub async fn shutdown(&mut self) -> Result<(), Error> {
        self.disconnect(None);
        let mut error = self.failure.take();
        while !self.requests.is_empty() {
            let mut request = std::pin::pin!(self.requests.next().fuse());
            let mut response =
                std::pin::pin!(self.response_receiver.as_ref().get_ref().recv().fuse());
            futures::select! {
                result = request => {
                    if let Some(Err(failure)) = result {
                        if error.is_none() { error = Some(failure); }
                    }
                }
                _ = response => {}
            }
        }
        while self.response_receiver.as_ref().get_ref().try_recv().is_ok() {}
        self.responses.clear();
        if let Some(cleanup) = &mut self.cleanup {
            cleanup.await?;
            self.cleanup = None;
        } else {
            self.connection.shutdown().await?;
        }
        match error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl<B: FileSystem, S: AsyncRead + AsyncWrite + Unpin> ConnectionTask<B, S> {
    fn read_step(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        if self.prefix_len != self.prefix.len() {
            let count = std::task::ready!(
                Pin::new(&mut self.stream).poll_read(cx, &mut self.prefix[self.prefix_len..])
            )?;
            if count == 0 {
                if self.prefix_len != 0 {
                    return Poll::Ready(Err(unexpected_eof()));
                }
                self.disconnect(None);
                return Poll::Ready(Ok(()));
            }
            self.prefix_len += count;
            if self.prefix_len == self.prefix.len() {
                let header = DirectTcpHeader::read_from_bytes(&self.prefix)
                    .map_err(|_| Error::InvalidFrame)?;
                let length = header.length();
                if header.message_type != SESSION_MESSAGE
                    || !(HEADER_SIZE..=MAX_MESSAGE_SIZE).contains(&length)
                {
                    return Poll::Ready(Err(Error::InvalidFrame));
                }
                self.packet.resize(length, 0);
                self.packet_len = 0;
            }
            return Poll::Ready(Ok(()));
        }
        if self.packet_len != self.packet.len() {
            let count = std::task::ready!(
                Pin::new(&mut self.stream).poll_read(cx, &mut self.packet[self.packet_len..])
            )?;
            if count == 0 {
                return Poll::Ready(Err(unexpected_eof()));
            }
            self.packet_len += count;
            return Poll::Ready(Ok(()));
        }
        let header = Header::read_from_prefix(&self.packet)
            .map_err(|_| Error::InvalidHeader)?
            .0;
        if header.command() == Command::CANCEL {
            self.connection.cancel(&self.packet)?;
        } else {
            // Leave room to receive CANCEL even when every operation slot is used.
            if self.responses.len() >= MAX_REQUESTS {
                return Poll::Pending;
            }
            let request = if self.requests.len() >= MAX_REQUESTS {
                Err(Error::RequestLimit)
            } else {
                self.connection.request_ref(&self.packet)
            };
            match request {
                Ok(request) => {
                    self.requests.push(
                        request
                            .execute_with_interim(self.response_sender.clone())
                            .boxed(),
                    );
                }
                Err(Error::RequestLimit) => {
                    self.response(self.connection.busy_response(&self.packet)?)?;
                }
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
        self.packet.clear();
        self.prefix_len = 0;
        self.packet_len = 0;
        Poll::Ready(Ok(()))
    }

    fn write_step(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let Some(response) = self.responses.front_mut() else {
            return Poll::Pending;
        };
        if response.offset != response.bytes.len() {
            let count = std::task::ready!(
                Pin::new(&mut self.stream).poll_write(cx, &response.bytes[response.offset..])
            )?;
            if count == 0 {
                return Poll::Ready(Err(
                    std::io::Error::from(std::io::ErrorKind::WriteZero).into()
                ));
            }
            response.offset += count;
        } else {
            std::task::ready!(Pin::new(&mut self.stream).poll_flush(cx))?;
            self.responses.pop_front();
        }
        Poll::Ready(Ok(()))
    }

    fn poll_run(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        // A ready backend or stream must still return control to TaskControl.
        for _ in 0..16 {
            let mut progress = false;
            if self.failure.is_some() || self.responses.len() < MAX_REQUESTS {
                if let Poll::Ready(Some(response)) = self.response_receiver.as_mut().poll_next(cx) {
                    if self.failure.is_none() {
                        if let Err(error) = self.response(response) {
                            self.disconnect(Some(error));
                        }
                    }
                    progress = true;
                }
            }
            if let Poll::Ready(Some(result)) = Pin::new(&mut self.requests).poll_next(cx) {
                match result {
                    Ok(()) => {}
                    Err(error) => self.disconnect(Some(error)),
                }
                progress = true;
            }
            if self.failure.is_none() {
                if let Poll::Ready(result) = self.write_step(cx) {
                    if let Err(error) = result {
                        self.disconnect(Some(error));
                    }
                    progress = true;
                }
            }
            if !self.eof {
                if let Poll::Ready(result) = self.read_step(cx) {
                    if let Err(error) = result {
                        self.disconnect(Some(error));
                    }
                    progress = true;
                }
            }
            if self.eof && self.requests.is_empty() && !self.cleanup_complete {
                let cleanup = self.cleanup.get_or_insert_with(|| {
                    let connection = self.connection.clone();
                    async move { connection.shutdown().await }.boxed()
                });
                match cleanup.as_mut().poll(cx) {
                    Poll::Pending => {}
                    Poll::Ready(result) => {
                        self.cleanup = None;
                        self.cleanup_complete = true;
                        if let Err(error) = result {
                            self.disconnect(Some(error));
                        }
                        progress = true;
                    }
                }
            }
            if self.cleanup_complete
                && self.responses.is_empty()
                && self.response_receiver.as_ref().get_ref().is_empty()
            {
                return Poll::Ready(match self.failure.take() {
                    Some(error) => Err(error),
                    None => Ok(()),
                });
            }
            if !progress {
                return Poll::Pending;
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

fn unexpected_eof() -> Error {
    std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "partial SMB frame").into()
}

impl<B: FileSystem, S> Inspect for ConnectionTask<B, S> {
    fn inspect(&self, req: inspect::Request<'_>) {
        req.respond()
            .field("connection", &self.connection)
            .field("receive_prefix_bytes", self.prefix_len)
            .field("receive_body_bytes", self.packet_len)
            .field("receive_body_length", self.packet.len())
            .field("active_requests", self.requests.len())
            .field("queued_responses", self.responses.len())
            .field(
                "response_channel_frames",
                self.response_receiver.as_ref().get_ref().len(),
            )
            .field(
                "queued_response_bytes",
                self.responses
                    .iter()
                    .map(|r| r.bytes.len() - r.offset)
                    .sum::<usize>(),
            )
            .field("transmit_offset", self.responses.front().map(|r| r.offset))
            .field("request_limit", MAX_REQUESTS)
            .field("eof", self.eof)
            .field("failure", self.failure.as_ref().map(ToString::to_string))
            .field(
                "terminal_error",
                self.result
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(ToString::to_string),
            )
            .field("finished", self.result.is_some());
    }
}

impl<B: FileSystem, S: AsyncRead + AsyncWrite + Unpin + Send + 'static> AsyncRun<()>
    for ConnectionTask<B, S>
{
    async fn run(&mut self, stop: &mut StopTask<'_>, _: &mut ()) -> Result<(), Cancelled> {
        let result = stop.until_stopped(poll_fn(|cx| self.poll_run(cx))).await?;
        self.result = Some(result);
        Ok(())
    }
}

impl<B: FileSystem, S: AsyncRead + AsyncWrite + Unpin + Send + 'static> InspectTask<()>
    for ConnectionTask<B, S>
{
    fn inspect(&self, req: inspect::Request<'_>, _: Option<&()>) {
        Inspect::inspect(self, req);
    }
}

/// Serve a connection directly. Use ConnectionTask with TaskControl for pause.
pub async fn serve<B: FileSystem>(
    connection: &mut Connection<B>,
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
) -> Result<(), Error> {
    let mut task = ConnectionTask::new(connection.clone(), stream);
    poll_fn(|cx| task.poll_run(cx)).await
}

struct ServerWorker<B: FileSystem> {
    driver: DefaultDriver,
    listener: Option<PolledSocket<TcpListener>>,
    server: Arc<crate::Server<B>>,
    connections: BTreeMap<u64, ConnectionTask<B, PolledSocket<TcpStream>>>,
    next_connection: u64,
    failed_connections: u64,
    last_error: Option<String>,
}

impl<B: FileSystem> Inspect for ServerWorker<B> {
    fn inspect(&self, req: inspect::Request<'_>) {
        req.respond()
            .field("server", &self.server)
            .field("connections", inspect::iter_by_key(self.connections.iter()))
            .field("failed_connections", self.failed_connections)
            .field("last_error", &self.last_error);
    }
}

impl<B: FileSystem> ServerWorker<B> {
    fn poll_run(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if self.connections.len() < 64 {
            if let Some(listener) = &mut self.listener {
                match listener.poll_accept(cx) {
                    Poll::Pending => {}
                    Poll::Ready(Err(error)) => {
                        self.last_error = Some(error.to_string());
                        tracelimit::warn_ratelimited!(?error, "SMB test listener failed");
                        self.listener = None;
                    }
                    Poll::Ready(Ok((stream, _))) => {
                        match PolledSocket::new(&self.driver, stream) {
                            Ok(stream) => {
                                self.connections.insert(
                                    self.next_connection,
                                    ConnectionTask::new(self.server.connect(), stream),
                                );
                                self.next_connection += 1;
                            }
                            Err(error) => {
                                self.last_error = Some(error.to_string());
                                self.failed_connections += 1;
                                tracelimit::warn_ratelimited!(
                                    ?error,
                                    "SMB test socket setup failed"
                                );
                            }
                        }
                        cx.waker().wake_by_ref();
                    }
                }
            }
        }
        self.connections
            .retain(|_, connection| match connection.poll_run(cx) {
                Poll::Pending => true,
                Poll::Ready(result) => {
                    if let Err(error) = result {
                        self.failed_connections += 1;
                        self.last_error = Some(error.to_string());
                        tracelimit::warn_ratelimited!(?error, "SMB test connection failed");
                    }
                    false
                }
            });
        if self.listener.is_none() && self.connections.is_empty() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

impl<B: FileSystem> AsyncRun<()> for ServerWorker<B> {
    async fn run(&mut self, stop: &mut StopTask<'_>, _: &mut ()) -> Result<(), Cancelled> {
        stop.until_stopped(poll_fn(|cx| self.poll_run(cx))).await?;
        Ok(())
    }
}

impl<B: FileSystem> InspectTask<()> for ServerWorker<B> {
    fn inspect(&self, req: inspect::Request<'_>, _: Option<&()>) {
        Inspect::inspect(self, req);
    }
}

/// Startable/stoppable TCP test service. All connections share its executor.
pub struct Server<B: FileSystem> {
    task: TaskControl<ServerWorker<B>, ()>,
    closed: bool,
}

impl<B: FileSystem> Server<B> {
    /// Create a stopped loopback listener on the supplied executor.
    pub fn new(
        driver: DefaultDriver,
        listener: TcpListener,
        server: Arc<crate::Server<B>>,
    ) -> Result<Self, Error> {
        if !listener.local_addr()?.ip().is_loopback() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "SMB test listener must be loopback",
            )
            .into());
        }
        let listener = PolledSocket::new(&driver, listener)?;
        let mut task = TaskControl::new(ServerWorker {
            driver: driver.clone(),
            listener: Some(listener),
            server,
            connections: BTreeMap::new(),
            next_connection: 1,
            failed_connections: 0,
            last_error: None,
        });
        task.insert(driver, "smb-test-server", ());
        Ok(Self {
            task,
            closed: false,
        })
    }

    /// Resume the existing listener, connections, requests, and transport progress.
    pub fn start(&mut self) -> bool {
        !self.closed && self.task.start()
    }

    /// Pause without draining provider I/O or disconnecting clients.
    pub async fn stop(&mut self) -> bool {
        self.task.stop().await
    }

    /// Permanently stop admission and drain/cancel operations before closing opens.
    pub async fn shutdown(&mut self) -> Result<(), Error> {
        self.stop().await;
        self.closed = true;
        let worker = self.task.task_mut();
        worker.listener = None;
        let mut failure = None;
        let mut completed = Vec::new();
        for (id, connection) in &mut worker.connections {
            match connection.shutdown().await {
                Ok(()) => completed.push(*id),
                Err(error) => {
                    if failure.is_none() {
                        failure = Some(error);
                    }
                }
            }
        }
        for id in completed {
            worker.connections.remove(&id);
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl<B: FileSystem> Inspect for Server<B> {
    fn inspect(&self, req: inspect::Request<'_>) {
        req.respond()
            .field("running", self.task.is_running())
            .field("closed", self.closed)
            .field("worker", &self.task);
    }
}
