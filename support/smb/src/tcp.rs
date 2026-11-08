// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A controllable loopback TCP test server for the shared SMB runtime.

pub use crate::runtime::{ConnectionTask, serve};
use crate::{Error, provider::FileSystem};
use inspect::Inspect;
use pal_async::{DefaultDriver, socket::PolledSocket};
use std::collections::BTreeMap;
use std::future::poll_fn;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::task::{Context, Poll};
use task_control::{AsyncRun, Cancelled, InspectTask, StopTask, TaskControl};

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
                                    ConnectionTask::new_with_driver(
                                        self.server.connect(),
                                        stream,
                                        self.driver.clone(),
                                    ),
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
