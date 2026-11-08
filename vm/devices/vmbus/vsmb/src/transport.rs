// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! vSMB stream negotiation precedes ordinary length-prefixed SMB messages.

use futures::{AsyncRead, AsyncWrite};
use inspect::Inspect;
use std::io;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
};
use std::task::{Context, Poll};

const VERSION_TYPE: u8 = 1;
const VERSION: u32 = 1;
pub(crate) const RDMA_V2: u32 = 1;

#[derive(Inspect)]
enum Phase {
    Header,
    Version,
    Reply,
    Active,
}

/// Retains partial negotiation across VM pause and output backpressure.
#[derive(Inspect)]
pub(crate) struct Transport<S> {
    #[inspect(skip)]
    stream: S,
    phase: Phase,
    #[inspect(skip)]
    request: [u8; 12],
    received: usize,
    #[inspect(skip)]
    reply: [u8; 12],
    sent: usize,
    version: u32,
    capabilities: u32,
    #[inspect(skip)]
    negotiated: Arc<AtomicU32>,
}

impl<S> Transport<S> {
    pub(crate) fn new(stream: S) -> Self {
        Self {
            stream,
            phase: Phase::Header,
            request: [0; 12],
            received: 0,
            reply: [0; 12],
            sent: 0,
            version: u32::MAX,
            capabilities: 0,
            negotiated: Arc::new(AtomicU32::new(0)),
        }
    }

    pub(crate) fn negotiated_capabilities(&self) -> Arc<AtomicU32> {
        self.negotiated.clone()
    }
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid vSMB transport negotiation",
    )
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Transport<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        for _ in 0..16 {
            match this.phase {
                Phase::Active => return Pin::new(&mut this.stream).poll_read(cx, output),
                Phase::Header | Phase::Version => {
                    let end = if matches!(this.phase, Phase::Header) {
                        4
                    } else {
                        12
                    };
                    let n = std::task::ready!(
                        Pin::new(&mut this.stream)
                            .poll_read(cx, &mut this.request[this.received..end])
                    )?;
                    if n == 0 {
                        return if this.received == 0 {
                            Poll::Ready(Ok(0))
                        } else {
                            Poll::Ready(Err(invalid()))
                        };
                    }
                    this.received += n;
                    if this.received != end {
                        continue;
                    }
                    if matches!(this.phase, Phase::Header) {
                        if this.request[..4] != [VERSION_TYPE, 0, 0, 8] {
                            return Poll::Ready(Err(invalid()));
                        }
                        this.phase = Phase::Version;
                    } else {
                        let requested =
                            u32::from_le_bytes(this.request[4..8].try_into().expect("fixed field"));
                        this.version = if requested == VERSION {
                            VERSION
                        } else {
                            u32::MAX
                        };
                        let requested_caps = u32::from_le_bytes(
                            this.request[8..12].try_into().expect("fixed field"),
                        );
                        this.capabilities = if this.version == VERSION {
                            requested_caps & RDMA_V2
                        } else {
                            0
                        };
                        this.reply[..4].copy_from_slice(&[VERSION_TYPE, 0, 0, 8]);
                        this.reply[4..8].copy_from_slice(&this.version.to_le_bytes());
                        this.reply[8..12].copy_from_slice(&this.capabilities.to_le_bytes());
                        this.phase = Phase::Reply;
                    }
                }
                Phase::Reply => {
                    if this.sent != this.reply.len() {
                        let n = std::task::ready!(
                            Pin::new(&mut this.stream).poll_write(cx, &this.reply[this.sent..])
                        )?;
                        if n == 0 {
                            return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                        }
                        this.sent += n;
                    } else {
                        std::task::ready!(Pin::new(&mut this.stream).poll_flush(cx))?;
                        if this.version == VERSION {
                            this.negotiated.store(this.capabilities, Ordering::Release);
                            this.phase = Phase::Active;
                        } else {
                            this.phase = Phase::Header;
                            this.received = 0;
                            this.sent = 0;
                        }
                    }
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Transport<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !matches!(this.phase, Phase::Active) {
            return Poll::Ready(Err(invalid()));
        }
        Pin::new(&mut this.stream).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_close(cx)
    }
}
