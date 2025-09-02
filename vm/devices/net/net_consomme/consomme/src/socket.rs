#![allow(missing_docs)]

use crate::Network;
use crate::TcpIo;
use crate::UdpIo;
use futures::AsyncRead as _;
use futures::AsyncWrite as _;
use pal_async::driver::Driver;
use pal_async::interest::InterestSlot;
use pal_async::interest::PollEvents;
use pal_async::socket::AsSockRef;
use pal_async::socket::PollReady as _;
use pal_async::socket::PolledSocket;
use socket2::Domain;
use socket2::Protocol;
use socket2::Socket;
use socket2::Type;
use std::io;
use std::net::Shutdown;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::pin::Pin;
use std::task::Poll;
use std::task::ready;

pub struct OsSockets<T> {
    driver: Option<T>,
    driver_seq: u64,
}

impl<T: Driver> OsSockets<T> {
    pub fn new(driver: T) -> Self {
        Self {
            driver: Some(driver),
            driver_seq: 0,
        }
    }

    pub fn without_driver() -> Self {
        Self {
            driver: None,
            driver_seq: 0,
        }
    }

    pub fn update_driver(&mut self, driver: T) {
        self.driver = Some(driver);
        self.driver_seq += 1;
    }

    fn polled_socket<S: AsSockRef>(&self, s: S) -> io::Result<PolledSocket<S>> {
        PolledSocket::new(self.driver.as_ref().ok_or(io::ErrorKind::Other)?, s)
    }

    fn socket<'a, S: AsSockRef>(
        &self,
        s: &'a mut OsSocket<S>,
    ) -> io::Result<&'a mut PolledSocket<S>> {
        if s.socket.is_none() {
            return Err(io::ErrorKind::NotConnected.into());
        }
        if s.driver_seq == self.driver_seq {
            return Ok(s.socket.as_mut().unwrap());
        }
        let socket = s.socket.take().unwrap().into_inner();
        let socket = self.polled_socket(socket)?;
        s.driver_seq = self.driver_seq;
        Ok(s.socket.insert(socket))
    }
}

impl<T: Driver> Network for OsSockets<T> {
    type Tcp = Self;
    type Udp = Self;

    fn tcp(&mut self) -> &mut Self::Tcp {
        self
    }

    fn udp(&mut self) -> &mut Self::Udp {
        self
    }
}

impl<T: Driver> TcpIo for OsSockets<T> {
    type Socket = OsSocket<Socket>;
    type Listener = OsSocket<Socket>;

    fn listen(&mut self, addr: SocketAddr) -> io::Result<Self::Listener> {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;

        let socket = self.polled_socket(socket)?;
        socket.get().bind(&addr.into())?;
        socket.listen(10)?;
        Ok(OsSocket {
            socket: Some(socket),
            driver_seq: self.driver_seq,
        })
    }

    fn connect(&mut self, addr: SocketAddr) -> io::Result<Self::Socket> {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;

        // On Windows the default behavior for non-existent loopback sockets is
        // to wait and try again. This is different than the Linux behavior of
        // immediately failing. Default to the Linux behavior.
        #[cfg(windows)]
        if addr.ip().is_loopback() {
            if let Err(err) = crate::windows::disable_connection_retries(&socket) {
                tracing::trace!(err, "Failed to disable loopback retries");
            }
        }

        let socket = self.polled_socket(socket)?;
        let Err(err) = socket.get().connect(&addr.into()) else {
            unreachable!("unexpected non-blocking synchronous connect success")
        };
        if !is_connect_incomplete_error(&err) {
            return Err(err);
        }
        Ok(OsSocket {
            socket: Some(socket),
            driver_seq: self.driver_seq,
        })
    }

    fn poll_accept(
        &mut self,
        cx: &mut std::task::Context<'_>,
        socket: &mut Self::Listener,
    ) -> Poll<io::Result<(Self::Socket, SocketAddr)>> {
        let socket = self.socket(socket)?;
        let (socket, addr) =
            ready!(socket.poll_accept(cx)).map_err(|_| take_socket_error(socket))?;
        let addr = addr.as_socket().ok_or(io::ErrorKind::Unsupported)?;
        let socket = self.polled_socket(socket)?;
        let socket = OsSocket {
            socket: Some(socket),
            driver_seq: self.driver_seq,
        };
        Poll::Ready(Ok((socket, addr)))
    }

    fn poll_connect(
        &mut self,
        cx: &mut std::task::Context<'_>,
        socket: &mut Self::Socket,
    ) -> Poll<io::Result<()>> {
        let socket = self.socket(socket)?;
        let r = ready!(socket.poll_ready(cx, PollEvents::OUT));
        if r.has_err() {
            return Err(take_socket_error(socket)).into();
        }
        Ok(()).into()
    }

    fn poll_close(
        &mut self,
        cx: &mut std::task::Context<'_>,
        socket: &mut Self::Socket,
    ) -> Poll<io::Result<()>> {
        let socket = self.socket(socket)?;
        let events = ready!(socket.poll_ready(cx, PollEvents::EMPTY));
        if events.has_err() {
            return Err(take_socket_error(socket)).into();
        }
        Ok(()).into()
    }

    fn poll_read_vectored(
        &mut self,
        cx: &mut std::task::Context<'_>,
        socket: &mut Self::Socket,
        bufs: &mut [io::IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(self.socket(socket)?).poll_read_vectored(cx, bufs)
    }

    fn poll_write_vectored(
        &mut self,
        cx: &mut std::task::Context<'_>,
        socket: &mut Self::Socket,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(self.socket(socket)?).poll_write_vectored(cx, bufs)
    }

    fn shutdown_writes(&mut self, socket: &mut Self::Socket) -> io::Result<()> {
        self.socket(socket)?.get().shutdown(Shutdown::Write)
    }
}

fn is_connect_incomplete_error(err: &io::Error) -> bool {
    if err.kind() == io::ErrorKind::WouldBlock {
        return true;
    }
    // This handles the remaining cases on Linux.
    #[cfg(unix)]
    if err.raw_os_error() == Some(libc::EINPROGRESS) {
        return true;
    }
    false
}

fn take_socket_error(socket: &PolledSocket<Socket>) -> io::Error {
    match socket.get().take_error() {
        Ok(Some(err)) => err,
        Ok(_) => io::Error::other("missing error"),
        Err(err) => err,
    }
}

impl<T: Driver> UdpIo for OsSockets<T> {
    type Socket = OsSocket<UdpSocket>;

    fn bind(&mut self, addr: SocketAddr) -> io::Result<Self::Socket> {
        let socket = UdpSocket::bind(addr)?;
        let socket = self.polled_socket(socket)?;
        Ok(OsSocket {
            socket: Some(socket),
            driver_seq: self.driver_seq,
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut std::task::Context<'_>,
        socket: &mut Self::Socket,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let socket = self.socket(socket)?;
        socket.poll_io(cx, InterestSlot::Read, PollEvents::IN, |socket| {
            socket.get().recv_from(buf)
        })
    }

    fn send_to(
        &mut self,
        socket: &mut Self::Socket,
        addr: SocketAddr,
        buf: &[u8],
    ) -> io::Result<()> {
        let socket = self.socket(socket)?;
        socket.get().send_to(buf, addr).map(drop)
    }
}

pub struct OsSocket<T> {
    socket: Option<PolledSocket<T>>,
    driver_seq: u64,
}
