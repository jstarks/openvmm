// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Owned compound execution from MS-SMB2 §§3.3.5.2.7 and 3.3.4.1.3.

use super::*;
use std::ops::Range;

/// Admitted commands, retained together until their ordered reply is complete.
pub struct Request<B: FileSystem> {
    pub(super) commands: Vec<CommandRequest<B>>,
    pub(super) related: bool,
}

pub(super) fn ranges(packet: &[u8]) -> Result<Vec<Range<usize>>, Error> {
    let mut ranges = Vec::new();
    let mut start = 0;
    loop {
        let bytes = packet.get(start..).ok_or(Error::InvalidCompound)?;
        let header = Header::read_from_prefix(bytes)
            .map_err(|_| Error::InvalidHeader)?
            .0;
        if header.protocol != SIGNATURE
            || header.structure_size.get() as usize != HEADER_SIZE
            || header.flags.server_to_redir()
            || !header.command().is_valid()
            || header.command() == Command::CANCEL
        {
            return Err(Error::InvalidHeader);
        }
        if ranges.len() == MAX_REQUESTS {
            return Err(Error::InvalidCompound);
        }
        let next = header.next_command.get() as usize;
        if next == 0 {
            ranges.push(start..packet.len());
            break;
        }
        let end = start.checked_add(next).ok_or(Error::InvalidCompound)?;
        if next < HEADER_SIZE
            || !next.is_multiple_of(COMPOUND_ALIGNMENT)
            || packet
                .len()
                .checked_sub(end)
                .is_none_or(|remaining| remaining < HEADER_SIZE)
        {
            return Err(Error::InvalidCompound);
        }
        ranges.push(start..end);
        start = end;
    }
    Ok(ranges)
}

pub(super) fn charge(packet: &[u8], header: &Header) -> Result<u32, Status> {
    let payload = match header.command() {
        Command::READ => read_body::<ReadRequest>(packet)?.length.get(),
        Command::WRITE => read_body::<WriteRequest>(packet)?.length.get(),
        Command::QUERY_DIRECTORY => read_body::<QueryDirectoryRequest>(packet)?
            .output_buffer_length
            .get(),
        Command::QUERY_INFO => read_body::<QueryInfoRequest>(packet)?
            .output_buffer_length
            .get(),
        Command::CHANGE_NOTIFY => read_body::<ChangeNotifyRequest>(packet)?
            .output_buffer_length
            .get(),
        _ => 0,
    };
    let required = payload.saturating_sub(1) / CREDIT_PAYLOAD_SIZE + 1;
    let declared = u32::from(header.credit_charge.get().max(1));
    if declared < required {
        return Err(Status::INVALID_PARAMETER);
    }
    Ok(declared)
}

pub(super) fn request_file_id(
    packet: &mut [u8],
    replacement: Option<FileId>,
) -> Result<Option<FileId>, Status> {
    let header = Header::read_from_prefix(packet)
        .map_err(|_| Status::INVALID_PARAMETER)?
        .0;
    let bytes = packet
        .get_mut(HEADER_SIZE..)
        .ok_or(Status::INVALID_PARAMETER)?;
    macro_rules! file {
        ($ty:ty) => {{
            let (request, _) =
                <$ty>::mut_from_prefix(bytes).map_err(|_| Status::INVALID_PARAMETER)?;
            if request.structure_size() != <$ty>::STRUCTURE_SIZE {
                return Err(Status::INVALID_PARAMETER);
            }
            let id = request.file_id;
            if let Some(replacement) = replacement {
                request.file_id = replacement;
            }
            Ok(Some(id))
        }};
    }
    match header.command() {
        Command::READ => file!(ReadRequest),
        Command::WRITE => file!(WriteRequest),
        Command::CLOSE => file!(CloseRequest),
        Command::FLUSH => file!(FlushRequest),
        Command::QUERY_INFO => file!(QueryInfoRequest),
        Command::SET_INFO => file!(SetInfoRequest),
        Command::QUERY_DIRECTORY => file!(QueryDirectoryRequest),
        Command::LOCK => file!(LockRequest),
        Command::IOCTL => file!(IoctlRequest),
        Command::CHANGE_NOTIFY => file!(ChangeNotifyRequest),
        _ => Ok(None),
    }
}

struct Previous {
    session: Option<u64>,
    tree: Option<u32>,
    file: Option<FileId>,
    provides_file: bool,
    status: Status,
    poisoned: Option<Status>,
}

pub(super) fn append_response(
    output: &mut Vec<u8>,
    last_response: &mut Option<usize>,
    mut response: Vec<u8>,
    related: bool,
) -> Result<(), Error> {
    Header::mut_from_prefix(&mut response[..])
        .map_err(|_| Error::InvalidHeader)?
        .0
        .flags
        .set_related_operations(related);
    if let Some(start) = *last_response {
        let next = output.len() - start;
        Header::mut_from_prefix(&mut output[start..])
            .map_err(|_| Error::InvalidHeader)?
            .0
            .next_command = (next as u32).into();
    }
    *last_response = Some(output.len());
    output.extend_from_slice(&response);
    output.resize(
        align_up(output.len(), COMPOUND_ALIGNMENT).map_err(Error::Backend)?,
        0,
    );
    Ok(())
}

struct InheritanceFailure {
    status: Status,
    stops_chain: bool,
}

impl InheritanceFailure {
    fn missing(status: Status) -> Self {
        Self {
            status,
            stops_chain: true,
        }
    }

    fn operation(status: Status) -> Self {
        Self {
            status,
            stops_chain: false,
        }
    }
}

impl Previous {
    fn inherit<B: FileSystem>(
        &self,
        request: &mut CommandRequest<B>,
    ) -> Result<(), InheritanceFailure> {
        if let Some(status) = self.poisoned {
            return Err(InheritanceFailure::missing(status));
        }
        let command = request.header.command();
        request.header.session_id = self.session.unwrap_or(0).into();
        request.header.tree_id = self.tree.unwrap_or(0).into();
        if !matches!(
            command,
            Command::NEGOTIATE | Command::SESSION_SETUP | Command::ECHO
        ) {
            self.session
                .ok_or_else(|| InheritanceFailure::missing(Status::INVALID_PARAMETER))?;
            if !matches!(command, Command::TREE_CONNECT | Command::LOGOFF) {
                self.tree
                    .ok_or_else(|| InheritanceFailure::missing(Status::INVALID_PARAMETER))?;
            }
        }
        if request_file_id(&mut request.packet, None)
            .map_err(InheritanceFailure::operation)?
            .is_some()
        {
            if self.provides_file && self.status.is_error() {
                return Err(InheritanceFailure::operation(self.status));
            }
            let file = self
                .file
                .ok_or_else(|| InheritanceFailure::missing(Status::INVALID_HANDLE))?;
            request_file_id(&mut request.packet, Some(file))
                .map_err(InheritanceFailure::operation)?;
        }
        Ok(())
    }
}

impl<B: FileSystem> Request<B> {
    /// Return final replies only. Retain this future across pause.
    ///
    /// Discarding accepted work disconnects the connection; it does not cancel backend I/O.
    pub async fn execute(self) -> Result<Vec<u8>, Error> {
        self.execute_inner(None).await
    }

    /// Deliver interim/early frames while retaining accepted work to completion.
    ///
    /// The caller must receive concurrently and retain this future across pause.
    /// If the receiver closes, the connection is canceled and executing backend
    /// work is still drained before returning the delivery error.
    pub async fn execute_with_interim(
        self,
        sender: async_channel::Sender<Vec<u8>>,
    ) -> Result<(), Error> {
        let connection = self
            .commands
            .first()
            .map(|request| request.connection.clone());
        let response = self.execute_inner(Some(&sender)).await?;
        if !response.is_empty() {
            if sender.send(response).await.is_err() {
                if let Some(connection) = connection {
                    connection.cancel_all();
                }
                return Err(Error::ResponseChannelClosed);
            }
        }
        Ok(())
    }

    async fn execute_inner(
        self,
        sender: Option<&async_channel::Sender<Vec<u8>>>,
    ) -> Result<Vec<u8>, Error> {
        use futures::FutureExt;
        use std::task::Poll;
        let compounded = self.commands.len() > 1;
        let mut output = Vec::new();
        let mut last_response = None;
        let mut previous: Option<Previous> = None;
        let mut commands = self.commands.into_iter();
        let mut index = 0;
        let mut delivery_failed = false;
        while let Some(mut request) = commands.next() {
            let command = request.header.command();
            let mut poisoned = None;
            if self.related && index != 0 {
                if let Some(previous) = &previous {
                    if let Err(failure) = previous.inherit(&mut request) {
                        if failure.stops_chain {
                            poisoned = Some(failure.status);
                        }
                        request.error = request.error.or(Some(failure.status));
                    }
                }
            }
            let file = request_file_id(&mut request.packet, None).ok().flatten();
            let connection = request.connection.clone();
            let header = request.header;
            let mut future = std::pin::pin!(request.execute().fuse());
            let first = std::future::poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx))).await;
            let mut protocol_error = None;
            let completion = match first {
                Poll::Ready(completion) => completion?,
                Poll::Pending => {
                    if let Some(sender) = sender {
                        if !output.is_empty() {
                            if sender.send(std::mem::take(&mut output)).await.is_err() {
                                delivery_failed = true;
                                connection.cancel_all();
                            }
                            last_response = None;
                        }
                        let session = connection
                            .state
                            .lock()
                            .requests
                            .get(&header.message_id.get())
                            .map_or(header.session_id.get(), |info| info.response_session);
                        let pending = std::iter::once(&header).chain(
                            commands
                                .as_slice()
                                .iter()
                                .filter(|_| self.related)
                                .map(|request| &request.header)
                                .filter(|header| {
                                    matches!(
                                        header.command(),
                                        Command::READ
                                            | Command::WRITE
                                            | Command::CLOSE
                                            | Command::FLUSH
                                            | Command::QUERY_INFO
                                            | Command::SET_INFO
                                            | Command::QUERY_DIRECTORY
                                            | Command::LOCK
                                            | Command::IOCTL
                                            | Command::CHANGE_NOTIFY
                                    )
                                }),
                        );
                        for header in pending {
                            match connection.pending_response(header, session) {
                                Ok(Some(response)) => {
                                    if sender.send(response).await.is_err() {
                                        delivery_failed = true;
                                        connection.cancel_all();
                                    }
                                }
                                Ok(None) => {}
                                Err(error) => {
                                    protocol_error = Some(error);
                                    connection.cancel_all();
                                    break;
                                }
                            }
                        }
                    }
                    // Delivery can fail after the interim while backend work is still pending.
                    if let Some(sender) = sender {
                        let mut closed = std::pin::pin!(sender.closed().fuse());
                        futures::select! {
                            completion = future => completion?,
                            () = closed => {
                                delivery_failed = true;
                                connection.cancel_all();
                                future.await?
                            }
                        }
                    } else {
                        future.await?
                    }
                }
            };
            if let Some(error) = protocol_error {
                return Err(error);
            }
            let response_header = completion.header;
            let response = completion.bytes;
            let status = response_header.status();
            let generated_file = if command == Command::CREATE && status == Status::SUCCESS {
                Some(
                    read_body::<CreateResponse>(&response)
                        .map_err(Error::Backend)?
                        .file_id,
                )
            } else {
                file
            };
            previous = Some(Previous {
                session: if command == Command::NEGOTIATE
                    || (command == Command::SESSION_SETUP && status != Status::SUCCESS)
                {
                    None
                } else {
                    Some(response_header.session_id.get()).filter(|id| *id != 0)
                },
                tree: if matches!(command, Command::NEGOTIATE | Command::SESSION_SETUP)
                    || (command == Command::TREE_CONNECT && status != Status::SUCCESS)
                {
                    None
                } else {
                    Some(response_header.tree_id.get()).filter(|id| *id != 0)
                },
                file: generated_file,
                provides_file: command == Command::CREATE || file.is_some(),
                status,
                poisoned: poisoned
                    .or_else(|| previous.as_ref().and_then(|previous| previous.poisoned)),
            });
            if completion.async_id.is_some() {
                if let Some(sender) = sender {
                    if sender.send(response).await.is_err() {
                        delivery_failed = true;
                        connection.cancel_all();
                    }
                }
            } else if compounded {
                append_response(
                    &mut output,
                    &mut last_response,
                    response,
                    self.related && index != 0,
                )?;
            } else {
                output = response;
            }
            index += 1;
        }
        if delivery_failed {
            Err(Error::ResponseChannelClosed)
        } else {
            Ok(output)
        }
    }
}
