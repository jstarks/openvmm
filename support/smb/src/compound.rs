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
    /// Run accepted work. Retain this future across pause; dropping is not cancellation.
    pub async fn execute(self) -> Result<Vec<u8>, Error> {
        let compounded = self.commands.len() > 1;
        let mut output = Vec::new();
        let mut last_response = None;
        let mut previous: Option<Previous> = None;
        for (index, mut request) in self.commands.into_iter().enumerate() {
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
            let mut response = request.execute().await?;
            let response_header = Header::read_from_prefix(&response)
                .map_err(|_| Error::InvalidHeader)?
                .0;
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
            if compounded {
                Header::mut_from_prefix(&mut response[..])
                    .map_err(|_| Error::InvalidHeader)?
                    .0
                    .flags
                    .set_related_operations(self.related && index != 0);
                if let Some(start) = last_response {
                    let next = output.len() - start;
                    Header::mut_from_prefix(&mut output[start..])
                        .map_err(|_| Error::InvalidHeader)?
                        .0
                        .next_command = (next as u32).into();
                }
                last_response = Some(output.len());
                output.extend_from_slice(&response);
                output.resize(
                    align_up(output.len(), COMPOUND_ALIGNMENT).map_err(Error::Backend)?,
                    0,
                );
            } else {
                output = response;
            }
        }
        Ok(output)
    }
}
