// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::io::Io;
use crate::names;
use event_listener::Event;
use futures::FutureExt;
use pal_async::driver::PollImpl;
use pal_async::fd::PollFdReady;
use pal_async::interest::{InterestSlot, PollEvents};
use parking_lot::Mutex;
use smb::provider::{Change, NotifyResult, RequestContext};
use smb::spec::{NotifyAction, NotifyFilter, Status};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::sync::Arc;

const DIRECTORY_LIMIT: usize = 4096;
const WAITER_LIMIT: usize = 1024;
const BUFFER_LIMIT: usize = 256 * 1024;

struct Source {
    // Unregister readiness before releasing the descriptor.
    ready: PollImpl<dyn PollFdReady>,
    file: Arc<File>,
    directories: HashMap<i32, String>,
    root: i32,
    ambiguous: bool,
}

impl Source {
    async fn new(io: &Io, directory: Arc<File>, tree: bool) -> Result<Self, Status> {
        let request = RequestContext::new(0);
        let file = io
            .watch_fd(&request)
            .await
            .map_err(super::filesystem::status)?;
        let mut source = Self {
            ready: io.readiness(&file).map_err(super::filesystem::status)?,
            file,
            directories: HashMap::new(),
            root: -1,
            ambiguous: false,
        };
        let mut pending = vec![(directory, String::new())];
        let mut seen = HashSet::new();
        while let Some((directory, prefix)) = pending.pop() {
            let stat = io
                .stat(directory.clone(), &request)
                .await
                .map_err(super::filesystem::status)?;
            if stat.stx_nlink == 0 {
                return Err(Status::DELETE_PENDING);
            }
            let key = (stat.stx_dev_major, stat.stx_dev_minor, stat.stx_ino);
            if !seen.insert(key) {
                source.ambiguous = true;
                continue;
            }
            if seen.len() > DIRECTORY_LIMIT {
                return Err(Status::INSUFFICIENT_RESOURCES);
            }
            let wd = io
                .watch_directory(source.file.clone(), directory.clone(), &request)
                .await
                .map_err(super::filesystem::status)?;
            if prefix.is_empty() {
                source.root = wd;
            }
            source.directories.insert(wd, prefix.clone());
            if !tree {
                continue;
            }
            for name in io
                .list(directory.clone(), &request)
                .await
                .map_err(super::filesystem::status)?
            {
                let text = match name.to_str() {
                    Ok(text) => names::project(text),
                    Err(error) => {
                        tracelimit::warn_ratelimited!(
                            ?error,
                            "omitting non-UTF-8 notification subtree"
                        );
                        continue;
                    }
                };
                let child = match io
                    .open(
                        directory.clone(),
                        name,
                        libc::O_PATH | libc::O_DIRECTORY,
                        0,
                        &request,
                    )
                    .await
                {
                    Ok(child) => child,
                    Err(error)
                        if matches!(
                            error.raw_os_error(),
                            Some(libc::ENOENT | libc::ENOTDIR | libc::ELOOP)
                        ) =>
                    {
                        continue;
                    }
                    Err(error) => return Err(super::filesystem::status(error)),
                };
                pending.push((
                    child,
                    if prefix.is_empty() {
                        text
                    } else {
                        format!("{prefix}\\{text}")
                    },
                ));
            }
        }
        Ok(source)
    }
}

struct State {
    source: Option<Source>,
    queue: Vec<Change>,
    waiters: VecDeque<(u64, u64)>,
    next: u64,
    reading: bool,
    dirty: bool,
    overflow: bool,
    terminal: Option<Status>,
}

pub(crate) struct Watch {
    directory: Arc<File>,
    filter: NotifyFilter,
    tree: bool,
    state: Mutex<State>,
    changed: Event,
}

struct Waiter {
    watch: Arc<Watch>,
    id: u64,
}

impl Drop for Waiter {
    fn drop(&mut self) {
        self.watch
            .state
            .lock()
            .waiters
            .retain(|(id, _)| *id != self.id);
        self.watch.changed.notify(usize::MAX);
    }
}

impl Watch {
    pub async fn new(
        io: &Io,
        directory: Arc<File>,
        filter: NotifyFilter,
        tree: bool,
    ) -> Result<Arc<Self>, Status> {
        let source = Source::new(io, directory.clone(), tree).await?;
        Ok(Arc::new(Self {
            directory,
            filter,
            tree,
            state: Mutex::new(State {
                source: Some(source),
                queue: Vec::new(),
                waiters: VecDeque::new(),
                next: 1,
                reading: false,
                dirty: false,
                overflow: false,
                terminal: None,
            }),
            changed: Event::new(),
        }))
    }

    #[cfg(test)]
    pub fn pending(&self, request: u64) -> bool {
        self.state
            .lock()
            .waiters
            .iter()
            .any(|(_, id)| *id == request)
    }

    pub fn waiter_count(&self) -> usize {
        self.state.lock().waiters.len()
    }

    pub fn invalidated(&self) -> bool {
        self.state.lock().terminal.is_some()
    }

    pub fn invalidate(&self) {
        let mut state = self.state.lock();
        state.terminal = Some(Status::DELETE_PENDING);
        state.queue.clear();
        drop(state);
        self.changed.notify(usize::MAX);
    }

    pub async fn retire_if_idle(&self, io: &Io) -> Result<(), Status> {
        let source = {
            let mut state = self.state.lock();
            if state.terminal.is_some() && state.waiters.is_empty() && !state.reading {
                state.source.take()
            } else {
                None
            }
        };
        if let Some(source) = source {
            drop(source.ready);
            io.close(source.file)
                .await
                .map_err(super::filesystem::status)?;
        }
        Ok(())
    }

    pub async fn shutdown(&self, io: &Io) -> Result<(), Status> {
        self.state
            .lock()
            .terminal
            .get_or_insert(Status::NOTIFY_CLEANUP);
        self.changed.notify(usize::MAX);
        loop {
            let listener = self.changed.listen();
            let source = {
                let mut state = self.state.lock();
                if state.reading || !state.waiters.is_empty() {
                    None
                } else {
                    Some(state.source.take())
                }
            };
            if let Some(source) = source {
                if let Some(source) = source {
                    drop(source.ready);
                    io.close(source.file)
                        .await
                        .map_err(super::filesystem::status)?;
                }
                return Ok(());
            }
            listener.await;
        }
    }

    pub async fn notify(
        self: &Arc<Self>,
        io: &Io,
        output: usize,
        request: &RequestContext,
    ) -> Result<NotifyResult, Status> {
        let id = {
            let mut state = self.state.lock();
            if state.waiters.len() == WAITER_LIMIT {
                return Err(Status::INSUFFICIENT_RESOURCES);
            }
            let id = state.next;
            state.next = id.checked_add(1).ok_or(Status::INSUFFICIENT_RESOURCES)?;
            state.waiters.push_back((id, request.id()));
            id
        };
        let _waiter = Waiter {
            watch: self.clone(),
            id,
        };
        let mut obtained = false;
        loop {
            let listener = self.changed.listen();
            if let Some(status) = self.state.lock().terminal {
                return Err(status);
            }
            if request.is_cancelled() && !obtained {
                return Err(Status::CANCELLED);
            }
            let (read, dirty) = {
                let mut state = self.state.lock();
                if state.waiters.front().is_some_and(|(first, _)| *first == id) && !state.reading {
                    if let Some(status) = state.terminal {
                        return Err(status);
                    }
                    if !state.dirty {
                        if state.overflow {
                            state.overflow = false;
                            return Ok(NotifyResult::Overflow);
                        }
                        if !state.queue.is_empty() {
                            if state.queue.iter().map(Change::encoded_len).sum::<usize>() > output {
                                return Ok(NotifyResult::Overflow);
                            }
                            return Ok(NotifyResult::Changes(std::mem::take(&mut state.queue)));
                        }
                    }
                    state.reading = true;
                    (true, state.dirty)
                } else {
                    (false, false)
                }
            };
            if read {
                let result = if dirty {
                    self.rebuild(io).await
                } else {
                    self.read(io, request).await
                };
                self.state.lock().reading = false;
                self.changed.notify(usize::MAX);
                if let Some(status) = self.state.lock().terminal {
                    return Err(status);
                }
                result?;
                let state = self.state.lock();
                obtained |= state.overflow || !state.queue.is_empty();
            } else {
                let mut listener = std::pin::pin!(listener.fuse());
                let mut cancelled = std::pin::pin!(request.cancelled().fuse());
                futures::select! {
                    () = listener => {},
                    () = cancelled => return Err(self.state.lock().terminal.unwrap_or(Status::CANCELLED)),
                }
            }
        }
    }

    async fn rebuild(&self, io: &Io) -> Result<(), Status> {
        let source = match Source::new(io, self.directory.clone(), self.tree).await {
            Ok(source) => source,
            Err(error) => {
                self.state.lock().terminal = Some(error);
                return Err(error);
            }
        };
        let old = {
            let mut state = self.state.lock();
            state.dirty = false;
            state.source.replace(source).expect("active watch source")
        };
        drop(old.ready);
        io.close(old.file).await.map_err(super::filesystem::status)
    }

    async fn read(&self, io: &Io, request: &RequestContext) -> Result<(), Status> {
        loop {
            let changed = self.changed.listen();
            let readiness = std::future::poll_fn(|cx| {
                self.state
                    .lock()
                    .source
                    .as_mut()
                    .expect("active watch source")
                    .ready
                    .poll_fd_ready(cx, InterestSlot::Read, PollEvents::IN)
            });
            let mut readiness = std::pin::pin!(readiness.fuse());
            let mut cancelled = std::pin::pin!(request.cancelled().fuse());
            let mut changed = std::pin::pin!(changed.fuse());
            futures::select! {
                _ = readiness => {},
                () = cancelled => return Err(Status::CANCELLED),
                () = changed => {
                    if let Some(status) = self.state.lock().terminal { return Err(status); }
                    continue;
                }
            }
            if request.is_cancelled() {
                return Err(Status::CANCELLED);
            }
            let file = {
                let mut state = self.state.lock();
                let source = state.source.as_mut().expect("active watch source");
                source.ready.clear_fd_ready(InterestSlot::Read);
                source.file.clone()
            };
            let committed = RequestContext::new(request.id());
            let mut bytes = Vec::new();
            loop {
                match io
                    .watch_events(
                        file.clone(),
                        if bytes.is_empty() {
                            request
                        } else {
                            &committed
                        },
                    )
                    .await
                {
                    Ok(batch) if batch.is_empty() => return Err(Status::UNSUCCESSFUL),
                    Ok(batch) => {
                        if bytes.len() + batch.len() > BUFFER_LIMIT {
                            let mut state = self.state.lock();
                            state.queue.clear();
                            state.overflow = true;
                            state.dirty = true;
                            return Ok(());
                        }
                        bytes.extend_from_slice(&batch);
                    }
                    Err(error) if error.raw_os_error() == Some(libc::EAGAIN) => break,
                    Err(error) => return Err(super::filesystem::status(error)),
                }
            }
            if bytes.is_empty() {
                continue;
            }
            self.decode(&bytes)?;
            return Ok(());
        }
    }

    fn decode(&self, bytes: &[u8]) -> Result<(), Status> {
        struct Entry {
            wd: i32,
            mask: u32,
            cookie: u32,
            name: String,
        }
        let mut entries = Vec::new();
        let mut remaining = bytes;
        let mut state = self.state.lock();
        while !remaining.is_empty() {
            if remaining.len() < 16 {
                return Err(Status::UNSUCCESSFUL);
            }
            let wd = i32::from_ne_bytes(remaining[..4].try_into().expect("checked event prefix"));
            let mask =
                u32::from_ne_bytes(remaining[4..8].try_into().expect("checked event prefix"));
            let cookie =
                u32::from_ne_bytes(remaining[8..12].try_into().expect("checked event prefix"));
            let length =
                u32::from_ne_bytes(remaining[12..16].try_into().expect("checked event prefix"))
                    as usize;
            let name = remaining.get(16..16 + length).ok_or(Status::UNSUCCESSFUL)?;
            remaining = &remaining[16 + length..];
            if mask & libc::IN_Q_OVERFLOW != 0 {
                state.overflow = true;
                state.dirty = true;
                continue;
            }
            if wd == state.source.as_ref().expect("active watch source").root
                && mask & (libc::IN_DELETE_SELF | libc::IN_IGNORED) != 0
            {
                state.terminal = Some(Status::DELETE_PENDING);
                continue;
            }
            if self.tree
                && (mask & libc::IN_ISDIR != 0
                    && mask
                        & (libc::IN_CREATE
                            | libc::IN_DELETE
                            | libc::IN_MOVED_FROM
                            | libc::IN_MOVED_TO)
                        != 0
                    || mask & (libc::IN_MOVE_SELF | libc::IN_IGNORED) != 0)
            {
                state.overflow = true;
                state.dirty = true;
            }
            let Some(prefix) = state
                .source
                .as_ref()
                .expect("active watch source")
                .directories
                .get(&wd)
            else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            let name =
                std::ffi::CStr::from_bytes_until_nul(name).map_err(|_| Status::UNSUCCESSFUL)?;
            if name.is_empty() {
                continue;
            }
            let text = match name.to_str() {
                Ok(text) => names::project(text),
                Err(error) => {
                    tracelimit::warn_ratelimited!(
                        ?error,
                        "non-UTF-8 notification requires enumeration"
                    );
                    state.overflow = true;
                    continue;
                }
            };
            let name = if prefix.is_empty() {
                text
            } else {
                format!("{prefix}\\{text}")
            };
            entries.push(Entry {
                wd,
                mask,
                cookie,
                name,
            });
        }
        let pairs: HashMap<_, _> = entries
            .iter()
            .filter(|entry| entry.mask & libc::IN_MOVED_FROM != 0)
            .map(|entry| (entry.cookie, entry.wd))
            .collect();
        let targets: HashMap<_, _> = entries
            .iter()
            .filter(|entry| entry.mask & libc::IN_MOVED_TO != 0)
            .map(|entry| (entry.cookie, entry.wd))
            .collect();
        for entry in entries {
            let naming = if entry.mask & libc::IN_ISDIR != 0 {
                self.filter.dir_name()
            } else {
                self.filter.file_name()
            };
            let action = if naming && entry.mask & libc::IN_CREATE != 0 {
                Some(NotifyAction::ADDED)
            } else if naming && entry.mask & libc::IN_DELETE != 0 {
                Some(NotifyAction::REMOVED)
            } else if naming && entry.mask & libc::IN_MOVED_FROM != 0 {
                Some(if targets.get(&entry.cookie) == Some(&entry.wd) {
                    NotifyAction::RENAMED_OLD_NAME
                } else {
                    NotifyAction::REMOVED
                })
            } else if naming && entry.mask & libc::IN_MOVED_TO != 0 {
                Some(if pairs.get(&entry.cookie) == Some(&entry.wd) {
                    NotifyAction::RENAMED_NEW_NAME
                } else {
                    NotifyAction::ADDED
                })
            } else if (entry.mask & libc::IN_MODIFY != 0
                && (self.filter.size() || self.filter.last_write()))
                || (entry.mask & libc::IN_ACCESS != 0 && self.filter.last_access())
                || (entry.mask & libc::IN_ATTRIB != 0
                    && (self.filter.attributes()
                        || self.filter.security()
                        || self.filter.ea()
                        || self.filter.creation()
                        || self.filter.last_access()
                        || self.filter.last_write()))
            {
                Some(NotifyAction::MODIFIED)
            } else {
                None
            };
            if let Some(action) = action {
                state.queue.push(Change {
                    action,
                    name: entry.name.clone(),
                });
            }
            if entry.mask & libc::IN_MOVED_TO != 0
                && entry.mask & libc::IN_ISDIR == 0
                && (self.filter.attributes() || self.filter.creation())
            {
                state.queue.push(Change {
                    action: NotifyAction::MODIFIED,
                    name: entry.name,
                });
            }
        }
        if state
            .source
            .as_ref()
            .expect("active watch source")
            .ambiguous
            || state.queue.len() > 4096
            || state.queue.iter().map(Change::encoded_len).sum::<usize>() > BUFFER_LIMIT
        {
            state.overflow = true;
        }
        if state.overflow {
            state.queue.clear();
        }
        Ok(())
    }
}
