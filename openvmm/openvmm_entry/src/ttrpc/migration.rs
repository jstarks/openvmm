// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Pre-copy for the direct-boot profile. VM state and every byte of guest RAM
//! cross the TCP stream; neither the management client nor shared files act
//! as a data path. Loopback only: this prototype does not encrypt guest RAM.

use super::*;
use futures::AsyncReadExt;
use futures::AsyncWriteExt;
use hmac::{Hmac, KeyInit, Mac};
use pal_async::socket::PolledSocket;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};

type Stream = PolledSocket<TcpStream>;
const CHUNK: usize = 1024 * 1024;
const MAX_STATE: usize = 16 * CHUNK;
const END: u64 = u64::MAX;

fn endpoint(
    endpoint: Option<vmservice::MigrationEndpoint>,
) -> anyhow::Result<(SocketAddr, [u8; 32])> {
    let endpoint = endpoint.context("missing migration endpoint")?;
    let port: u16 = endpoint.port.try_into().context("invalid loopback port")?;
    anyhow::ensure!(port != 0, "missing loopback port");
    Ok((
        (Ipv4Addr::LOCALHOST, port).into(),
        endpoint
            .pairing_key
            .try_into()
            .ok()
            .context("expected a 32-byte pairing key")?,
    ))
}

async fn authenticate(stream: &mut Stream, key: &[u8; 32], sender: bool) -> anyhow::Result<()> {
    let mut local = [0; 32];
    getrandom::fill(&mut local).context("obtaining migration nonce")?;
    stream.write_all(&local).await?;
    let mut remote = [0; 32];
    stream.read_exact(&mut remote).await?;
    let (src, dst) = if sender {
        (&local, &remote)
    } else {
        (&remote, &local)
    };
    let mut transcript = b"OpenVMM loopback migration v1".to_vec();
    transcript.extend_from_slice(src);
    transcript.extend_from_slice(dst);
    transcript.push(u8::from(sender));
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key)?;
    mac.update(&transcript);
    stream.write_all(&mac.finalize().into_bytes()).await?;
    *transcript.last_mut().unwrap() ^= 1;
    let mut proof = [0; 32];
    stream.read_exact(&mut proof).await?;
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key)?;
    mac.update(&transcript);
    mac.verify_slice(&proof)
        .context("migration peer authentication failed")?;
    Ok(())
}

async fn send_blob(stream: &mut Stream, bytes: &[u8], max: usize) -> anyhow::Result<()> {
    anyhow::ensure!(bytes.len() <= max, "migration record exceeds limit");
    stream
        .write_all(&(bytes.len() as u32).to_le_bytes())
        .await?;
    stream.write_all(bytes).await?;
    Ok(())
}

async fn recv_blob(stream: &mut Stream, max: usize) -> anyhow::Result<Vec<u8>> {
    let mut size = [0; 4];
    stream.read_exact(&mut size).await?;
    let size = u32::from_le_bytes(size) as usize;
    anyhow::ensure!(size <= max, "migration record exceeds limit");
    let mut buf = vec![0; size];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn expect(stream: &mut Stream, tag: u8) -> anyhow::Result<()> {
    let mut byte = [0];
    stream.read_exact(&mut byte).await?;
    anyhow::ensure!(byte == [tag], "unexpected migration phase");
    Ok(())
}

async fn delta(
    worker: &mesh::Sender<VmRpc>,
    stream: &mut Stream,
    base: u64,
    len: u64,
) -> anyhow::Result<u64> {
    let bits = worker.call_failable(VmRpc::CollectRamDirty, ()).await?;
    let pages = len / 4096;
    anyhow::ensure!(
        bits.len() as u64 == pages.div_ceil(64),
        "dirty bitmap size changed"
    );
    let dirty = |page: u64| bits[(page / 64) as usize] & (1 << (page % 64)) != 0;
    let mut page = 0;
    let mut copied = 0;
    while page < pages {
        if !dirty(page) {
            page += 1;
            continue;
        }
        let first = page;
        while page < pages && page - first < CHUNK as u64 / 4096 && dirty(page) {
            page += 1;
        }
        let offset = first * 4096;
        let size = (page - first) * 4096;
        let bytes = worker
            .call_failable(VmRpc::ReadMemory, (base + offset, size as usize))
            .await?;
        stream.write_all(&offset.to_le_bytes()).await?;
        send_blob(stream, &bytes, CHUNK).await?;
        copied += size;
    }
    stream.write_all(&END.to_le_bytes()).await?;
    Ok(copied)
}

async fn apply_delta(
    stream: &mut Stream,
    mapping: &sparse_mmap::SparseMapping,
    len: usize,
) -> anyhow::Result<()> {
    let mut end = 0;
    loop {
        let mut offset = [0; 8];
        stream.read_exact(&mut offset).await?;
        let offset = u64::from_le_bytes(offset);
        if offset == END {
            break;
        }
        let offset = usize::try_from(offset)?;
        let bytes = recv_blob(stream, CHUNK).await?;
        anyhow::ensure!(
            offset >= end
                && offset.is_multiple_of(4096)
                && !bytes.is_empty()
                && bytes.len().is_multiple_of(4096),
            "invalid dirty extent"
        );
        end = offset
            .checked_add(bytes.len())
            .filter(|&v| v <= len)
            .context("dirty extent outside RAM")?;
        mapping.write_at(offset, &bytes)?;
    }
    Ok(())
}

impl VmService {
    pub(super) async fn migrate(
        &mut self,
        ctx: mesh::CancelContext,
        request: vmservice::MigrateVmRequest,
    ) -> anyhow::Result<vmservice::MigrateVmResponse> {
        let (addr, key) = endpoint(request.endpoint)?;
        let mut ctx = ctx.with_timeout(Duration::from_secs(120));
        anyhow::ensure!(
            matches!(self.lifecycle, VmLifecycle::Running),
            "migration requires running VM"
        );
        let vm = self.vm.as_ref().context("source missing")?;
        let config = vm
            .servicing_profile
            .clone()
            .context("unsupported migration configuration")?;
        let worker = vm.worker_rpc.clone();
        let mut stream = ctx
            .until_cancelled(PolledSocket::connect_tcp(&self.driver, addr))
            .await??;
        stream.get().set_nodelay(true)?;
        ctx.until_cancelled(authenticate(&mut stream, &key, true))
            .await??;
        let (base, len) = worker
            .call_failable(VmRpc::SetRamDirtyTracking, true)
            .await?;
        let mut paused = false;
        let transfer = ctx
            .until_cancelled(async {
                send_blob(&mut stream, &mesh::payload::encode(config), CHUNK).await?;
                stream.write_all(&len.to_le_bytes()).await?;
                expect(&mut stream, b'R').await?;
                worker.call_failable(VmRpc::CollectRamDirty, ()).await?;
                for offset in (0..len).step_by(CHUNK) {
                    let size = (len - offset).min(CHUNK as u64) as usize;
                    let bytes = worker
                        .call_failable(VmRpc::ReadMemory, (base + offset, size))
                        .await?;
                    stream.write_all(&bytes).await?;
                }
                let dirty = delta(&worker, &mut stream, base, len).await?;
                // Backpressure alone doesn't guarantee that the receiver has
                // applied the live round. Drain it before stopping the guest.
                expect(&mut stream, b'D').await?;
                paused = true;
                self.pause_vm().await?;
                let final_bytes = delta(&worker, &mut stream, base, len).await?;
                let state = worker.call_failable(VmRpc::Save, ()).await?;
                send_blob(&mut stream, &mesh::payload::encode(state), MAX_STATE).await?;
                expect(&mut stream, b'P').await?;
                anyhow::Ok(vmservice::MigrateVmResponse {
                    initial_bytes: len,
                    dirty_bytes: dirty,
                    final_bytes,
                })
            })
            .await
            .map_err(anyhow::Error::from)
            .and_then(|r| r);
        if transfer.is_err() {
            drop(stream);
            let disable = worker
                .call_failable(VmRpc::SetRamDirtyTracking, false)
                .await;
            if paused {
                self.resume_vm().await?;
            }
            disable.context("disabling dirty tracking after rollback")?;
            return transfer;
        }
        // The receiver remains paused unless it receives this byte. Never
        // resume the source if the outcome of writing it is ambiguous.
        let commit = stream.write_all(b"C").await;
        self.teardown_vm().await?;
        commit?;
        ctx.until_cancelled(expect(&mut stream, b'A')).await??;
        transfer
    }

    pub(super) async fn receive_migration(
        &mut self,
        ctx: mesh::CancelContext,
        request: vmservice::ReceiveMigrationVmRequest,
    ) -> anyhow::Result<()> {
        let mut ctx = ctx.with_timeout(Duration::from_secs(120));
        let (addr, key) = endpoint(request.endpoint)?;
        anyhow::ensure!(self.vm.is_none(), "destination already has a VM");
        let config = request
            .config
            .context("missing destination configuration")?;
        let profile =
            servicing::profile(&config).context("unsupported destination configuration")?;
        let memory = config
            .memory_config
            .as_ref()
            .context("missing RAM configuration")?;
        let size = usize::try_from(memory.memory_mb)?
            .checked_mul(1024 * 1024)
            .context("RAM size overflow")?;
        anyhow::ensure!(size > 0, "empty destination RAM");
        let backing = memory.backing_file_path.as_ref().map(PathBuf::from);
        let listener = TcpListener::bind(addr)?;
        let mut listener = PolledSocket::new(&self.driver, listener)?;
        let (conn, _) = ctx.until_cancelled(listener.accept()).await??;
        conn.set_nodelay(true)?;
        let mut stream = PolledSocket::new(&self.driver, conn)?;
        let receive = async {
            authenticate(&mut stream, &key, false).await?;
            let remote: servicing::TransferProfile =
                mesh::payload::decode(&recv_blob(&mut stream, CHUNK).await?)?;
            anyhow::ensure!(remote == profile, "source and destination profiles differ");
            let mut length = [0; 8];
            stream.read_exact(&mut length).await?;
            anyhow::ensure!(
                u64::from_le_bytes(length) == size as u64,
                "RAM size mismatch"
            );
            let temp = backing
                .as_ref()
                .map(|path| {
                    tempfile::NamedTempFile::new_in(
                        path.parent().context("missing backing parent")?,
                    )
                    .map_err(anyhow::Error::from)
                })
                .transpose()?;
            let ram = if let Some(temp) = &temp {
                temp.as_file().set_len(size as u64)?;
                openvmm_helpers::shared_memory::file_to_shared_memory_fd(
                    temp.as_file().try_clone()?,
                )?
            } else {
                sparse_mmap::alloc_shared_memory(size, "migration")?
            };
            let mapping = sparse_mmap::SparseMapping::new(size)?;
            mapping.map_file(0, size, &ram, 0, true)?;
            stream.write_all(b"R").await?;
            let mut buf = vec![0; CHUNK];
            for offset in (0..size).step_by(CHUNK) {
                let n = (size - offset).min(CHUNK);
                stream.read_exact(&mut buf[..n]).await?;
                mapping.write_at(offset, &buf[..n])?;
            }
            apply_delta(&mut stream, &mapping, size).await?;
            stream.write_all(b"D").await?;
            apply_delta(&mut stream, &mapping, size).await?;
            let state = mesh::payload::decode(&recv_blob(&mut stream, MAX_STATE).await?)?;
            anyhow::Ok((ram, state, temp))
        };
        let (ram, state, temp) = ctx.until_cancelled(receive).await??;
        self.create_vm_inner(config, Some(RestoreSource::Migrated(ram, state)))
            .await?;
        let decision = async {
            if let (Some(temp), Some(path)) = (temp, &backing) {
                temp.persist_noclobber(path)?;
            }
            stream.write_all(b"P").await?;
            expect(&mut stream, b'C').await
        }
        .await;
        if let Err(err) = decision {
            self.teardown_vm().await?;
            return Err(err).context("source did not commit migration");
        }
        if !request.start_paused {
            self.resume_vm().await?;
        }
        stream.write_all(b"A").await?;
        Ok(())
    }
}
