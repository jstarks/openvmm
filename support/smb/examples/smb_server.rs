// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Local unsigned guest-access test server with a writable memory share.

use pal_async::DefaultPool;
use smb::{Server, memory::MemoryFs};
use std::net::{SocketAddr, TcpListener};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let address: SocketAddr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:1445".to_owned())
        .parse()?;
    if !address.ip().is_loopback() {
        return Err("the synthetic test server only listens on loopback".into());
    }
    let listener = TcpListener::bind(address)?;
    let server = Server::new("memory", MemoryFs::new(16 * 1024 * 1024, 4096))?;
    println!(
        "SMB test share \\\\{}\\memory on {}",
        address.ip(),
        listener.local_addr()?
    );
    DefaultPool::run_with(async |driver| -> Result<(), smb::Error> {
        let mut service = smb::tcp::Server::new(driver, listener, server)?;
        service.start();
        std::future::pending().await
    })?;
    Ok(())
}
