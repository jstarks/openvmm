// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Manages a blob URL resolver child process for disks backed by
//! URLs with expiring credentials (e.g., Azure Blob SAS tokens).
//!
//! The resolver binary communicates via JSON-lines on stdin/stdout.
//! See the `drop-vhd-resolver` tool for the protocol specification.

use anyhow::Context as _;
use mesh::CellUpdater;
use std::io::BufRead;
use std::io::Write;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;

/// Response from the resolver process.
#[derive(serde::Deserialize)]
struct ResolverResponse {
    url: Option<String>,
    expires: Option<String>,
    token: Option<String>,
    error: Option<String>,
}

/// Launch the resolver in serve mode, send the initial resolve request,
/// and return the URL, expiry, refresh token, and child process.
pub fn initial_resolve(
    resolver_path: &str,
    params: &[(String, String)],
) -> anyhow::Result<(String, Option<String>, String, Child)> {
    let mut child = Command::new(resolver_path)
        .arg("serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("failed to launch resolver: {resolver_path}"))?;

    let stdin = child.stdin.as_mut().context("no stdin")?;
    let stdout = child.stdout.as_mut().context("no stdout")?;

    // Build the resolve request
    let params_map: std::collections::HashMap<&str, &str> =
        params.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

    let request = serde_json::json!({
        "action": "resolve",
        "params": params_map,
    });

    writeln!(stdin, "{}", request)?;
    stdin.flush()?;

    // Read the response (one JSON line)
    let mut line = String::new();
    let mut reader = std::io::BufReader::new(stdout);
    reader.read_line(&mut line)?;

    let response: ResolverResponse =
        serde_json::from_str(&line).context("failed to parse resolver response")?;

    if let Some(error) = response.error {
        anyhow::bail!("resolver error: {error}");
    }

    let url = response.url.context("resolver did not return a URL")?;
    let token = response.token.context("resolver did not return a token")?;

    Ok((url, response.expires, token, child))
}

/// Spawn a background thread that refreshes the URL before it expires.
///
/// The thread owns the `CellUpdater` and the resolver child process.
/// It sleeps until near the expiry time, sends a refresh request, and
/// pushes the new URL into the cell.
pub fn spawn_refresh_task(
    mut updater: CellUpdater<String>,
    initial_token: String,
    initial_expires: Option<String>,
    mut child: Child,
) {
    std::thread::Builder::new()
        .name("blob-url-refresh".into())
        .spawn(move || {
            let mut token = initial_token;
            let mut expires = initial_expires;

            loop {
                // Sleep until 10 minutes before expiry, or 1 hour if no expiry known.
                let sleep_duration = expires
                    .as_deref()
                    .and_then(parse_sleep_duration)
                    .unwrap_or(std::time::Duration::from_secs(3600));

                tracing::info!(
                    ?sleep_duration,
                    "blob-url-refresh: sleeping until next refresh"
                );
                std::thread::sleep(sleep_duration);

                match refresh(&mut child, &token) {
                    Ok(response) => {
                        if let Some(new_url) = response.url {
                            tracing::info!("blob-url-refresh: refreshed URL");
                            // Block on the async set — we're in a dedicated thread.
                            futures::executor::block_on(updater.set(new_url));
                        }
                        if let Some(new_token) = response.token {
                            token = new_token;
                        }
                        expires = response.expires;
                    }
                    Err(e) => {
                        tracing::error!(
                            error = &*format!("{e:#}"),
                            "blob-url-refresh: refresh failed, will retry in 60s"
                        );
                        std::thread::sleep(std::time::Duration::from_secs(60));
                    }
                }
            }
        })
        .expect("failed to spawn blob-url-refresh thread");
}

fn refresh(child: &mut Child, token: &str) -> anyhow::Result<ResolverResponse> {
    let stdin = child.stdin.as_mut().context("no stdin")?;
    let stdout = child.stdout.as_mut().context("no stdout")?;

    let request = serde_json::json!({
        "action": "refresh",
        "token": token,
    });

    writeln!(stdin, "{}", request)?;
    stdin.flush()?;

    let mut line = String::new();
    let mut reader = std::io::BufReader::new(stdout);
    reader.read_line(&mut line)?;

    let response: ResolverResponse =
        serde_json::from_str(&line).context("failed to parse resolver response")?;

    if let Some(error) = response.error {
        anyhow::bail!("resolver error: {error}");
    }

    Ok(response)
}

/// Parse an ISO 8601 expiry string and return a duration to sleep
/// (expiry minus 10 minutes, clamped to at least 30 seconds).
fn parse_sleep_duration(expires: &str) -> Option<std::time::Duration> {
    let expiry: jiff::Timestamp = expires.parse().ok()?;
    let now = jiff::Timestamp::now();
    let margin = jiff::SignedDuration::from_mins(10);
    let refresh_at = expiry - margin;
    let until_refresh = refresh_at - now;
    let secs = until_refresh.total(jiff::Unit::Second).ok()?.max(30.0);
    Some(std::time::Duration::from_secs(secs as u64))
}
