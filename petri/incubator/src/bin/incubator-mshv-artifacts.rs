// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Acquire pinned public Azure Linux boot artifacts without installing RPMs.

#![forbid(unsafe_code)]

use anyhow::Context;
use clap::Parser;
use sha2::Digest;
use std::collections::BTreeMap;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

const REPOSITORY: &str = "https://packages.microsoft.com/azurelinux/3.0/prod";

struct Artifact {
    repository: &'static str,
    filename: &'static str,
    sha256: &'static str,
}

impl Artifact {
    fn url(&self) -> String {
        format!(
            "{}/{}/x86_64/Packages/{}/{}",
            REPOSITORY,
            self.repository,
            &self.filename[..1],
            self.filename
        )
    }
}

const ARTIFACTS: &[Artifact] = &[
    Artifact {
        repository: "base",
        filename: "shim-15.8-6.azl3.x86_64.rpm",
        sha256: "192f18a34eb5be85d6cbba278824e2fbaf7e3af8df3d40c56a24df7256eb5205",
    },
    Artifact {
        repository: "base",
        filename: "grub2-efi-binary-2.06-27.azl3.x86_64.rpm",
        sha256: "c47d6e5becf63971609dd198035f8bc30fac9271d3a0367d01380b466601303d",
    },
    Artifact {
        repository: "base",
        filename: "edk2-hvloader-20240524git3e722403cd16-20.azl3.x86_64.rpm",
        sha256: "8f5dcf56e7a009f5e2a9f594c46c6d6b43345eff7f2ddd4b011095ab95ec40c3",
    },
    Artifact {
        repository: "ms-non-oss",
        filename: "mshv-26100.9444.2609032029.1-1.azl3.x86_64.rpm",
        sha256: "95a95671546fc29488ffd8b61c00d9869928ceca25005f5c1ca3beaaf83d9385",
    },
    Artifact {
        repository: "ms-non-oss",
        filename: "mshv-bootloader-lx-26100.9444.2609032029.1-1.azl3.x86_64.rpm",
        sha256: "cf75cc2633df5d35484ea75aacea7d308a1b18f4064c0e159d99e0e20c48df63",
    },
];

#[derive(Parser)]
#[command(about = "Acquire pinned public x64 mshv boot artifacts from Azure Linux RPMs")]
struct Args {
    /// Directory for cached RPMs (created if absent).
    #[arg(long)]
    cache: PathBuf,
    /// New output directory; its parent must exist. Existing paths are refused.
    #[arg(long)]
    output: PathBuf,
    /// Only use cached RPMs; never access the network.
    #[arg(long)]
    offline: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    acquire(&args.cache, &args.output, args.offline)?;
    println!("Boot artifacts: {}", args.output.display());
    Ok(())
}

fn acquire(cache: &Path, output: &Path, offline: bool) -> anyhow::Result<()> {
    match fs_err::symlink_metadata(output) {
        Ok(_) => anyhow::bail!("output already exists: {}", output.display()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    fs_err::create_dir_all(cache)?;
    let mut files = BTreeMap::new();
    let mut manifest = String::new();
    for artifact in ARTIFACTS {
        let path = cached_rpm(cache, artifact, offline)?;
        let package =
            rpm::Package::open(&path).with_context(|| format!("reading RPM {}", path.display()))?;
        anyhow::ensure!(
            package.metadata.get_arch()? == "x86_64",
            "expected x86_64 RPM: {}",
            artifact.filename
        );
        collect_payload(&package, &mut files)
            .with_context(|| format!("extracting {}", artifact.filename))?;
        manifest.push_str(&format!("{}  {}\n", artifact.sha256, artifact.url()));
    }
    for required in [
        "boot/EFI/BOOT/bootx64.efi",
        "boot/EFI/BOOT/grubx64.efi",
        "boot/HvLoader.efi",
        "boot/lxhvloader.dll",
        "boot/Windows/System32/hvax64.exe",
        "boot/Windows/System32/hvix64.exe",
    ] {
        anyhow::ensure!(
            files.contains_key(required),
            "missing boot artifact {required}"
        );
    }
    files.insert("SHA256SUMS".into(), manifest.into_bytes());
    publish(output, files)
}

fn cached_rpm(cache: &Path, artifact: &Artifact, offline: bool) -> anyhow::Result<PathBuf> {
    let path = cache.join(artifact.filename);
    match fs_err::symlink_metadata(&path) {
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.file_type().is_file(),
                "cache entry is not a regular file: {}",
                path.display()
            );
            verify_hash(&path, artifact.sha256)?;
            return Ok(path);
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    anyhow::ensure!(!offline, "RPM is not cached: {}", path.display());
    let temp = tempfile::NamedTempFile::new_in(cache)?;
    let status = std::process::Command::new("curl")
        .args([
            "--fail",
            "--location",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--connect-timeout",
            "30",
            "--max-time",
            "300",
            "--output",
        ])
        .arg(temp.path())
        .arg(artifact.url())
        .status()
        .context("launching curl to download RPM (curl must be on PATH)")?;
    anyhow::ensure!(status.success(), "RPM download failed: {status}");
    verify_hash(temp.path(), artifact.sha256)?;
    temp.persist_noclobber(&path)
        .with_context(|| format!("publishing cached RPM {}", path.display()))?;
    Ok(path)
}

fn verify_hash(path: &Path, expected: &str) -> anyhow::Result<()> {
    let mut file = fs_err::File::open(path)?;
    let mut hash = sha2::Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let len = file.read(&mut buffer)?;
        if len == 0 {
            break;
        }
        hash.update(&buffer[..len]);
    }
    let actual = hex::encode(hash.finalize());
    anyhow::ensure!(
        actual == expected,
        "SHA-256 mismatch for {}: expected {expected}, got {actual}",
        path.display()
    );
    Ok(())
}

fn collect_payload(
    package: &rpm::Package,
    files: &mut BTreeMap<String, Vec<u8>>,
) -> anyhow::Result<()> {
    for entry in package.files()? {
        let entry = entry?;
        let path = entry.metadata.path();
        let path = path.to_str().context("non-UTF-8 RPM path")?;
        let Some(destination) = destination(path)? else {
            continue;
        };
        match entry.metadata.file_type() {
            rpm::FileType::Dir => continue,
            rpm::FileType::Regular => {}
            other => anyhow::bail!("unsupported RPM file type {other:?}: {path}"),
        }
        let content = entry
            .content()
            .with_context(|| format!("missing contents for {path}"))?;
        anyhow::ensure!(
            !files
                .keys()
                .any(|key| key.eq_ignore_ascii_case(&destination)),
            "duplicate extracted path: {destination}"
        );
        files.insert(destination, content.to_vec());
    }
    Ok(())
}

fn destination(path: &str) -> anyhow::Result<Option<String>> {
    anyhow::ensure!(
        path.starts_with('/')
            && path[1..].split('/').all(|part| {
                !part.is_empty()
                    && part != "."
                    && part != ".."
                    && part.is_ascii()
                    && !part.ends_with([' ', '.'])
                    && !part
                        .chars()
                        .any(|c| c.is_control() || "\"*:<>?\\|".contains(c))
            }),
        "unsupported RPM path: {path:?}"
    );
    // Keep the complete EFI payload and packaged licenses, never package scripts
    // or host configuration. No RPM path is used as an absolute host path.
    if let Some(relative) = path.strip_prefix("/boot/efi/") {
        Ok(Some(format!("boot/{relative}")))
    } else if let Some(relative) = path.strip_prefix("/usr/share/licenses/") {
        Ok(Some(format!("licenses/{relative}")))
    } else {
        Ok(None)
    }
}

fn publish(output: &Path, files: BTreeMap<String, Vec<u8>>) -> anyhow::Result<()> {
    fs_err::create_dir(output)
        .with_context(|| format!("creating new output directory {}", output.display()))?;
    for (name, contents) in files {
        let path = output.join(name);
        if let Some(parent) = path.parent() {
            fs_err::create_dir_all(parent)?;
        }
        let mut file = fs_err::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        file.write_all(&contents)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;

    #[test]
    fn maps_only_boot_files_and_licenses() {
        assert_eq!(
            destination("/boot/efi/Windows/System32/kdstub.dll").unwrap(),
            Some("boot/Windows/System32/kdstub.dll".into())
        );
        assert_eq!(
            destination("/usr/share/licenses/mshv/EULA.txt").unwrap(),
            Some("licenses/mshv/EULA.txt".into())
        );
        assert_eq!(destination("/etc/dnf/protected.d/shim.conf").unwrap(), None);
    }

    #[test]
    fn rejects_unsafe_paths() {
        for path in [
            "/boot/efi/../escape",
            "/boot/efi/./file",
            "/boot/efi//file",
            "/boot/efi/C:drive",
            "/boot/efi/a\\b",
            "/boot/efi/file.",
            "/boot/efi/file ",
            "/boot/efi/file\n",
            "/boot/efi/\u{e9}",
            "relative",
            "/",
        ] {
            assert!(destination(path).is_err(), "{path:?}");
        }
    }

    #[test]
    fn verifies_cached_bytes_even_offline() {
        let cache = tempfile::tempdir().unwrap();
        let artifact = Artifact {
            repository: "base",
            filename: "test.rpm",
            sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        };
        assert!(cached_rpm(cache.path(), &artifact, true).is_err());
        let path = cache.path().join(artifact.filename);
        fs_err::write(&path, b"abc").unwrap();
        assert_eq!(cached_rpm(cache.path(), &artifact, true).unwrap(), path);
        fs_err::write(&path, b"bad").unwrap();
        assert!(cached_rpm(cache.path(), &artifact, true).is_err());
    }

    #[test]
    fn refuses_existing_output_before_acquiring() {
        let temp = tempfile::tempdir().unwrap();
        let cache = temp.path().join("cache");
        let output = temp.path().join("output");
        fs_err::write(&output, b"keep").unwrap();
        assert!(acquire(&cache, &output, false).is_err());
        assert_eq!(fs_err::read(&output).unwrap(), b"keep");
        assert!(!cache.exists());
    }

    #[test]
    fn publishes_without_clobbering() {
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("output");
        let files = BTreeMap::from([("boot/HvLoader.efi".into(), b"loader".to_vec())]);
        publish(&output, files.clone()).unwrap();
        assert!(publish(&output, files).is_err());
        assert_eq!(
            fs_err::read(output.join("boot/HvLoader.efi")).unwrap(),
            b"loader"
        );
    }
}
