// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use fs_err::File;
use fs_err::PathExt;
use std::path::Path;
use std::path::PathBuf;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::writer::Tee;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::fmt::TestWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Initialize Petri tracing with the given output path for log files.
///
/// Events go to three places:
/// - `petri.jsonl`, in newline-separated JSON format.
/// - standard output, in human readable format.
/// - a log file, in human readable format. This file is `petri.log`, except
///   for events whose target ends in `.log`, which go to separate files named by
///   the target.
pub fn try_init_tracing(root_path: &Path) -> anyhow::Result<()> {
    let targets =
        if let Ok(var) = std::env::var("OPENVMM_LOG").or_else(|_| std::env::var("HVLITE_LOG")) {
            var.parse().unwrap()
        } else {
            Targets::new().with_default(LevelFilter::DEBUG)
        };

    let json_log_file = File::create(root_path.join("petri.jsonl"))?;

    let json_sub = tracing_subscriber::fmt::layer()
        .json()
        .with_ansi(false)
        .log_internal_errors(true)
        .with_writer(std::fs::File::from(json_log_file))
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE);

    let compact_sub = tracing_subscriber::fmt::layer()
        .compact()
        .with_ansi(false) // avoid polluting logs with escape sequences
        .log_internal_errors(true)
        .with_writer(PetriWriter::new(root_path)?)
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE);

    tracing_subscriber::registry()
        .with(json_sub)
        .with(compact_sub)
        .with(targets)
        .try_init()?;

    Ok(())
}

struct PetriWriter {
    root_path: PathBuf,
    log_file: File,
    separate_files: once_map::OnceMap<String, Box<File>>,
}

impl PetriWriter {
    fn new(root_path: &Path) -> anyhow::Result<Self> {
        fs_err::create_dir_all(&root_path)?;
        // Canonicalize so that printed attachment paths are most likely to
        // work.
        let root_path = root_path.fs_err_canonicalize()?;
        let log_file = File::create(root_path.join("petri.log"))?;
        Ok(Self {
            log_file,
            root_path,
            separate_files: Default::default(),
        })
    }

    fn log_file_for(&self, target: &str) -> anyhow::Result<&File> {
        let f = match self.separate_files.get(target) {
            Some(f) => f,
            None => {
                self.separate_files.try_insert(target.to_owned(), |_| {
                    let path = self.root_path.join(target);
                    let file = File::create(&path)?;
                    // Print the junit attachment syntax to attach the file to the test result.
                    println!("[[ATTACHMENT|{}]]", path.display());
                    anyhow::Ok(Box::new(file))
                })?
            }
        };
        Ok(f)
    }
}

impl<'a> MakeWriter<'a> for PetriWriter {
    type Writer = Tee<TestWriter, &'a File>;

    fn make_writer(&'a self) -> Self::Writer {
        // When unknown err on the side of logging too much.
        Tee::new(TestWriter::new(), &self.log_file)
    }

    fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        let file = if meta.target().ends_with(".log") {
            match self.log_file_for(meta.target()) {
                Ok(file) => file,
                Err(err) => {
                    tracing::error!(
                        log_file_target = meta.target(),
                        error = err.as_ref() as &dyn std::error::Error,
                        "failed to create separate log file"
                    );
                    &self.log_file
                }
            }
        } else {
            &self.log_file
        };
        Tee::new(TestWriter::new(), file)
    }
}

/// Report a file as an attachment to the currently running test. This ensures
/// that the file makes it into the test results.
pub fn trace_attachment(path: impl AsRef<Path>) {
    fn trace(path: &Path) {
        // ATTACHMENT is most reliable when using true canonicalized paths
        #[expect(clippy::disallowed_methods)]
        match path.fs_err_canonicalize() {
            Ok(path) => {
                tracing::info!(target = "attachment", path = %path.display());
                // Use the inline junit syntax to attach the file to the test
                // result.
                println!("[[ATTACHMENT|{}]]", path.display());
            }
            Err(err) => {
                tracing::error!(
                    path = %path.display(),
                    error = &err as &dyn std::error::Error,
                    "failed to canonicalize attachment path"
                );
            }
        }
    }
    trace(path.as_ref());
}
