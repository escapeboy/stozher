//! The Stozher kernel binary: `serve`, `keygen`, `verify`.
//!
//! Argument parsing is hand-written. The surface is three subcommands and two flags; a parser
//! generator would be a dependency in a product whose pitch is a minimal auditable surface
//! (ADR-0003), and there is nothing here it would make clearer.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use stozher_kernel::{Config, Kernel, checkpoint, http, keys};

const USAGE: &str = "\
stozher-kernel — append-only hash-chained event store, validating ingest, versioned policy pull

usage:
  stozher-kernel serve   --config <path>   run the HTTP service
  stozher-kernel keygen  --out <path>      generate the kernel seed (mode 0600, refuses to overwrite)
  stozher-kernel verify  --config <path>   verify every stream and its checkpoints, then exit
  stozher-kernel help

The kernel refuses to start if its seed file is readable by anyone but its owner (spec 09 section 8).
";

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_target(false)
        // Payloads, key material and signatures are never logged at any level; INFO carries
        // envelope ids, stream names and reason codes only.
        .with_max_level(tracing::Level::INFO)
        .init();

    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let command = arguments.first().map(String::as_str).unwrap_or("help");
    let flag = |name: &str| -> Option<PathBuf> {
        arguments
            .iter()
            .position(|a| a == name)
            .and_then(|i| arguments.get(i + 1))
            .map(PathBuf::from)
    };

    match command {
        "keygen" => {
            let Some(out) = flag("--out") else {
                eprintln!("keygen requires --out <path>");
                return ExitCode::FAILURE;
            };
            match keys::keygen(&out) {
                Ok(key_id) => {
                    // The public identifier is printed so the operator can enrol it; the seed
                    // itself only ever exists in the file, at mode 0600.
                    println!("wrote {} (mode 0600)", out.display());
                    println!("checkpoint key (m/1054'/3'/0'): {key_id}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("keygen failed: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        "serve" => run(flag("--config"), Mode::Serve),
        "verify" => run(flag("--config"), Mode::Verify),
        "help" | "--help" | "-h" => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("unknown command {other:?}\n");
            print!("{USAGE}");
            ExitCode::FAILURE
        }
    }
}

enum Mode {
    Serve,
    Verify,
}

fn run(config_path: Option<PathBuf>, mode: Mode) -> ExitCode {
    let Some(config_path) = config_path else {
        eprintln!("--config <path> is required");
        return ExitCode::FAILURE;
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("cannot start the async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(async move {
        let config = match Config::load(&config_path) {
            Ok(config) => config,
            Err(e) => {
                eprintln!("configuration: {e}");
                return ExitCode::FAILURE;
            }
        };
        let bind = config.bind.clone();
        let kernel = match Kernel::open(config).await {
            Ok(kernel) => Arc::new(kernel),
            Err(e) => {
                eprintln!("startup refused: {e}");
                return ExitCode::FAILURE;
            }
        };
        match mode {
            Mode::Verify => verify(&kernel).await,
            Mode::Serve => serve(kernel, &bind).await,
        }
    })
}

async fn verify(kernel: &Kernel) -> ExitCode {
    let streams = match kernel.ingest.store().streams().await {
        Ok(streams) => streams,
        Err(e) => {
            eprintln!("cannot list streams: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut failures = 0usize;
    for stream in &streams {
        let Some(name) = stream["stream"].as_str() else {
            continue;
        };
        match checkpoint::verify_stream(&kernel.ingest, name).await {
            Ok(report) => println!(
                "{name}: {} envelopes, head {}, anchored {}",
                report["count"], report["head-hash"], report["anchored"]
            ),
            Err(e) => {
                failures += 1;
                println!("{name}: FAILED {e}");
            }
        }
    }
    let records = kernel
        .ingest
        .store()
        .rejection_chain()
        .await
        .unwrap_or_default();
    match stozher_kernel::store::verify_rejection_chain(
        &records,
        kernel.ingest.store().rejection_stream(),
    ) {
        Ok(head) => println!(
            "{}: {} rejection records, head {}",
            kernel.ingest.store().rejection_stream(),
            records.len(),
            head.unwrap_or_else(|| "-".to_owned())
        ),
        Err(e) => {
            failures += 1;
            println!("rejection stream: FAILED {e}");
        }
    }
    if failures == 0 {
        println!("all {} streams verify", streams.len());
        ExitCode::SUCCESS
    } else {
        eprintln!("{failures} stream(s) failed verification");
        ExitCode::FAILURE
    }
}

async fn serve(kernel: Arc<Kernel>, bind: &str) -> ExitCode {
    let listener = match tokio::net::TcpListener::bind(bind).await {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("cannot bind {bind}: {e}");
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(
        bind = %bind,
        version = stozher_core::VERSION,
        checkpoint_key = %kernel.ingest.kernel_key().id(),
        "stozher-kernel listening"
    );
    let app = http::router(Arc::clone(&kernel));
    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutting down");
    };
    match axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("server failed: {e}");
            ExitCode::FAILURE
        }
    }
}
