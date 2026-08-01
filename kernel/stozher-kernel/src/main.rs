//! The Stozher kernel binary: `serve`, `keygen`, `identity`, `token`, `genesis`, `verify`, `decide`,
//! `conformance`.
//!
//! Argument parsing is hand-written. The surface is a handful of subcommands and flags; a parser
//! generator would be a dependency in a product whose pitch is a minimal auditable surface
//! (ADR-0003), and there is nothing here it would make clearer.
//!
//! Four of the seven subcommands — `keygen`, `identity`, `token`, `genesis` — open no socket, read
//! no configuration and touch no database. They are the operator's half of the install, and they run
//! on the operator's own machine so that a private seed never has to exist on the server.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use stozher_kernel::clock::Clock;
use stozher_kernel::genesis::{Ceremony, Identity};
use stozher_kernel::{Config, Kernel, checkpoint, genesis, http, keys};

const USAGE: &str = "\
stozher-kernel — append-only hash-chained event store, validating ingest, versioned policy pull

usage:
  stozher-kernel serve    --config <path>  run the HTTP service
  stozher-kernel keygen   --out <path>     generate a seed (mode 0600, refuses to overwrite)
  stozher-kernel identity --key <path> [--role <n>] [--index <n>]
                          print the public key identifiers a seed yields
  stozher-kernel grant    --key <path> --root <human:name> --grantee <subject>
                          --grantee-key <ed25519:...> --out <path>
                          [--days <n>] [--components <a,b>] [--actions <a,b>]
                          [--classes <a,b>] [--resources <a,b>]
                          sign the standing mandate a component acts under
  stozher-kernel token                     print a fresh caller token and the digest to configure
  stozher-kernel genesis  --key <path> --root <human:name> --out <dir>
                          [--agent <agent:name>] [--policy-version <v>]
                          [--second-root <human:name>] [--second-root-key <ed25519:...>]
                          [--core-stream <name>] [--caller <subject,subject>]
                          [--bind <addr>] [--database <path>] [--kernel-seed <path>]
                          [--console-url <url>]
                          build the two genesis envelopes and a kernel configuration, offline
                          (spec 05 section 5.2)
  stozher-kernel submit   --url <base> [--file <path>] [--token-env <VAR>]
                          POST an already-signed ingest request (stdin when no --file)
  stozher-kernel answer   --url <base> --request <64 hex> [--file <path>] [--token-env <VAR>]
                          hand an already-signed gate decision to the console
  stozher-kernel await-health --url <base> [--timeout <seconds>]
  stozher-kernel snapshot --config <path> --out <path>
                          consistent copy of the store, service still running
  stozher-kernel verify   --config <path>  verify every stream and its checkpoints, then exit
  stozher-kernel decide   --request <64 hex> --key <path> [--approve | --deny <reason>]
                          [--minutes <n>] [--role <n>] [--index <n>]
                          sign a gate decision and print it; submit it to
                          POST /console/pending/<request-hash>/decide
  stozher-kernel conformance --manifest <path> --component <command>
                          [--vectors <dir>] [--at <timestamp>]
                          run spec 08 section 4 against a component and print the result;
                          exits non-zero unless every group passed
  stozher-kernel help

The kernel refuses to start if its seed file is readable by anyone but its owner (spec 09 section 8).

`keygen`, `identity`, `token`, `genesis` and `decide` open no socket and read no configuration: they
run in the operator's own process, on the operator's own machine, so a private seed never has to
exist on the server. `genesis` prints two ordinary POST /v1/ingest bodies; nothing about them is
privileged and every ingest check runs over them.

`decide` reads the approver's own key file. The service never holds approver key material and has no
route that produces an approver's signature, so it cannot manufacture an approval — the friction
here is what buys that.

An approver enrolled by `genesis` holds the root key at role 0': sign with `--role 0 --index 0`.
";

/// An approval is a permission to act now, not a licence (spec 06 section 1.2).
const DEFAULT_APPROVAL_MINUTES: i64 = 15;

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let command = arguments.first().map(String::as_str).unwrap_or("help");

    let logs = tracing_subscriber::fmt()
        .with_target(false)
        // Payloads, key material and signatures are never logged at any level; INFO carries
        // envelope ids, stream names and reason codes only.
        .with_max_level(tracing::Level::INFO);
    if command == "conformance" {
        // `conformance` writes a document to stdout for a person or a script to read. A log line in
        // the middle of it is not a cosmetic problem: it makes the output unparseable, which turns a
        // green run into an error nobody can distinguish from a failed one.
        logs.with_writer(std::io::stderr).init();
    } else {
        logs.init();
    }
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
        "identity" => identity(&arguments),
        "grant" => grant(&arguments),
        "token" => match genesis::caller_token() {
            Ok((token, digest)) => {
                // The token goes to the component that will present it; only the digest is written
                // to configuration, so the file that ships to the server holds no secret.
                println!("token        {token}");
                println!("token-sha256 {digest}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("token: {e}");
                ExitCode::FAILURE
            }
        },
        "genesis" => ceremony(&arguments),
        "snapshot" => snapshot(&arguments),
        "submit" => submit(&arguments),
        "answer" => answer(&arguments),
        "await-health" => await_health(&arguments),
        "serve" => run(flag("--config"), Mode::Serve),
        "verify" => run(flag("--config"), Mode::Verify),
        "decide" => decide(&arguments),
        "conformance" => conformance(&arguments),
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

/// Print every public identifier a seed yields, and nothing else.
///
/// One seed, four subjects (§01 §6): the organization backs up one secret and can recover the human
/// root, the bootstrap subject, the kernel's checkpoint key and the policy key from it. The seed
/// itself is never printed, and this command opens no socket, so it is safe to run on the laptop
/// that holds the seed and to paste its output into a ticket.
/// Read a `--name value` pair out of the argument list.
fn value<'a>(arguments: &'a [String], name: &str) -> Option<&'a str> {
    arguments
        .iter()
        .position(|a| a == name)
        .and_then(|i| arguments.get(i + 1))
        .map(String::as_str)
}

/// A comma-separated list flag, or a default. Empty entries are dropped rather than becoming an
/// empty pattern, which would match nothing and read like a typo that permitted everything.
fn list(arguments: &[String], name: &str, default: &[&str]) -> Vec<String> {
    match value(arguments, name) {
        Some(raw) => raw
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(str::to_owned)
            .collect(),
        None => default.iter().map(|d| (*d).to_owned()).collect(),
    }
}

fn identity(arguments: &[String]) -> ExitCode {
    let Some(path) = value(arguments, "--key") else {
        eprintln!("identity requires --key <path>");
        return ExitCode::FAILURE;
    };
    let seed = match keys::Seed::load(&PathBuf::from(path)) {
        Ok(seed) => seed,
        Err(e) => {
            eprintln!("key: {e}");
            return ExitCode::FAILURE;
        }
    };
    // `--role` prints one identifier and nothing else, so a script can read it without parsing a
    // table. A gateway's device key at role 2' is the case this exists for (§10 §1).
    if let Some(role) = value(arguments, "--role") {
        let Ok(role) = role.parse::<u32>() else {
            eprintln!("--role must be a non-negative integer");
            return ExitCode::FAILURE;
        };
        let index = value(arguments, "--index")
            .and_then(|i| i.parse::<u32>().ok())
            .unwrap_or(0);
        return match seed.derive(role, index) {
            Ok(key) => {
                println!("{}", key.id());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("derivation: {e}");
                ExitCode::FAILURE
            }
        };
    }
    match Identity::of(&seed) {
        Ok(identity) => {
            println!("root       (m/1054'/0'/0')  {}", identity.root);
            println!("agent      (m/1054'/1'/0')  {}", identity.agent);
            println!("checkpoint (m/1054'/3'/0')  {}", identity.checkpoint);
            println!("policy     (m/1054'/4'/0')  {}", identity.policy);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("derivation: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Build the two genesis envelopes and write them where the operator can submit them.
///
/// The output is two ordinary `POST /v1/ingest` bodies and the configuration fragment they
/// presuppose. Nothing here is privileged: the kernel validates both envelopes the way it validates
/// any other, which is the whole point of ADR-0006 §2 — genesis is two fully-validated envelopes,
/// not a bypass.
fn ceremony(arguments: &[String]) -> ExitCode {
    let value = |name: &str| value(arguments, name);
    let (Some(key_path), Some(root_subject), Some(out)) =
        (value("--key"), value("--root"), value("--out"))
    else {
        eprintln!("genesis requires --key <path>, --root <human:name> and --out <dir>");
        return ExitCode::FAILURE;
    };
    let second_root = match (value("--second-root"), value("--second-root-key")) {
        (Some(subject), Some(key)) => match stozher_core::signed::KeyId::parse(key) {
            Ok(key) => Some((subject.to_owned(), key)),
            Err(e) => {
                eprintln!("--second-root-key: {e}");
                return ExitCode::FAILURE;
            }
        },
        (None, None) => None,
        _ => {
            eprintln!("--second-root and --second-root-key are given together or not at all");
            return ExitCode::FAILURE;
        }
    };
    let seed = match keys::Seed::load(&PathBuf::from(key_path)) {
        Ok(seed) => seed,
        Err(e) => {
            eprintln!("key: {e}");
            return ExitCode::FAILURE;
        }
    };
    let ceremony = Ceremony {
        root_subject: root_subject.to_owned(),
        agent_subject: value("--agent").unwrap_or("agent:bootstrap").to_owned(),
        policy_version: value("--policy-version").unwrap_or("2026.07.1").to_owned(),
        second_root,
        core_stream: value("--core-stream").unwrap_or("kernel:core").to_owned(),
        now: stozher_kernel::clock::SystemClock.now(),
    };
    let built = match genesis::build(&seed, &ceremony) {
        Ok(built) => built,
        Err(e) => {
            eprintln!("ceremony: {e}");
            return ExitCode::FAILURE;
        }
    };
    let directory = Path::new(out);
    if let Err(e) = std::fs::create_dir_all(directory) {
        eprintln!("cannot create {out}: {e}");
        return ExitCode::FAILURE;
    }
    // A complete configuration rather than a fragment: merging one by hand is where an operator
    // drops the root they meant to enrol, and a JSON processor is one more tool the install would
    // have to require.
    let callers = list(arguments, "--caller", &["agent:gateway"]);
    let (config, credentials) = match genesis::kernel_config(
        &built,
        &genesis::Deployment {
            bind: value("--bind").unwrap_or("0.0.0.0:8787"),
            database: value("--database").unwrap_or("/var/lib/stozher/data/stozher.db"),
            kernel_seed: value("--kernel-seed").unwrap_or("/var/lib/stozher/keys/kernel.seed"),
            console_base_url: value("--console-url").unwrap_or("http://127.0.0.1:8787"),
            callers: &callers,
        },
    ) {
        Ok(built) => built,
        Err(e) => {
            eprintln!("configuration: {e}");
            return ExitCode::FAILURE;
        }
    };

    for (name, document) in [
        ("01-root-mandate.json", &built.root_mandate),
        ("02-first-policy.json", &built.first_policy),
        ("config-fragment.json", &built.config_fragment),
        ("policy-document.json", &built.policy_document),
        ("kernel-config.json", &config),
    ] {
        let canonical = match stozher_core::jcs::canonicalize(document) {
            Ok(canonical) => canonical,
            Err(e) => {
                eprintln!("canonicalizing {name}: {e}");
                return ExitCode::FAILURE;
            }
        };
        if let Err(e) = std::fs::write(directory.join(name), canonical.as_bytes()) {
            eprintln!("writing {name}: {e}");
            return ExitCode::FAILURE;
        }
    }
    println!("wrote {out}/01-root-mandate.json    (seq 0 — the interactive root mandate)");
    println!(
        "wrote {out}/02-first-policy.json    (seq 1 — the first policy, approved by the root)"
    );
    println!("wrote {out}/config-fragment.json    (policy-key and roots for the kernel config)");
    println!("wrote {out}/policy-document.json    (the signed policy, for diffing)");
    println!("wrote {out}/kernel-config.json      (a complete configuration; holds no token)");
    println!("mandate-ref {}", built.mandate_ref);
    for credential in &credentials {
        // Printed once, here, and nowhere else. The configuration holds the digest; whoever needs
        // the token is standing in front of this terminal.
        println!("caller-token {} {}", credential.subject, credential.token);
    }
    for warning in &built.warnings {
        // Not a log line at a level someone might not be reading: a ceremony finding is the kind of
        // thing an operator discovers eighteen months later, at the worst possible moment.
        eprintln!("\nWARNING: {warning}");
    }
    ExitCode::SUCCESS
}

/// Sign a gate decision (spec 06 section 1.2) and print it.
///
/// This subcommand deliberately does no network I/O and needs no kernel configuration: it reads the
/// approver's own seed file, signs, and writes the object to stdout. The approver then submits it
/// through the console. Keeping the two apart is what makes "the kernel cannot manufacture an
/// approval" a structural fact rather than a policy the kernel promises to follow.
fn decide(arguments: &[String]) -> ExitCode {
    let value = |name: &str| -> Option<&str> {
        arguments
            .iter()
            .position(|a| a == name)
            .and_then(|i| arguments.get(i + 1))
            .map(String::as_str)
    };
    let present = |name: &str| arguments.iter().any(|a| a == name);

    let (Some(request_hash), Some(key_path)) = (value("--request"), value("--key")) else {
        eprintln!("decide requires --request <64 hex> and --key <path>");
        return ExitCode::FAILURE;
    };
    if !stozher_core::crypto::is_digest_hex(request_hash) {
        eprintln!("--request must be 64 lowercase hex digits");
        return ExitCode::FAILURE;
    }
    let deny = value("--deny");
    if present("--approve") == deny.is_some() {
        // Not a default. A decision the operator did not state is not a decision.
        eprintln!("decide requires exactly one of --approve or --deny <reason>");
        return ExitCode::FAILURE;
    }
    if let Some(reason) = deny {
        if reason.trim().is_empty() {
            eprintln!("a denial must state why: the reason is what the calling agent is owed");
            return ExitCode::FAILURE;
        }
    }
    let minutes = value("--minutes")
        .and_then(|m| m.parse::<i64>().ok())
        .unwrap_or(DEFAULT_APPROVAL_MINUTES);
    if minutes <= 0 {
        eprintln!("--minutes must be positive");
        return ExitCode::FAILURE;
    }
    let role = value("--role")
        .and_then(|r| r.parse::<u32>().ok())
        .unwrap_or(1);
    let index = value("--index")
        .and_then(|i| i.parse::<u32>().ok())
        .unwrap_or(0);

    let seed = match keys::Seed::load(&PathBuf::from(key_path)) {
        Ok(seed) => seed,
        Err(e) => {
            eprintln!("key: {e}");
            return ExitCode::FAILURE;
        }
    };
    let key = match seed.derive(role, index) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("derivation: {e}");
            return ExitCode::FAILURE;
        }
    };
    let now = stozher_kernel::clock::SystemClock.now();
    let not_after = match stozher_kernel::clock::shift(&now, minutes * 60) {
        Ok(not_after) => not_after,
        Err(e) => {
            eprintln!("clock: {e}");
            return ExitCode::FAILURE;
        }
    };
    let decision = key.sign(&serde_json::json!({
        "v": stozher_core::VERSION,
        "kind": "gate-decision",
        "request-hash": request_hash,
        "decision": if deny.is_some() { "deny" } else { "approve" },
        "decided-at": now,
        "not-after": not_after,
        // §06 §1.2: the default profile MUST set this true. One signature is one action.
        "single-use": true,
        "reason": deny.map_or(serde_json::Value::Null, serde_json::Value::from)
    }));
    match decision.and_then(|object| stozher_core::jcs::canonicalize(&object)) {
        Ok(canonical) => {
            println!("{canonical}");
            eprintln!("signed by {} — valid until {not_after}", key.id());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("signing: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Sign a standing mandate for a component, in the root's own process.
///
/// This is the step that makes "point your agent at the gateway" possible: a gateway with no
/// resolvable mandate refuses the session at connect time (§10 §1.4), and the mandate cannot come
/// from the gateway itself because §03 §1 forbids self-grant.
fn grant(arguments: &[String]) -> ExitCode {
    let value = |name: &str| value(arguments, name);
    let (Some(key_path), Some(root_subject), Some(grantee), Some(grantee_key), Some(out)) = (
        value("--key"),
        value("--root"),
        value("--grantee"),
        value("--grantee-key"),
        value("--out"),
    ) else {
        eprintln!(
            "grant requires --key <path>, --root <human:name>, --grantee <subject>, \
             --grantee-key <ed25519:...> and --out <path>"
        );
        return ExitCode::FAILURE;
    };
    let grantee_key = match stozher_core::signed::KeyId::parse(grantee_key) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("--grantee-key: {e}");
            return ExitCode::FAILURE;
        }
    };
    let Some(days) = value("--days")
        .map_or(Some(30), |d| d.parse::<i64>().ok())
        .filter(|d| *d > 0)
    else {
        eprintln!("--days must be a positive integer");
        return ExitCode::FAILURE;
    };
    let seed = match keys::Seed::load(&PathBuf::from(key_path)) {
        Ok(seed) => seed,
        Err(e) => {
            eprintln!("key: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mandate = genesis::standing_grant(
        &seed,
        &genesis::Grant {
            root_subject,
            grantee_subject: grantee,
            grantee_key: &grantee_key,
            days,
            components: list(arguments, "--components", &["gateway"]),
            actions: list(arguments, "--actions", &["*"]),
            classes: list(
                arguments,
                "--classes",
                &["read", "benign", "consequential", "prohibited"],
            ),
            resources: list(arguments, "--resources", &["*"]),
            now: &stozher_kernel::clock::SystemClock.now(),
        },
    );
    let mandate = match mandate {
        Ok(mandate) => mandate,
        Err(e) => {
            eprintln!("grant: {e}");
            return ExitCode::FAILURE;
        }
    };
    let canonical = match stozher_core::jcs::canonicalize(&mandate) {
        Ok(canonical) => canonical,
        Err(e) => {
            eprintln!("canonicalizing the mandate: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = std::fs::write(out, canonical.as_bytes()) {
        eprintln!("writing {out}: {e}");
        return ExitCode::FAILURE;
    }
    let id = match stozher_core::signed::object_id(&mandate) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("mandate id: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!("wrote {out}");
    println!("mandate-ref  {id}");
    println!("not-after    {}", mandate["not-after"]);
    ExitCode::SUCCESS
}

/// Take a consistent snapshot of the store without stopping the service.
///
/// Reads the database path out of the deployment's own configuration, so a backup cannot be taken
/// of a file the kernel is not actually using — which is the way backups turn out to have been
/// empty for eight months.
fn snapshot(arguments: &[String]) -> ExitCode {
    let (Some(config_path), Some(out)) = (value(arguments, "--config"), value(arguments, "--out"))
    else {
        eprintln!("snapshot requires --config <path> and --out <path>");
        return ExitCode::FAILURE;
    };
    let config = match Config::load(Path::new(config_path)) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("configuration: {e}");
            return ExitCode::FAILURE;
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("cannot start the async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(stozher_kernel::Store::snapshot_to(
        &config.database,
        Path::new(out),
    )) {
        Ok(()) => {
            println!("wrote {out}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("snapshot: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Read a document from `--file`, or from standard input when no path is given.
fn document(arguments: &[String]) -> std::io::Result<Vec<u8>> {
    match value(arguments, "--file") {
        Some(path) => std::fs::read(path),
        None => {
            use std::io::Read;
            let mut buffer = Vec::new();
            std::io::stdin().read_to_end(&mut buffer)?;
            Ok(buffer)
        }
    }
}

/// The bearer credential, by the *name* of the variable holding it — never as an argument.
///
/// A token on a command line is in the shell history, in `ps` output for every user on the box, and
/// in whatever collects the operator's terminal. Naming the variable costs one line of setup and
/// removes all three.
fn credential(arguments: &[String]) -> Option<String> {
    let variable = value(arguments, "--token-env").unwrap_or("STOZHER_KERNEL_TOKEN");
    std::env::var(variable)
        .ok()
        .map(|token| token.trim().to_owned())
        .filter(|token| !token.is_empty())
        .or_else(|| {
            eprintln!("{variable} is unset — the kernel would refuse the request");
            None
        })
}

/// Submit an already-signed ingest request. Prints the kernel's answer and exits non-zero on refusal.
fn submit(arguments: &[String]) -> ExitCode {
    let Some(url) = value(arguments, "--url") else {
        eprintln!("submit requires --url <base>");
        return ExitCode::FAILURE;
    };
    let (Some(token), Ok(body)) = (credential(arguments), document(arguments)) else {
        return ExitCode::FAILURE;
    };
    match stozher_kernel::operator::ingest(url, &token, &body) {
        Ok(answer) => {
            println!("{}", answer.body);
            if answer.ok() {
                ExitCode::SUCCESS
            } else {
                eprintln!("the kernel refused it ({})", answer.status);
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("submit: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Hand a signed decision to the console. The decision is read, never produced, here.
fn answer(arguments: &[String]) -> ExitCode {
    let (Some(url), Some(request_hash)) =
        (value(arguments, "--url"), value(arguments, "--request"))
    else {
        eprintln!("answer requires --url <base> and --request <64 hex>");
        return ExitCode::FAILURE;
    };
    let (Some(token), Ok(body)) = (credential(arguments), document(arguments)) else {
        return ExitCode::FAILURE;
    };
    let Ok(decision) = String::from_utf8(body) else {
        eprintln!("the decision must be UTF-8 JSON");
        return ExitCode::FAILURE;
    };
    match stozher_kernel::operator::decide(url, &token, request_hash, decision.trim()) {
        Ok(answer) => {
            println!("{}", answer.body);
            if answer.ok() {
                ExitCode::SUCCESS
            } else {
                eprintln!("the console refused it ({})", answer.status);
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("answer: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Block until the kernel answers `/health`, or give up and say so.
///
/// An install script that raced the service would fail with whatever refusal a half-started kernel
/// happens to produce, which is the least informative possible way to learn that it was too early.
fn await_health(arguments: &[String]) -> ExitCode {
    let Some(url) = value(arguments, "--url") else {
        eprintln!("await-health requires --url <base>");
        return ExitCode::FAILURE;
    };
    let seconds = value(arguments, "--timeout")
        .and_then(|t| t.parse::<u64>().ok())
        .unwrap_or(60);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
    loop {
        if let Ok(answer) = stozher_kernel::operator::health(url) {
            if answer.ok() {
                println!("{url} is up");
                return ExitCode::SUCCESS;
            }
        }
        if std::time::Instant::now() >= deadline {
            eprintln!("{url} did not answer /health within {seconds}s");
            return ExitCode::FAILURE;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

fn run(config_path: Option<PathBuf>, mode: Mode) -> ExitCode {
    let Some(config_path) = config_path else {
        eprintln!("--config <path> is required");
        return ExitCode::FAILURE;
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
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
    // An empty store is a refusal, not a pass. Nothing the box holds distinguishes "never
    // bootstrapped" from "restored over the top of the records", and §05 §5.2's ceremony means a
    // deployment that has ever run holds at least two envelopes — so "no streams" on a box that is
    // meant to hold an audit trail is a data-loss incident. `deploy/bin/stozher-restore` branches on
    // this exit code, and a green line over nothing is the one answer that would let a bad restore
    // through: an unavailable audit is recoverable, an audit wrongly reported intact is not.
    //
    // It is deliberately not the same message as a chain that failed verification. "Your records
    // are wrong" and "you have no records" send an operator to different places.
    if streams.is_empty() {
        eprintln!(
            "no streams: this store holds no audit trail at all. That is not a verified chain — \
             it is an empty one. If this box has ever run, the records are missing; if it has not, \
             it has not been bootstrapped yet."
        );
        return ExitCode::FAILURE;
    }
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
    // §04 §4.6: the kernel emits a checkpoint per stream at least every `checkpoint-interval`, so a
    // rebuilt chain always contradicts a published head. The service owns the loop; it is not left
    // to an operator to remember.
    // Both loops, including the decay sweep the deployment used to have to schedule itself. They
    // live behind one function so a test can start exactly what the service starts.
    let maintenance = kernel.spawn_maintenance();

    let app = http::router(Arc::clone(&kernel));
    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutting down");
    };
    let outcome = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await;
    maintenance.abort();
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("server failed: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Run `spec/08 §4` against a component and print the result.
///
/// The run happens against a kernel this process builds in memory and discards — see
/// [`stozher_kernel::harness`]. Nothing about the operator's deployment is read and nothing about it
/// is touched, which is what makes a certification exercise safe to perform against a manifest that
/// arrived by e-mail from a stranger.
///
/// The output is the evidence document and nothing else, so it can be piped. A green run is not a
/// registration: `spec/08 §3.1` wants a human signature over the manifest hash, and this prints what
/// that human is being asked to sign over rather than acting for them.
fn conformance(arguments: &[String]) -> ExitCode {
    let value = |name: &str| -> Option<&str> {
        arguments
            .iter()
            .position(|a| a == name)
            .and_then(|i| arguments.get(i + 1))
            .map(String::as_str)
    };
    let (Some(manifest_path), Some(command)) = (value("--manifest"), value("--component")) else {
        eprintln!("conformance requires --manifest <path> and --component <command>");
        return ExitCode::FAILURE;
    };
    let mut words = command.split_whitespace().map(str::to_owned);
    let Some(program) = words.next() else {
        eprintln!("--component names no program");
        return ExitCode::FAILURE;
    };
    let component_arguments: Vec<String> = words.collect();

    let manifest = match std::fs::read_to_string(manifest_path)
        .map_err(|e| e.to_string())
        .and_then(|text| {
            serde_json::from_str::<serde_json::Value>(&text).map_err(|e| e.to_string())
        }) {
        Ok(document) => match stozher_kernel::manifest::Manifest::parse(&document) {
            Ok(manifest) => manifest,
            Err(e) => {
                eprintln!("the manifest is not one this kernel would register: {e}");
                return ExitCode::FAILURE;
            }
        },
        Err(e) => {
            eprintln!("cannot read {manifest_path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let vectors = value("--vectors").unwrap_or("spec/vectors");
    let corpus = match load_corpus(Path::new(vectors)) {
        Ok(corpus) => corpus,
        Err(e) => {
            eprintln!("cannot read the vector corpus at {vectors}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let at = match value("--at") {
        Some(at) => at.to_owned(),
        None => Clock::now(&stozher_kernel::clock::SystemClock),
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("cannot start the async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(async move {
        let driver =
            match stozher_kernel::driver::StdioDriver::spawn(&program, &component_arguments) {
                Ok(driver) => driver,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::FAILURE;
                }
            };
        let plan = stozher_kernel::harness::Plan {
            manifest: &manifest,
            corpus,
            at,
        };
        let outcome = stozher_kernel::harness::run(&driver, &plan).await;
        driver.shutdown().await;
        match outcome {
            Ok(run) => {
                match serde_json::to_string_pretty(&run.evidence()) {
                    Ok(evidence) => println!("{evidence}"),
                    Err(e) => eprintln!("the result would not serialize: {e}"),
                }
                if run.is_green() {
                    ExitCode::SUCCESS
                } else {
                    // Red is the default and the exit code says so, because a harness whose failure
                    // an operator has to notice by reading is a harness that will pass in a script.
                    eprintln!("outstanding: {:?}", run.outstanding());
                    ExitCode::FAILURE
                }
            }
            Err(e) => {
                eprintln!("the run could not be performed: {e}");
                ExitCode::FAILURE
            }
        }
    })
}

/// Every `spec/vectors/` document that declares a kind.
///
/// Read from a directory rather than compiled in, so an operator certifying a component can point
/// the harness at the corpus that component was written against and see the mismatch, instead of
/// this binary silently certifying against its own.
fn load_corpus(directory: &Path) -> std::io::Result<Vec<serde_json::Value>> {
    let mut documents = Vec::new();
    for entry in std::fs::read_dir(directory)? {
        let path = entry?.path();
        if path.extension().and_then(std::ffi::OsStr::to_str) != Some("json") {
            continue;
        }
        let text = std::fs::read_to_string(&path)?;
        if let Ok(document) = serde_json::from_str::<serde_json::Value>(&text) {
            if document.get("kind").is_some() {
                documents.push(document);
            }
        }
    }
    Ok(documents)
}
