//! The Stozher kernel binary: `serve`, `keygen`, `identity`, `token`, `genesis`, `verify`, `decide`,
//! `revoke`, `conformance`.
//!
//! Argument parsing is hand-written. The surface is a handful of subcommands and flags; a parser
//! generator would be a dependency in a product whose pitch is a minimal auditable surface
//! (ADR-0003), and there is nothing here it would make clearer.
//!
//! Nine subcommands — `keygen`, `identity`, `token`, `genesis`, `grant`, `decide`, `revoke`,
//! `policy-request`, `policy-sign` — open no socket, read no configuration and touch no database. They are the
//! operator's half of the install and of every authority decision after it, and they run on the
//! operator's own machine so that a private seed never has to exist on the server.

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
                          [--classes <a,b>] [--resources <a,b>] [--config <path>]
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
                          [--minutes <n>] [--role <n>] [--index <n>] [--config <path>]
                          sign a gate decision and print it; submit it to
                          POST /console/pending/<request-hash>/decide
  stozher-kernel revoke   --mandate <64 hex> --key <path> [--reason <text>]
                          [--role <n>] [--index <n>] [--config <path>]
                          sign a revocation and print it (spec 03 section 7)
  stozher-kernel submit-revocation --url <base> [--file <path>] [--token-env <VAR>]
                          hand an already-signed revocation to POST /v1/revocations
  stozher-kernel policy-request --document <path> --subject <agent:name> --key <path>
                          --mandate <64 hex> --in-force <version> --out <path>
                          [--minutes <n>] [--role <n>] [--index <n>] [--config <path>]
                          build the action request that asks to publish a policy (spec 05 section 5)
  stozher-kernel park     --url <base> [--file <path>] [--token-env <VAR>]
                          hand an action request to the pending queue
  stozher-kernel policy-current --url <base> [--token-env <VAR>]
                          print the policy version in force — what --in-force takes
  stozher-kernel policy-draft --url <base> --version <new> --out <path> [--token-env <VAR>]
                          write the policy in force out as a draft of <new>, signature stripped
  stozher-kernel policy-sign --document <path> --key <path> --out <path>
                          sign an edited draft with the organization policy key (role 4')
  stozher-kernel policy-publish --url <base> --request <path> --document <path> --key <path>
                          [--stream <name>] [--role <n>] [--index <n>] [--token-env <VAR>]
                          [--config <path>]
                          publish the approved policy: read the decision, extend the chain, submit
  stozher-kernel root-request --requester <human:name> --key <path> --mandate <64 hex>
                          --in-force <version> --out <path>
                          (--enrol <ed25519:...> --subject <human:name> | --retire <ed25519:...>)
                          [--evidence-out <path>] [--minutes <n>] [--config <path>]
                          build the action request that changes the root set (spec 03 section 6)
  stozher-kernel root-publish --url <base> --request <path> --key <path>
                          [--evidence <path>] [--stream <name>] [--token-env <VAR>] [--config <path>]
                          record the approved root-set change
  stozher-kernel effect-request --action <kernel.x> --target <t> --requester <subject>
                          --key <path> --mandate <64 hex> --in-force <version> --out <path>
                          (--args-hash <64 hex> | --args-from <path>)
                          [--classification <c>] [--minutes <n>] [--config <path>]
                          the general form: any gated kernel action, incl. conformance_run and
                          register_component (spec 08 section 3.3)
  stozher-kernel effect-publish --url <base> --request <path> --key <path>
                          [--evidence <path>] [--schema <s>] [--retain-days <n>] [--stream <name>]
                          [--token-env <VAR>]
                          record the approved action, with its evidence as the payload
  stozher-kernel conformance --manifest <path> --component <command>
                          [--vectors <dir>] [--at <timestamp>]
                          run spec 08 section 4 against a component and print the result;
                          exits non-zero unless every group passed
  stozher-kernel help

The kernel refuses to start if its seed file is readable by anyone but its owner (spec 09 section 8).

`keygen`, `identity`, `token`, `genesis`, `grant`, `decide`, `revoke`, `policy-request` and
`policy-sign` open no socket and read no configuration: they run in the operator's own process, on the operator's own
machine, so a private seed never has to exist on the server. `genesis` prints two ordinary
POST /v1/ingest bodies; nothing about them is privileged and every ingest check runs over them.

Publishing a policy version after the install is six commands, and the split is the same one:
`policy-draft` fetches the document in force to edit, `policy-sign` signs the edit with the
organization's policy key, `policy-request` builds the question offline, `park` puts it in the queue, a root answers it with
`decide` + `answer`, and `policy-publish` records the result. The command that holds the root key
never opens a socket; the command that opens the socket holds no root key.

`decide` reads the approver's own key file, and `revoke` the revoker's. The service never holds
either, and has no route that produces such a signature, so it cannot manufacture an approval or a
revocation — the friction here is what buys that.

A root enrolled by `genesis` holds its key at role 0': approve or revoke with `--role 0 --index 0`.
A component's own grantor, revoking something it delegated, signs at the role that grant was made
under.

`grant`, `decide` and `revoke` take an optional `--config`, and only a deployment running a
`clock-advance` needs it (ADR-0023): the kernel is then ahead of the host, so a mandate or an
approval stamped with real time is expired before it can be submitted, and a revocation is stamped
before the issue it names. `genesis` deliberately has no such flag — its two documents are the
deployment's founding record and outlive any demonstration.
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
        "revoke" => revoke(&arguments),
        "submit-revocation" => submit_revocation(&arguments),
        "policy-request" => policy_request(&arguments),
        "park" => park(&arguments),
        "policy-current" => policy_current(&arguments),
        "policy-draft" => policy_draft(&arguments),
        "policy-sign" => policy_sign(&arguments),
        "policy-publish" => policy_publish(&arguments),
        "root-request" => root_request(&arguments),
        "root-publish" => root_publish(&arguments),
        "effect-request" => effect_request(&arguments),
        "effect-publish" => effect_publish(&arguments),
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
/// The clock these offline commands stamp documents with.
///
/// Without `--config` this is the host's. With it, the deployment's — which matters only when that
/// deployment declares a `clock-advance` (ADR-0023): the kernel would then be running ahead, and a
/// mandate or an approval minted on real time is expired before it can be submitted. An auditor
/// demonstrating retention hits exactly that.
///
/// `genesis` deliberately does **not** take this. Its documents outlive the demonstration — the root
/// mandate and the first policy are the deployment's founding record, and stamping them with a time
/// chosen to make decay observable would put the advance into the one pair of documents that must
/// mean what they say for the deployment's whole life.
fn offline_clock(arguments: &[String]) -> Result<stozher_kernel::clock::SharedClock, String> {
    let Some(path) = value(arguments, "--config") else {
        return Ok(std::sync::Arc::new(stozher_kernel::clock::SystemClock));
    };
    let config = stozher_kernel::Config::load(std::path::Path::new(path))
        .map_err(|e| format!("reading {path}: {e}"))?;
    stozher_kernel::clock::from_config(&config).map_err(|e| format!("clock: {e}"))
}

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
    let key = match seed_key(arguments, key_path, 1) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let now = match offline_clock(arguments) {
        Ok(clock) => clock.now(),
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
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
    let grant_now = match offline_clock(arguments) {
        Ok(clock) => clock.now(),
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
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
            now: &grant_now,
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

/// Sign a revocation, in the revoker's own process — §03 §7.
///
/// This command exists because the revocation *object* is now nested inside the envelope. While the
/// envelope was itself the revocation, its signature covered `stream`, `seq` and `prev-hash` —
/// values only the kernel knows at append — so the revoker's seed and a connection to the kernel had
/// to meet in one process. There was therefore no `revoke` command for the whole life of the
/// product: the person most likely to need one is a root whose seed exists on a single laptop, and
/// that is exactly the person the old shape excluded.
fn revoke(arguments: &[String]) -> ExitCode {
    let value = |name: &str| value(arguments, name);
    let (Some(mandate), Some(key_path)) = (value("--mandate"), value("--key")) else {
        eprintln!("revoke requires --mandate <64 hex> and --key <path>");
        return ExitCode::FAILURE;
    };
    if !stozher_core::crypto::is_digest_hex(mandate) {
        eprintln!("--mandate must be 64 lowercase hex digits");
        return ExitCode::FAILURE;
    }
    let key = match seed_key(arguments, key_path, 1) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    // Now, and not a flag. §03 §7 refuses a `revoked-at` earlier than the mandate's `issued-at`
    // outright — backdating a revocation to erase a window of authority is a rejection, not a
    // workflow — and a revocation dated in the future is a mandate that is still live.
    let now = match offline_clock(arguments) {
        Ok(clock) => clock.now(),
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let mut object = serde_json::Map::new();
    object.insert("v".to_owned(), stozher_core::VERSION.into());
    object.insert("kind".to_owned(), "revocation".into());
    object.insert("revokes".to_owned(), mandate.into());
    object.insert("revoked-at".to_owned(), now.clone().into());
    // §03 §7: `reason` is present in the envelope iff it is present in the object, so an absent
    // reason is an absent member — not a null, which the projection could not match.
    if let Some(reason) = value("--reason") {
        if reason.trim().is_empty() {
            eprintln!("--reason, if given, must say something");
            return ExitCode::FAILURE;
        }
        object.insert("reason".to_owned(), reason.into());
    }
    match key
        .sign(&serde_json::Value::Object(object))
        .and_then(|object| stozher_core::jcs::canonicalize(&object))
    {
        Ok(canonical) => {
            println!("{canonical}");
            eprintln!("signed by {} — revokes {mandate} at {now}", key.id());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("signing: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Load a seed and derive the key `--role`/`--index` name, defaulting to `default_role` at index 0.
///
/// The three commands that sign something in the operator's own process all need this, and the
/// default role differs between them: an approver and a revoker are usually the human root at `0'`,
/// a publishing component is an agent subject at `1'`. Passing the default in keeps that choice at
/// the call site, where the reader can see which one this command means.
fn seed_key(
    arguments: &[String],
    key_path: &str,
    default_role: u32,
) -> std::result::Result<keys::SigningKey, String> {
    let role = value(arguments, "--role")
        .and_then(|r| r.parse::<u32>().ok())
        .unwrap_or(default_role);
    let index = value(arguments, "--index")
        .and_then(|i| i.parse::<u32>().ok())
        .unwrap_or(0);
    let seed = keys::Seed::load(&PathBuf::from(key_path)).map_err(|e| format!("key: {e}"))?;
    seed.derive(role, index)
        .map_err(|e| format!("derivation: {e}"))
}

/// Build the action request that asks to publish a policy version — §05 §5.
///
/// Offline, and it produces no signature: an action request is not a signed object, it is the object
/// whose `object-hash` an approver signs *over* (§06 §1.1). It is written to a file rather than
/// printed and re-derived later because it carries a `nonce`, so rebuilding it would produce a
/// different `request-hash` and orphan the approval that named the first one.
///
/// The whole ceremony this begins exists because §05 §5 refuses a privileged path: publishing policy
/// is a `consequential` effect, judged by the policy already in force and approved by a named human.
/// The kernel's own bar cannot be lowered by the document being installed.
fn policy_request(arguments: &[String]) -> ExitCode {
    let value = |name: &str| value(arguments, name);
    let (
        Some(document_path),
        Some(subject),
        Some(key_path),
        Some(mandate),
        Some(in_force),
        Some(out),
    ) = (
        value("--document"),
        value("--subject"),
        value("--key"),
        value("--mandate"),
        value("--in-force"),
        value("--out"),
    )
    else {
        eprintln!(
            "policy-request requires --document <path>, --subject <agent:name>, --key <path>, \
             --mandate <64 hex>, --in-force <version> and --out <path>"
        );
        return ExitCode::FAILURE;
    };
    if !stozher_core::crypto::is_digest_hex(mandate) {
        eprintln!("--mandate must be the 64-hex id of the mandate the publisher acts under");
        return ExitCode::FAILURE;
    }
    let document: serde_json::Value = match std::fs::read(document_path)
        .map_err(|e| e.to_string())
        .and_then(|bytes| serde_json::from_slice(&bytes).map_err(|e| e.to_string()))
    {
        Ok(document) => document,
        Err(e) => {
            eprintln!("reading {document_path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let Some(version) = document["policy-version"].as_str() else {
        eprintln!("{document_path} carries no policy-version — it is not a policy document");
        return ExitCode::FAILURE;
    };
    if version == in_force {
        // Not pedantry. §05 §5 rule 1 makes `policy-version` the *outgoing* version and
        // `execution.target` the incoming one; equal values mean the operator passed the same
        // version twice, and the resulting envelope claims the change was judged by itself.
        eprintln!(
            "--in-force is {in_force}, which is the version this document installs: \
             pass the version currently in force (GET /v1/policy/current)"
        );
        return ExitCode::FAILURE;
    }
    let document_hash = match stozher_core::jcs::object_hash(&document) {
        Ok(hash) => hash,
        Err(e) => {
            eprintln!("hashing the document: {e}");
            return ExitCode::FAILURE;
        }
    };
    let publisher = match seed_key(arguments, key_path, 1) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let now = match offline_clock(arguments) {
        Ok(clock) => clock.now(),
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let minutes = value("--minutes")
        .and_then(|m| m.parse::<i64>().ok())
        .unwrap_or(60);
    let not_after = match stozher_kernel::clock::shift(&now, minutes * 60) {
        Ok(not_after) => not_after,
        Err(e) => {
            eprintln!("clock: {e}");
            return ExitCode::FAILURE;
        }
    };
    let nonce = match genesis::request_nonce() {
        Ok(nonce) => nonce,
        Err(e) => {
            eprintln!("nonce: {e}");
            return ExitCode::FAILURE;
        }
    };
    let request = serde_json::json!({
        "v": stozher_core::VERSION,
        "kind": "action-request",
        "requested-at": now,
        "subject": subject,
        "key": publisher.id().as_str(),
        "component": "kernel",
        "mandate-ref": mandate,
        "policy-version": in_force,
        "classification": "consequential",
        "action": "kernel.publish_policy",
        "target": format!("policy:{version}"),
        "args-hash": document_hash,
        "nonce": nonce,
        "not-after": not_after
    });
    let (canonical, hash) = match (
        stozher_core::jcs::canonicalize(&request),
        stozher_core::jcs::object_hash(&request),
    ) {
        (Ok(canonical), Ok(hash)) => (canonical, hash),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("canonicalizing: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = std::fs::write(out, &canonical) {
        eprintln!("writing {out}: {e}");
        return ExitCode::FAILURE;
    }
    println!("{hash}");
    eprintln!("wrote {out} — park it, have a root approve {hash}, then policy-publish");
    ExitCode::SUCCESS
}

/// Write the policy in force out as a draft of the next version, for a human to edit.
///
/// The starting point for a change has to be the document that is actually in force, not the
/// baseline the ceremony shipped: a deployment three versions in would otherwise silently revert
/// every classification it has added. The signature is stripped, because what comes back is not a
/// policy — it is a file to edit and then sign with [`policy_sign`].
fn policy_draft(arguments: &[String]) -> ExitCode {
    let (Some(url), Some(version), Some(out)) = (
        value(arguments, "--url"),
        value(arguments, "--version"),
        value(arguments, "--out"),
    ) else {
        eprintln!("policy-draft requires --url <base>, --version <new> and --out <path>");
        return ExitCode::FAILURE;
    };
    let Some(token) = credential(arguments) else {
        return ExitCode::FAILURE;
    };
    let answer = match stozher_kernel::operator::read(url, &token, "v1/policy/current") {
        Ok(answer) if answer.ok() => answer,
        Ok(answer) => {
            eprintln!("the kernel refused it ({}): {}", answer.status, answer.body);
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("policy-draft: {e}");
            return ExitCode::FAILURE;
        }
    };
    let Ok(mut document) = serde_json::from_str::<serde_json::Value>(&answer.body) else {
        eprintln!("the kernel's policy document is not JSON");
        return ExitCode::FAILURE;
    };
    let Some(map) = document.as_object_mut() else {
        eprintln!("the kernel's policy document is not an object");
        return ExitCode::FAILURE;
    };
    let in_force = map
        .get("policy-version")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("<unknown>")
        .to_owned();
    if in_force == version {
        eprintln!("{version} is already in force — a draft of it would replace it with itself");
        return ExitCode::FAILURE;
    }
    map.remove("sig");
    map.insert(
        "policy-version".to_owned(),
        serde_json::Value::from(version),
    );
    match serde_json::to_string_pretty(&document) {
        Ok(text) => {
            if let Err(e) = std::fs::write(out, format!("{text}\n")) {
                eprintln!("writing {out}: {e}");
                return ExitCode::FAILURE;
            }
            eprintln!("wrote {out} from {in_force} — edit it, then policy-sign it");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("rendering the draft: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Sign a policy document with the organization's policy key — §05 §2.
///
/// Offline, in the operator's own process. The kernel verifies every policy document against the
/// `policy-key` in its configuration and holds no such key itself, so this is the only place a
/// policy version can be made valid — and, like `decide` and `revoke`, it opens no socket.
fn policy_sign(arguments: &[String]) -> ExitCode {
    let (Some(document_path), Some(key_path), Some(out)) = (
        value(arguments, "--document"),
        value(arguments, "--key"),
        value(arguments, "--out"),
    ) else {
        eprintln!("policy-sign requires --document <path>, --key <path> and --out <path>");
        return ExitCode::FAILURE;
    };
    let document: serde_json::Value = match std::fs::read(document_path)
        .map_err(|e| e.to_string())
        .and_then(|bytes| serde_json::from_slice(&bytes).map_err(|e| e.to_string()))
    {
        Ok(document) => document,
        Err(e) => {
            eprintln!("reading {document_path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    if document.get("sig").is_some() {
        // Signing over a document that still carries a signature would sign the old signature in
        // as data. `policy-draft` strips it; a document that has one is one nobody edited.
        eprintln!("{document_path} still carries a sig — sign the draft, not a published document");
        return ExitCode::FAILURE;
    }
    if document["policy-version"]
        .as_str()
        .unwrap_or_default()
        .is_empty()
    {
        eprintln!("{document_path} carries no policy-version");
        return ExitCode::FAILURE;
    }
    // Role 4' — the organization's policy key (§01 §6), not the root and not the agent subject.
    let key = match seed_key(arguments, key_path, keys::ROLE_ORG_POLICY) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    match key
        .sign(&document)
        .and_then(|signed| stozher_core::jcs::canonicalize(&signed))
    {
        Ok(canonical) => {
            if let Err(e) = std::fs::write(out, format!("{canonical}\n")) {
                eprintln!("writing {out}: {e}");
                return ExitCode::FAILURE;
            }
            eprintln!("wrote {out} — signed by {}", key.id());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("signing: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Print the policy version currently in force, and nothing else.
///
/// `policy-request` needs it and cannot know it: §05 §5 rule 1 makes the envelope's
/// `policy-version` the **outgoing** version, so the change is judged by the policy it replaces
/// rather than by itself. A script that assumed the last version it published is still in force
/// would be wrong the first time two people published.
fn policy_current(arguments: &[String]) -> ExitCode {
    let Some(url) = value(arguments, "--url") else {
        eprintln!("policy-current requires --url <base>");
        return ExitCode::FAILURE;
    };
    let Some(token) = credential(arguments) else {
        return ExitCode::FAILURE;
    };
    match stozher_kernel::operator::read(url, &token, "v1/policy/current") {
        Ok(answer) if answer.ok() => {
            match serde_json::from_str::<serde_json::Value>(&answer.body)
                .ok()
                .and_then(|document| document["policy-version"].as_str().map(str::to_owned))
            {
                Some(version) => {
                    println!("{version}");
                    ExitCode::SUCCESS
                }
                None => {
                    eprintln!("the kernel's policy document carries no policy-version");
                    ExitCode::FAILURE
                }
            }
        }
        Ok(answer) => {
            eprintln!("the kernel refused it ({}): {}", answer.status, answer.body);
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("policy-current: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Hand an action request to the pending queue. It appends nothing and permits nothing.
fn park(arguments: &[String]) -> ExitCode {
    let Some(url) = value(arguments, "--url") else {
        eprintln!("park requires --url <base>");
        return ExitCode::FAILURE;
    };
    let (Some(token), Ok(body)) = (credential(arguments), document(arguments)) else {
        return ExitCode::FAILURE;
    };
    match stozher_kernel::operator::park(url, &token, &body) {
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
            eprintln!("park: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Publish a policy version: read the human's decision, extend the chain, submit — §05 §5.
///
/// This is the half that needs the network, and it is deliberately the half that holds **no root
/// key**. It reads two facts it cannot know offline — the decision a named human recorded, and the
/// head of the stream the envelope must extend — signs the envelope with the *publishing subject's*
/// key, and submits it through `POST /v1/ingest` like anything else. The authority is the approval
/// inside; this command cannot manufacture one and does not try.
fn policy_publish(arguments: &[String]) -> ExitCode {
    let value = |name: &str| value(arguments, name);
    let (Some(url), Some(request_path), Some(document_path), Some(key_path)) = (
        value("--url"),
        value("--request"),
        value("--document"),
        value("--key"),
    ) else {
        eprintln!(
            "policy-publish requires --url <base>, --request <path>, --document <path> and \
             --key <path>"
        );
        return ExitCode::FAILURE;
    };
    let Some(token) = credential(arguments) else {
        return ExitCode::FAILURE;
    };
    let stream = value("--stream").unwrap_or("kernel:core");

    let read_json = |path: &str| -> std::result::Result<serde_json::Value, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("reading {path}: {e}"))?;
        serde_json::from_slice(&bytes).map_err(|e| format!("{path} is not JSON: {e}"))
    };
    let (request, document) = match (read_json(request_path), read_json(document_path)) {
        (Ok(request), Ok(document)) => (request, document),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let request_hash = match stozher_core::jcs::object_hash(&request) {
        Ok(hash) => hash,
        Err(e) => {
            eprintln!("hashing the request: {e}");
            return ExitCode::FAILURE;
        }
    };
    // The document the approval named, re-derived from the file rather than trusted from the
    // request: if they differ, the operator is about to publish bytes nobody approved.
    let document_hash = match stozher_core::jcs::object_hash(&document) {
        Ok(hash) => hash,
        Err(e) => {
            eprintln!("hashing the document: {e}");
            return ExitCode::FAILURE;
        }
    };
    if request["args-hash"].as_str() != Some(document_hash.as_str()) {
        eprintln!(
            "{document_path} is not the document {request_path} asks to publish: \
             the request commits to {}, this file hashes to {document_hash}",
            request["args-hash"].as_str().unwrap_or("nothing")
        );
        return ExitCode::FAILURE;
    }

    let decision = match fetch_decision(url, &token, &request_hash) {
        Ok(decision) => decision,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let publisher = match seed_key(arguments, key_path, 1) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let now = match offline_clock(arguments) {
        Ok(clock) => clock.now(),
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let retain_until = match stozher_kernel::clock::shift(&now, 365 * 86_400) {
        Ok(retain_until) => retain_until,
        Err(e) => {
            eprintln!("clock: {e}");
            return ExitCode::FAILURE;
        }
    };

    // The kernel's core stream has other writers — gate decisions, revocations, checkpoints — so
    // losing the race is ordinary and is retried rather than reported. A retry re-signs, because
    // `seq` and `prev-hash` are inside the signed bytes.
    const ATTEMPTS: usize = 4;
    let mut last = String::new();
    for attempt in 0..ATTEMPTS {
        let (seq, prev) = match head_of(url, &token, stream) {
            Ok(head) => head,
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::FAILURE;
            }
        };
        let envelope = publisher.sign(&serde_json::json!({
            "v": stozher_core::VERSION,
            "kind": "policy-change",
            "emitted-at": now,
            "stream": stream,
            "seq": seq,
            "prev-hash": prev,
            "identity": {
                "subject": request["subject"],
                "key": publisher.id().as_str(),
                "component": "kernel"
            },
            "mandate-ref": request["mandate-ref"],
            "policy-version": request["policy-version"],
            "classification": "consequential",
            "execution": {
                "action": "kernel.publish_policy",
                "target": request["target"],
                "args-hash": document_hash,
                "outcome": "applied",
                "started-at": now,
                "finished-at": now
            },
            "evidence": {
                "schema": "kernel.publish_policy.v1",
                "media-type": "application/json",
                "payload-hash": document_hash,
                "retain-until": retain_until
            },
            "authorization": { "request": request, "decision": decision }
        }));
        let body = envelope.and_then(|envelope| {
            stozher_core::jcs::canonicalize(&serde_json::json!({
                "envelope": envelope,
                // The document travels with the envelope, so `/v1/policy/current` can serve the
                // bytes the approval committed to rather than a copy someone uploaded separately.
                "payloads": [{
                    "payload-hash": document_hash,
                    "media-type": "application/json",
                    "payload": document
                }]
            }))
        });
        let body = match body {
            Ok(body) => body,
            Err(e) => {
                eprintln!("signing: {e}");
                return ExitCode::FAILURE;
            }
        };
        match stozher_kernel::operator::ingest(url, &token, body.as_bytes()) {
            Ok(answer) if answer.ok() => {
                println!("{}", answer.body);
                return ExitCode::SUCCESS;
            }
            Ok(answer) if attempt + 1 < ATTEMPTS && contended(&answer.body) => {
                last = answer.body;
                std::thread::sleep(std::time::Duration::from_millis(200 << attempt));
            }
            Ok(answer) => {
                println!("{}", answer.body);
                eprintln!("the kernel refused it ({})", answer.status);
                return ExitCode::FAILURE;
            }
            Err(e) => {
                eprintln!("policy-publish: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    eprintln!("{stream} stayed contended for {ATTEMPTS} attempts; nothing was recorded");
    println!("{last}");
    ExitCode::FAILURE
}

/// Build the action request that asks to change the root set — §03 §6.
///
/// Offline. An enrolment also writes the **evidence** naming the human, because §03 §6 requires it
/// to be submitted with the change and bound by `args-hash`: the name recorded in the root set is
/// then the name a second root approved, not one the emitter chose afterwards.
///
/// The requester is a root acting directly, which §03 §1 says still needs a mandate somebody else
/// granted — so `--mandate` here is a mandate from the *other* root. That is the whole of why §03
/// §6 says a one-root deployment cannot change its root set, and it is checked at ingest, not here.
fn root_request(arguments: &[String]) -> ExitCode {
    let value = |name: &str| value(arguments, name);
    let (enrol, retire) = (value("--enrol"), value("--retire"));
    let (Some(requester), Some(key_path), Some(mandate), Some(in_force), Some(out)) = (
        value("--requester"),
        value("--key"),
        value("--mandate"),
        value("--in-force"),
        value("--out"),
    ) else {
        eprintln!(
            "root-request requires --requester <human:name>, --key <path>, --mandate <64 hex>, \
             --in-force <version> and --out <path>"
        );
        return ExitCode::FAILURE;
    };
    let (action, target_key) = match (enrol, retire) {
        (Some(key), None) => ("kernel.enroll_root", key),
        (None, Some(key)) => ("kernel.retire_root", key),
        _ => {
            eprintln!("root-request requires exactly one of --enrol <ed25519:…> or --retire <…>");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = stozher_core::signed::KeyId::parse(target_key) {
        eprintln!("{target_key} is not a key identifier: {}", e.detail());
        return ExitCode::FAILURE;
    }
    // The evidence for an enrolment, and the hash the approval will be bound to. A retirement names
    // only the key: the subject it was enrolled under is already in the root set (§03 §6).
    let evidence = if action == "kernel.enroll_root" {
        let Some(subject) = value("--subject") else {
            eprintln!(
                "--subject human:<name> is required to enrol: the root set records the human"
            );
            return ExitCode::FAILURE;
        };
        if !subject.starts_with("human:") || subject.len() <= "human:".len() {
            eprintln!("--subject must be a human:<name> subject");
            return ExitCode::FAILURE;
        }
        Some(serde_json::json!({ "subject": subject, "key": target_key }))
    } else {
        None
    };
    let args_hash = match evidence.as_ref().map_or_else(
        || {
            // A retirement carries no arguments, so `args-hash` commits to the empty object rather
            // than to nothing: §06 §1.1 has no representation for "no arguments at all".
            stozher_core::jcs::object_hash(&serde_json::json!({}))
        },
        stozher_core::jcs::object_hash,
    ) {
        Ok(hash) => hash,
        Err(e) => {
            eprintln!("hashing the evidence: {e}");
            return ExitCode::FAILURE;
        }
    };
    let key = match seed_key(arguments, key_path, keys::ROLE_HUMAN_ROOT) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let now = match offline_clock(arguments) {
        Ok(clock) => clock.now(),
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let minutes = value("--minutes")
        .and_then(|m| m.parse::<i64>().ok())
        .unwrap_or(60);
    let (Ok(not_after), Ok(nonce)) = (
        stozher_kernel::clock::shift(&now, minutes * 60),
        genesis::request_nonce(),
    ) else {
        eprintln!("could not stamp the request");
        return ExitCode::FAILURE;
    };
    let request = serde_json::json!({
        "v": stozher_core::VERSION,
        "kind": "action-request",
        "requested-at": now,
        "subject": requester,
        "key": key.id().as_str(),
        "component": "kernel",
        "mandate-ref": mandate,
        "policy-version": in_force,
        "classification": "consequential",
        "action": action,
        "target": format!("root:{target_key}"),
        "args-hash": args_hash,
        "nonce": nonce,
        "not-after": not_after
    });
    let (Ok(canonical), Ok(hash)) = (
        stozher_core::jcs::canonicalize(&request),
        stozher_core::jcs::object_hash(&request),
    ) else {
        eprintln!("canonicalizing the request");
        return ExitCode::FAILURE;
    };
    if let Err(e) = std::fs::write(out, &canonical) {
        eprintln!("writing {out}: {e}");
        return ExitCode::FAILURE;
    }
    if let Some(evidence) = &evidence {
        let path = value("--evidence-out").map_or_else(|| format!("{out}.evidence"), str::to_owned);
        match stozher_core::jcs::canonicalize(evidence)
            .map_err(|e| e.to_string())
            .and_then(|text| std::fs::write(&path, text).map_err(|e| e.to_string()))
        {
            Ok(()) => eprintln!("wrote {path} — the evidence the approval binds"),
            Err(e) => {
                eprintln!("writing {path}: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    println!("{hash}");
    eprintln!("wrote {out} — park it, have a *different* root approve {hash}, then root-publish");
    ExitCode::SUCCESS
}

/// Record an approved root-set change — §03 §6.
///
/// Signed by the root that asked, because §03 §6 requires the envelope to be signed by an existing
/// root; approved by a different one, because §06 §5 forbids answering your own request. Neither of
/// those is decided here — the kernel checks both, and this command holds no authority it could use
/// to skip them.
fn root_publish(arguments: &[String]) -> ExitCode {
    let value = |name: &str| value(arguments, name);
    let (Some(url), Some(request_path), Some(key_path)) =
        (value("--url"), value("--request"), value("--key"))
    else {
        eprintln!("root-publish requires --url <base>, --request <path> and --key <path>");
        return ExitCode::FAILURE;
    };
    let Some(token) = credential(arguments) else {
        return ExitCode::FAILURE;
    };
    let request: serde_json::Value = match std::fs::read(request_path)
        .map_err(|e| e.to_string())
        .and_then(|bytes| serde_json::from_slice(&bytes).map_err(|e| e.to_string()))
    {
        Ok(request) => request,
        Err(e) => {
            eprintln!("reading {request_path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let enrolling = request["action"].as_str() == Some("kernel.enroll_root");
    let args_hash = request["args-hash"].as_str().unwrap_or_default().to_owned();
    // The evidence, re-read from disk and re-hashed rather than trusted from the request: if they
    // differ, the operator is about to enrol a key or a name nobody approved.
    let payloads = if enrolling {
        let path =
            value("--evidence").map_or_else(|| format!("{request_path}.evidence"), str::to_owned);
        let evidence: serde_json::Value = match std::fs::read(&path)
            .map_err(|e| e.to_string())
            .and_then(|bytes| serde_json::from_slice(&bytes).map_err(|e| e.to_string()))
        {
            Ok(evidence) => evidence,
            Err(e) => {
                eprintln!("reading {path}: {e}");
                return ExitCode::FAILURE;
            }
        };
        match stozher_core::jcs::object_hash(&evidence) {
            Ok(hash) if hash == args_hash => vec![serde_json::json!({
                "payload-hash": hash,
                "media-type": "application/json",
                "payload": evidence
            })],
            Ok(hash) => {
                eprintln!(
                    "{path} hashes to {hash}, the request commits to {args_hash}: \
                     this is not the evidence that was approved"
                );
                return ExitCode::FAILURE;
            }
            Err(e) => {
                eprintln!("hashing {path}: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        Vec::new()
    };

    let evidence = if enrolling {
        serde_json::json!({
            "schema": "kernel.enroll_root.v1",
            "media-type": "application/json",
            "payload-hash": args_hash,
            "retain-until": match stozher_kernel::clock::shift(
                &match offline_clock(arguments) {
                    Ok(clock) => clock.now(),
                    Err(e) => {
                        eprintln!("{e}");
                        return ExitCode::FAILURE;
                    }
                },
                365 * 86_400,
            ) {
                Ok(retain_until) => retain_until,
                Err(e) => {
                    eprintln!("clock: {e}");
                    return ExitCode::FAILURE;
                }
            }
        })
    } else {
        serde_json::Value::Null
    };
    publish_effect(
        arguments, url, &token, key_path, &request, &evidence, &payloads,
    )
}

/// Build the action request for any gated kernel action — the general form of `policy-request`.
///
/// Three of the five actions §05 §5 rule 6 puts beyond policy's reach have their own ceremony above,
/// because each carries a rule a general command cannot check: a policy change binds a document, an
/// enrolment binds a human's name. The other two — `kernel.conformance_run` and
/// `kernel.register_component` — carry no such rule, and had no command at all: the v0.4 gate
/// *"a component not written by us registers through the documented path"* was met by a helper in
/// the test kit, which is not a path an operator has.
///
/// `--args-hash` is separate from `--evidence` on purpose. A registration commits to its manifest,
/// so the two are the same hash; a conformance run commits to the manifest it attests while
/// carrying the run report as evidence, so they are not.
fn effect_request(arguments: &[String]) -> ExitCode {
    let value = |name: &str| value(arguments, name);
    let (
        Some(action),
        Some(target),
        Some(requester),
        Some(key_path),
        Some(mandate),
        Some(in_force),
        Some(out),
    ) = (
        value("--action"),
        value("--target"),
        value("--requester"),
        value("--key"),
        value("--mandate"),
        value("--in-force"),
        value("--out"),
    )
    else {
        eprintln!(
            "effect-request requires --action, --target, --requester, --key, --mandate, \
             --in-force and --out"
        );
        return ExitCode::FAILURE;
    };
    let args_hash = match (value("--args-hash"), value("--args-from")) {
        (Some(hash), None) if stozher_core::crypto::is_digest_hex(hash) => hash.to_owned(),
        (Some(hash), None) => {
            eprintln!("--args-hash {hash} is not 64 lowercase hex digits");
            return ExitCode::FAILURE;
        }
        (None, Some(path)) => match std::fs::read(path)
            .map_err(|e| e.to_string())
            .and_then(|bytes| {
                serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|e| e.to_string())
            })
            .and_then(|document| {
                stozher_core::jcs::object_hash(&document).map_err(|e| e.detail().to_owned())
            }) {
            Ok(hash) => hash,
            Err(e) => {
                eprintln!("hashing {path}: {e}");
                return ExitCode::FAILURE;
            }
        },
        _ => {
            eprintln!("effect-request requires exactly one of --args-hash or --args-from <path>");
            return ExitCode::FAILURE;
        }
    };
    let classification = value("--classification").unwrap_or("consequential");
    let key = match seed_key(arguments, key_path, keys::ROLE_HUMAN_ROOT) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let now = match offline_clock(arguments) {
        Ok(clock) => clock.now(),
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let minutes = value("--minutes")
        .and_then(|m| m.parse::<i64>().ok())
        .unwrap_or(60);
    let (Ok(not_after), Ok(nonce)) = (
        stozher_kernel::clock::shift(&now, minutes * 60),
        genesis::request_nonce(),
    ) else {
        eprintln!("could not stamp the request");
        return ExitCode::FAILURE;
    };
    let request = serde_json::json!({
        "v": stozher_core::VERSION,
        "kind": "action-request",
        "requested-at": now,
        "subject": requester,
        "key": key.id().as_str(),
        "component": value("--emitting-component").unwrap_or("kernel"),
        "mandate-ref": mandate,
        "policy-version": in_force,
        "classification": classification,
        "action": action,
        "target": target,
        "args-hash": args_hash,
        "nonce": nonce,
        "not-after": not_after
    });
    let (Ok(canonical), Ok(hash)) = (
        stozher_core::jcs::canonicalize(&request),
        stozher_core::jcs::object_hash(&request),
    ) else {
        eprintln!("canonicalizing the request");
        return ExitCode::FAILURE;
    };
    if let Err(e) = std::fs::write(out, &canonical) {
        eprintln!("writing {out}: {e}");
        return ExitCode::FAILURE;
    }
    println!("{hash}");
    eprintln!("wrote {out} — park it, have a root approve {hash}, then effect-publish");
    ExitCode::SUCCESS
}

/// Record an approved gated action — the general form of `policy-publish`.
fn effect_publish(arguments: &[String]) -> ExitCode {
    let value = |name: &str| value(arguments, name);
    let (Some(url), Some(request_path), Some(key_path)) =
        (value("--url"), value("--request"), value("--key"))
    else {
        eprintln!("effect-publish requires --url <base>, --request <path> and --key <path>");
        return ExitCode::FAILURE;
    };
    let Some(token) = credential(arguments) else {
        return ExitCode::FAILURE;
    };
    let request: serde_json::Value = match std::fs::read(request_path)
        .map_err(|e| e.to_string())
        .and_then(|bytes| serde_json::from_slice(&bytes).map_err(|e| e.to_string()))
    {
        Ok(request) => request,
        Err(e) => {
            eprintln!("reading {request_path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let action = request["action"].as_str().unwrap_or_default().to_owned();
    // The evidence, if any, hashed here rather than taken on trust: an operator publishing the
    // wrong file learns it now instead of from a refusal about a hash.
    let (payloads, evidence_section) = match value("--evidence") {
        None => (Vec::new(), serde_json::Value::Null),
        Some(path) => {
            let document: serde_json::Value = match std::fs::read(path)
                .map_err(|e| e.to_string())
                .and_then(|bytes| serde_json::from_slice(&bytes).map_err(|e| e.to_string()))
            {
                Ok(document) => document,
                Err(e) => {
                    eprintln!("reading {path}: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let Ok(hash) = stozher_core::jcs::object_hash(&document) else {
                eprintln!("hashing {path}");
                return ExitCode::FAILURE;
            };
            // Policy caps retention per weight class (§09 §2), and a `benign` ceiling is much
            // shorter than a `consequential` one — so this is a flag rather than a constant. The
            // refusal names the ceiling when it is exceeded, which is what makes retrying obvious.
            let retain_days = value("--retain-days")
                .and_then(|d| d.parse::<i64>().ok())
                .unwrap_or(365);
            let retain_until = match stozher_kernel::clock::shift(
                &match offline_clock(arguments) {
                    Ok(clock) => clock.now(),
                    Err(e) => {
                        eprintln!("{e}");
                        return ExitCode::FAILURE;
                    }
                },
                retain_days * 86_400,
            ) {
                Ok(retain_until) => retain_until,
                Err(e) => {
                    eprintln!("clock: {e}");
                    return ExitCode::FAILURE;
                }
            };
            (
                vec![serde_json::json!({
                    "payload-hash": hash,
                    "media-type": "application/json",
                    "payload": document
                })],
                serde_json::json!({
                    "schema": value("--schema").map_or_else(|| format!("{action}.v1"), str::to_owned),
                    "media-type": "application/json",
                    "payload-hash": hash,
                    "retain-until": retain_until
                }),
            )
        }
    };
    publish_effect(
        arguments,
        url,
        &token,
        key_path,
        &request,
        &evidence_section,
        &payloads,
    )
}

/// Sign and submit the effect an approved request describes, retrying a contended chain position.
///
/// Shared by [`effect_publish`] and [`root_publish`]: the difference between them is entirely in
/// what they check *before* this point, and duplicating the retry — whose one subtle part is that
/// exhausting it must not be reported as a permanent refusal — is how the two would come to differ.
fn publish_effect(
    arguments: &[String],
    url: &str,
    token: &str,
    key_path: &str,
    request: &serde_json::Value,
    evidence: &serde_json::Value,
    payloads: &[serde_json::Value],
) -> ExitCode {
    let stream = value(arguments, "--stream").unwrap_or("kernel:core");
    let request_hash = match stozher_core::jcs::object_hash(request) {
        Ok(hash) => hash,
        Err(e) => {
            eprintln!("hashing the request: {e}");
            return ExitCode::FAILURE;
        }
    };
    let decision = match fetch_decision(url, token, &request_hash) {
        Ok(decision) => decision,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let key = match seed_key(arguments, key_path, keys::ROLE_HUMAN_ROOT) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let now = match offline_clock(arguments) {
        Ok(clock) => clock.now(),
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };

    const ATTEMPTS: usize = 4;
    let mut last = String::new();
    for attempt in 0..ATTEMPTS {
        let (seq, prev) = match head_of(url, token, stream) {
            Ok(head) => head,
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::FAILURE;
            }
        };
        let mut body = serde_json::json!({
            "v": stozher_core::VERSION,
            "kind": "effect",
            "emitted-at": now,
            "stream": stream,
            "seq": seq,
            "prev-hash": prev,
            "identity": {
                "subject": request["subject"],
                "key": key.id().as_str(),
                "component": request["component"]
            },
            "mandate-ref": request["mandate-ref"],
            "policy-version": request["policy-version"],
            "classification": request["classification"],
            "execution": {
                "action": request["action"],
                "target": request["target"],
                "args-hash": request["args-hash"],
                "outcome": "applied",
                "started-at": now,
                "finished-at": now
            },
            "authorization": { "request": request, "decision": decision }
        });
        if !evidence.is_null() {
            body["evidence"] = evidence.clone();
        }
        let submission = key.sign(&body).and_then(|envelope| {
            stozher_core::jcs::canonicalize(
                &serde_json::json!({ "envelope": envelope, "payloads": payloads }),
            )
        });
        let submission = match submission {
            Ok(submission) => submission,
            Err(e) => {
                eprintln!("signing: {e}");
                return ExitCode::FAILURE;
            }
        };
        match stozher_kernel::operator::ingest(url, token, submission.as_bytes()) {
            Ok(answer) if answer.ok() => {
                println!("{}", answer.body);
                return ExitCode::SUCCESS;
            }
            Ok(answer) if attempt + 1 < ATTEMPTS && contended(&answer.body) => {
                last = answer.body;
                std::thread::sleep(std::time::Duration::from_millis(200 << attempt));
            }
            Ok(answer) => {
                println!("{}", answer.body);
                eprintln!("the kernel refused it ({})", answer.status);
                return ExitCode::FAILURE;
            }
            Err(e) => {
                eprintln!("effect-publish: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    eprintln!("{stream} stayed contended for {ATTEMPTS} attempts; nothing was recorded");
    println!("{last}");
    ExitCode::FAILURE
}

/// Whether a refusal is another writer having taken the chain position first.
fn contended(body: &str) -> bool {
    body.contains("chain-seq-duplicate") || body.contains("chain-prev-hash-mismatch")
}

/// The approval a named human recorded for this request, or why there is none to use.
fn fetch_decision(
    url: &str,
    token: &str,
    request_hash: &str,
) -> std::result::Result<serde_json::Value, String> {
    let answer =
        stozher_kernel::operator::read(url, token, &format!("v1/gate/requests/{request_hash}"))
            .map_err(|e| format!("reading the parked request: {e}"))?;
    if !answer.ok() {
        return Err(format!(
            "the kernel has no answerable request {request_hash} ({}): {}",
            answer.status, answer.body
        ));
    }
    let parked: serde_json::Value =
        serde_json::from_str(&answer.body).map_err(|e| format!("the kernel's answer: {e}"))?;
    let decision = parked
        .get("decision")
        .filter(|d| !d.is_null())
        .ok_or_else(|| {
            format!("{request_hash} has not been answered yet — a root must approve it first")
        })?;
    match decision["decision"].as_str() {
        Some("approve") => Ok(decision.clone()),
        // A denial is an answer, and it is terminal (§06 §4.1). Publishing anyway is the one thing
        // this command must not make easy, and the reason the human gave is what the operator is owed.
        Some("deny") => Err(format!(
            "{request_hash} was denied: {}",
            decision["reason"].as_str().unwrap_or("no reason recorded")
        )),
        _ => Err(format!("{request_hash} carries no readable decision")),
    }
}

/// The `(seq, prev-hash)` an envelope extending `stream` must carry.
fn head_of(
    url: &str,
    token: &str,
    stream: &str,
) -> std::result::Result<(u64, serde_json::Value), String> {
    let answer = stozher_kernel::operator::read(url, token, "v1/streams")
        .map_err(|e| format!("reading the streams: {e}"))?;
    if !answer.ok() {
        return Err(format!(
            "the kernel refused /v1/streams ({})",
            answer.status
        ));
    }
    let listed: serde_json::Value =
        serde_json::from_str(&answer.body).map_err(|e| format!("the kernel's answer: {e}"))?;
    let found = listed["streams"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .find(|row| row["stream"].as_str() == Some(stream));
    match found {
        Some(row) => {
            let seq = row["head-seq"]
                .as_u64()
                .ok_or_else(|| format!("{stream} has no readable head"))?;
            Ok((seq + 1, row["head-hash"].clone()))
        }
        // Not a fresh start. A deployment that has run at all has the ceremony's two envelopes on
        // this stream, so an empty one means the wrong stream name or the wrong deployment, and
        // appending at seq 0 would be building a second chain beside the real one.
        None => Err(format!(
            "{stream} holds nothing — check --stream against the kernel's kernel-core-stream"
        )),
    }
}

/// Hand a signed revocation to the kernel. The revocation is read, never produced, here.
fn submit_revocation(arguments: &[String]) -> ExitCode {
    let Some(url) = value(arguments, "--url") else {
        eprintln!("submit-revocation requires --url <base>");
        return ExitCode::FAILURE;
    };
    let (Some(token), Ok(body)) = (credential(arguments), document(arguments)) else {
        return ExitCode::FAILURE;
    };
    let Ok(object) = String::from_utf8(body) else {
        eprintln!("the revocation must be UTF-8 JSON");
        return ExitCode::FAILURE;
    };
    match stozher_kernel::operator::revoke(url, &token, object.trim()) {
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
            eprintln!("submit-revocation: {e}");
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
    // From the chain, not from the `streams` projection: that table is rebuildable and carries no
    // triggers, so a row deleted from it took a whole stream out of this loop and left the operator
    // a clean report over records nobody looked at.
    let streams = match kernel.ingest.store().streams_holding_envelopes().await {
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
        let name = stream.as_str();
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
