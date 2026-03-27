//! Windows runtime verifier for the `secure-memory` crate.
//!
//! Exercises three distinct protection tracks:
//!
//! | Track | Subcommand | How it works |
//! |---|---|---|
//! | RAM locking | `lock` | `QueryWorkingSetEx` inspects the Locked bit |
//! | Guard underflow | `guard-underflow` | child crashes on `PAGE_NOACCESS` byte before data |
//! | Guard overflow | `guard-overflow` | child crashes on `PAGE_NOACCESS` byte after data |
//!
//! Run `secure-memory-verifier all` to execute every track in sequence.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "this is a CLI tool; printing to stdout/stderr is intentional"
)]

#[cfg(windows)]
mod check_guard;
#[cfg(windows)]
mod check_lock;

use std::process;

// ── Output helpers ────────────────────────────────────────────────────────────

pub fn print_check(name: &str) {
    println!("[CHECK] {name}");
}

pub fn print_pass(msg: &str) {
    println!("[PASS]  {msg}");
}

pub fn print_fail(msg: &str) {
    eprintln!("[FAIL]  {msg}");
}

pub fn print_info(msg: &str) {
    println!("[INFO]  {msg}");
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Hidden child-process modes: `--child <mode>`.
    // These spawn a process that intentionally crashes or exercises a specific path.
    #[cfg(windows)]
    if args.get(1).map(String::as_str) == Some("--child") {
        match args.get(2).map(String::as_str) {
            Some("guard-underflow") => check_guard::child(check_guard::Side::Under),
            Some("guard-overflow") => check_guard::child(check_guard::Side::Over),
            other => {
                eprintln!("unknown --child mode: {other:?}");
                process::exit(2);
            }
        }
    }

    let cmd = args.get(1).map(String::as_str).unwrap_or("--help");

    #[cfg(windows)]
    {
        let ok = match cmd {
            "lock" => check_lock::run(),
            "guard-underflow" => check_guard::run(check_guard::Side::Under),
            "guard-overflow" => check_guard::run(check_guard::Side::Over),
            "all" => run_all(),
            "--help" | "-h" => {
                print_usage();
                return;
            }
            other => {
                eprintln!("unknown subcommand: {other}");
                print_usage();
                process::exit(2);
            }
        };
        process::exit(if ok { 0 } else { 1 });
    }

    #[cfg(not(windows))]
    {
        eprintln!("secure-memory-verifier only runs on Windows");
        process::exit(2);
    }
}

#[cfg(windows)]
type Check = (&'static str, fn() -> bool);

#[cfg(windows)]
fn run_all() -> bool {
    let checks: &[Check] = &[
        ("lock", check_lock::run),
        ("guard-underflow", || check_guard::run(check_guard::Side::Under)),
        ("guard-overflow", || check_guard::run(check_guard::Side::Over)),
    ];

    let results: Vec<(&str, bool)> = checks.iter().map(|(name, f)| (*name, f())).collect();

    println!();
    println!("=== Summary ===");
    let mut all_ok = true;
    for (name, ok) in &results {
        if *ok {
            println!("  PASS  {name}");
        } else {
            println!("  FAIL  {name}");
            all_ok = false;
        }
    }
    all_ok
}

fn print_usage() {
    println!("Usage: secure-memory-verifier <SUBCOMMAND>");
    println!();
    println!("Subcommands:");
    println!("  lock             Verify data page is locked in RAM (QueryWorkingSetEx)");
    println!("  guard-underflow  Verify guard page fires on access before data (child crash)");
    println!("  guard-overflow   Verify guard page fires on access after data (child crash)");
    println!("  all              Run every check in sequence");
}
