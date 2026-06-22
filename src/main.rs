use anyhow::{Context, Result};
use bip39::{Language, Mnemonic};
use bitcoin::address::{Address, NetworkChecked, NetworkUnchecked};
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Network, PublicKey};
use clap::Parser;
use itertools::Itertools;
use rayon::prelude::*;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(about = "Try permutations of 12 BIP-39 words to match a BTC legacy address", version)]
struct Args {
    /// Target legacy Bitcoin address (Base58, starting with '1')
    target_address: String,

    /// Exactly 12 words (unordered or partially ordered)
    words: Vec<String>,

    /// Maximum number of permutations to test (to avoid 12! by default)
    #[arg(long, default_value_t = 1_000_000)]
    max_permutations: usize,

    /// BIP-39 wordlist language (english, portuguese, spanish, french, italian, czech, korean, japanese, chinese-simplified, chinese-traditional)
    #[arg(long, short, default_value = "english")]
    language: String,

    /// Number of threads to use (defaults to number of CPU cores)
    #[arg(long, short, default_value_t = 0)]
    threads: usize,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.words.len() != 12 {
        anyhow::bail!("Expected exactly 12 words, got {}", args.words.len());
    }

    let num_threads = if args.threads == 0 {
        num_cpus::get()
    } else {
        args.threads
    };

    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global()
        .context("Failed to build thread pool")?;

    println!("Using {} threads", num_threads);

    let target_address_unchecked = args
        .target_address
        .parse::<Address<NetworkUnchecked>>()
        .context("Invalid target Bitcoin address")?;

    let target_address: Address<NetworkChecked> = target_address_unchecked
        .require_network(Network::Bitcoin.into())
        .context("This tool currently only supports mainnet legacy addresses")?;

    let start = Instant::now();
    let language = parse_language(&args.language)?;
    let found = search_permutations_parallel(&args.words, &target_address, args.max_permutations, language)?;
    let elapsed = start.elapsed();

    if !found {
        println!(
            "No matching mnemonic found within the first {} permutations (elapsed: {:?})",
            format_number(args.max_permutations), elapsed
        );
    }

    Ok(())
}

fn format_number(n: usize) -> String {
    if n >= 1_000_000_000 {
        format!("{:.1}G", n as f64 / 1_000_000_000.0)
    } else if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

fn parse_language(lang: &str) -> Result<Language> {
    match lang.to_lowercase().as_str() {
        "english" => Ok(Language::English),
        "portuguese" => Ok(Language::Portuguese),
        "spanish" => Ok(Language::Spanish),
        "french" => Ok(Language::French),
        "italian" => Ok(Language::Italian),
        "czech" => Ok(Language::Czech),
        "korean" => Ok(Language::Korean),
        "japanese" => Ok(Language::Japanese),
        "chinese-simplified" => Ok(Language::SimplifiedChinese),
        "chinese-traditional" => Ok(Language::TraditionalChinese),
        _ => anyhow::bail!("Unknown language: {}. Supported: english, portuguese, spanish, french, italian, czech, korean, japanese, chinese-simplified, chinese-traditional", lang),
    }
}

fn search_permutations_parallel(
    words: &[String],
    target: &Address<NetworkChecked>,
    max_permutations: usize,
    language: Language,
) -> Result<bool> {
    let derivation_path: DerivationPath = "m/44'/0'/0'/0/0".parse()?;
    let target_str = target.to_string();

    // Create shared Secp256k1 context (thread-safe)
    let secp = Arc::new(Secp256k1::new());

    let counter = Arc::new(AtomicUsize::new(0));
    let found = Arc::new(AtomicBool::new(false));
    let found_phrase = Arc::new(std::sync::Mutex::new(String::new()));
    let found_index = Arc::new(AtomicUsize::new(0));

    let permutations: Vec<_> = words
        .iter()
        .cloned()
        .permutations(words.len())
        .take(max_permutations)
        .enumerate()
        .collect();

    let total = permutations.len();
    println!("Testing {} permutations...", format_number(total));
    let _ = io::stdout().flush();

    permutations.par_iter().for_each(|(idx, perm)| {
        if found.load(Ordering::Relaxed) {
            return;
        }

        let i = counter.fetch_add(1, Ordering::Relaxed);
        if i % 100000 == 0 && i > 0 {
            println!("Checked {} permutations...", format_number(i));
            let _ = io::stdout().flush();
        }

        let phrase = perm.join(" ");

        let mnemonic = match Mnemonic::parse_in_normalized(language, &phrase) {
            Ok(m) => m,
            Err(_) => return,
        };

        let seed = mnemonic.to_seed("");

        let master_xprv = match Xpriv::new_master(Network::Bitcoin, &seed) {
            Ok(x) => x,
            Err(_) => return,
        };

        let child_xprv = match master_xprv.derive_priv(&secp, &derivation_path) {
            Ok(x) => x,
            Err(_) => return,
        };

        let child_priv = child_xprv.private_key;
        let child_pub = PublicKey::new(child_priv.public_key(&secp));
        let addr: Address<NetworkChecked> = Address::p2pkh(&child_pub, Network::Bitcoin);

        if addr.to_string() == target_str {
            found.store(true, Ordering::SeqCst);
            found_index.store(*idx, Ordering::SeqCst);
            let mut fp = found_phrase.lock().unwrap();
            *fp = phrase;
        }
    });

    if found.load(Ordering::SeqCst) {
        let fp = found_phrase.lock().unwrap();
        let idx = found_index.load(Ordering::SeqCst);
        println!("Found matching mnemonic: {}", *fp);
        println!("Permutation index (0-based): {}", idx);
        println!("Derived address: {}", target_str);
        Ok(true)
    } else {
        Ok(false)
    }
}
