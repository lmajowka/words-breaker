use anyhow::{Context, Result};
use bip39::{Language, Mnemonic};
use bitcoin::address::{Address, NetworkChecked, NetworkUnchecked};
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Network, PublicKey};
use clap::Parser;
use itertools::Itertools;
use rayon::iter::ParallelBridge;
use rayon::prelude::*;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(about = "Try permutations of BIP-39 words (10-12) to match a BTC legacy address. \
Missing words (when 10 or 11 are given) are filled from the 2048-word BIP-39 list.", version)]
struct Args {
    /// Target legacy Bitcoin address (Base58, starting with '1')
    target_address: String,

    /// 10, 11, or 12 words (unordered or partially ordered). Missing words are
    /// completed from the BIP-39 wordlist.
    words: Vec<String>,

    /// BIP-39 wordlist language (english, portuguese, spanish, french, italian, czech, korean, japanese, chinese-simplified, chinese-traditional)
    #[arg(long, short, default_value = "english")]
    language: String,

    /// Number of threads to use (defaults to number of CPU cores)
    #[arg(long, short, default_value_t = 0)]
    threads: usize,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if !(10..=12).contains(&args.words.len()) {
        anyhow::bail!("Expected 10, 11, or 12 words, got {}", args.words.len());
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
    let found = search_permutations_parallel(&args.words, &target_address, language)?;
    let elapsed = start.elapsed();

    if !found {
        println!(
            "Exhausted all permutations without a match (elapsed: {:?})",
            elapsed
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
    language: Language,
) -> Result<bool> {
    let derivation_path: DerivationPath = "m/44'/0'/0'/0/0".parse()?;
    let target_str = target.to_string();

    // Create shared Secp256k1 context (thread-safe)
    let secp = Arc::new(Secp256k1::new());

    // A valid BIP-39 mnemonic needs 12 words. Whatever is missing is completed
    // from the full 2048-word list for the chosen language.
    let missing = 12 - words.len();

    // `words_by_prefix("")` matches every word, so it yields the full wordlist.
    let wordlist: &'static [&'static str] = language.words_by_prefix("");

    if missing > 0 {
        println!(
            "Got {} words; completing {} missing word(s) from the {}-word BIP-39 list.",
            words.len(),
            missing,
            wordlist.len()
        );
    }

    let total = total_candidates(words.len(), wordlist.len(), missing);
    println!(
        "Searching {} candidates (streamed, not held in memory)...",
        format_number(total)
    );
    let _ = io::stdout().flush();

    // Stream candidate phrases lazily: known words are permuted, and missing
    // word(s) are inserted into every gap from the wordlist on demand. Nothing
    // is collected up front, so memory stays flat regardless of how many
    // candidates exist.
    let owned_words: Vec<String> = words.to_vec();
    let candidates = owned_words
        .into_iter()
        .permutations(words.len())
        .flat_map(move |base| insert_missing(base, missing, wordlist).map(|v| v.join(" ")));

    let counter = Arc::new(AtomicUsize::new(0));
    let found = Arc::new(AtomicBool::new(false));
    let found_phrase = Arc::new(std::sync::Mutex::new(String::new()));
    let found_index = Arc::new(AtomicUsize::new(0));

    candidates.par_bridge().for_each(|phrase| {
        if found.load(Ordering::Relaxed) {
            return;
        }

        let i = counter.fetch_add(1, Ordering::Relaxed);
        if i % 100000 == 0 && i > 0 {
            println!("Checked {} candidates...", format_number(i));
            let _ = io::stdout().flush();
        }

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
            found_index.store(i, Ordering::SeqCst);
            let mut fp = found_phrase.lock().unwrap();
            *fp = phrase;
        }
    });

    if found.load(Ordering::SeqCst) {
        let fp = found_phrase.lock().unwrap();
        let idx = found_index.load(Ordering::SeqCst);
        println!("Found matching mnemonic: {}", *fp);
        if missing > 0 {
            let recovered = recovered_words(words, &fp);
            println!("Recovered missing word(s): {}", recovered.join(" "));
        }
        println!("Candidate index (0-based): {}", idx);
        println!("Derived address: {}", target_str);
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Number of candidate phrases for `n` known words with `missing` slots filled
/// from a wordlist of `wordlist_len` words: n! * wordlist_len^missing.
fn total_candidates(n: usize, wordlist_len: usize, missing: usize) -> usize {
    let factorial: usize = (1..=n).product::<usize>().max(1);
    factorial * wordlist_len.pow(missing as u32)
}

/// Lazily inserts `remaining` words from `wordlist` into every gap of `seq`,
/// recursing until full 12-word phrases are produced. `remaining` is at most 2
/// (12 minus the 10-12 words the user supplies), so the recursion is shallow.
fn insert_missing(
    seq: Vec<String>,
    remaining: usize,
    wordlist: &'static [&'static str],
) -> Box<dyn Iterator<Item = Vec<String>> + Send> {
    if remaining == 0 {
        return Box::new(std::iter::once(seq));
    }

    let len = seq.len();
    Box::new((0..=len).flat_map(move |pos| {
        let seq = seq.clone();
        wordlist.iter().flat_map(move |&word| {
            let mut next = Vec::with_capacity(seq.len() + 1);
            next.extend_from_slice(&seq[..pos]);
            next.push(word.to_string());
            next.extend_from_slice(&seq[pos..]);
            insert_missing(next, remaining - 1, wordlist)
        })
    }))
}

/// Returns the words in `phrase` that were not part of the originally supplied
/// `known` words (i.e. the words recovered from the wordlist), as a multiset
/// difference.
fn recovered_words(known: &[String], phrase: &str) -> Vec<String> {
    let mut remaining: Vec<String> = known.to_vec();
    let mut recovered = Vec::new();
    for word in phrase.split_whitespace() {
        if let Some(pos) = remaining.iter().position(|k| k == word) {
            remaining.remove(pos);
        } else {
            recovered.push(word.to_string());
        }
    }
    recovered
}
