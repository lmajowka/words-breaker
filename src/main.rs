use anyhow::{Context, Result};
use bip39::{Language, Mnemonic};
use bitcoin::address::{Address, NetworkChecked, NetworkUnchecked};
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::{Network, PublicKey};
use clap::Parser;
use itertools::Itertools;
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
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.words.len() != 12 {
        anyhow::bail!("Expected exactly 12 words, got {}", args.words.len());
    }

    let target_address_unchecked = args
        .target_address
        .parse::<Address<NetworkUnchecked>>()
        .context("Invalid target Bitcoin address")?;

    let target_address: Address<NetworkChecked> = target_address_unchecked
        .require_network(Network::Bitcoin.into())
        .context("This tool currently only supports mainnet legacy addresses")?;

    let start = Instant::now();
    let language = parse_language(&args.language)?;
    let found = search_permutations(&args.words, &target_address, args.max_permutations, language)?;
    let elapsed = start.elapsed();

    if !found {
        println!(
            "No matching mnemonic found within the first {} permutations (elapsed: {:?})",
            args.max_permutations, elapsed
        );
    }

    Ok(())
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

fn search_permutations(
    words: &[String],
    target: &Address<NetworkChecked>,
    max_permutations: usize,
    language: Language,
) -> Result<bool> {
    let derivation_path: DerivationPath = "m/44'/0'/0'/0/0".parse()?;

    let secp = bitcoin::secp256k1::Secp256k1::new();

    for (i, perm) in words.iter().cloned().permutations(words.len()).take(max_permutations).enumerate() {
        if i % 1000 == 0 && i > 0 {
            println!("Checked {} permutations...", i);
        }

        let phrase = perm.join(" ");

        let mnemonic = match Mnemonic::parse_in_normalized(language, &phrase) {
            Ok(m) => m,
            Err(_) => continue, // skip invalid mnemonics
        };

        let seed = mnemonic.to_seed("");

        let master_xprv = Xpriv::new_master(Network::Bitcoin, &seed)
            .context("Failed to create master xprv")?;

        let child_xprv = master_xprv.derive_priv(&secp, &derivation_path)?;

        let child_priv = child_xprv.private_key;
        let child_pub = PublicKey::new(child_priv.public_key(&secp));

        let addr: Address<NetworkChecked> = Address::p2pkh(&child_pub, Network::Bitcoin);

        if &addr == target {
            println!("Found matching mnemonic: {}", phrase);
            println!("Permutation index (0-based within search): {}", i);
            println!("Derived address: {}", addr);
            return Ok(true);
        }
    }

    Ok(false)
}
