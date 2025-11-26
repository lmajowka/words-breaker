# Words Breaker

A command-line tool that attempts to recover a BIP-39 mnemonic seed phrase by testing permutations of 12 known words against a target Bitcoin legacy address.

## Use Case

If you have 12 BIP-39 mnemonic words but don't remember the correct order, this tool will brute-force permutations to find the combination that derives to your known Bitcoin address.

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (1.70 or later recommended)

## Building

### Windows

```powershell
cargo build --release
```

The binary will be located at `target\release\words-breaker.exe`.

### Linux / macOS

```bash
cargo build --release
```

The binary will be located at `target/release/words-breaker`.

## Usage

```
words-breaker <TARGET_ADDRESS> <WORD1> <WORD2> ... <WORD12> [OPTIONS]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `TARGET_ADDRESS` | Target legacy Bitcoin address (Base58, starting with `1`) |
| `WORD1..WORD12` | Exactly 12 BIP-39 words in any order |

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `-l, --language` | `english` | BIP-39 wordlist language |
| `--max-permutations` | `1000000` | Maximum number of permutations to test |
| `-h, --help` | | Print help |
| `-V, --version` | | Print version |

**Supported languages:** `english`, `portuguese`, `spanish`, `french`, `italian`, `czech`, `korean`, `japanese`, `chinese-simplified`, `chinese-traditional`

### Examples

**Windows:**
```powershell
.\target\release\words-breaker.exe 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa abandon ability able about above absent absorb abstract absurd abuse access accident --max-permutations 500000
```

**Linux / macOS:**
```bash
./target/release/words-breaker 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa abandon ability able about above absent absorb abstract absurd abuse access accident --max-permutations 500000
```

**With Portuguese wordlist:**
```bash
./target/release/words-breaker 1CfntEjWHwCc7moXnMHUX8QuBJaakAnv8U bexiga bonde curativo nevoeiro mundial vareta urubu megafone cozinha livro surpresa senador -l portuguese
```

## How It Works

1. Generates permutations of the 12 provided words
2. For each permutation, validates it as a BIP-39 mnemonic
3. Derives the Bitcoin address using derivation path `m/44'/0'/0'/0/0`
4. Compares the derived P2PKH address against the target
5. Stops and outputs the correct phrase when a match is found

## Performance Notes

- 12 words have 479,001,600 (12!) possible permutations
- The default limit of 1,000,000 permutations covers ~0.2% of all possibilities
- Progress is logged every 1,000 permutations
- Invalid BIP-39 checksums are skipped automatically

## License

MIT
