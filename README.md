# 🛡️ Seed Obfuscator 🔐
[![Download Executable](https://img.shields.io/badge/Download_Executable-v1.0.0-blue?style=for-the-badge&logo=linux)](https://github.com/reimen-cpu/Seed-Obfuscator/releases/latest/download/seed-obfuscator)

A lightweight, 100% offline desktop application to secure your BIP-39 seed phrases. It uses a mathematical XOR transformation with a secret key to convert your seed phrase into a *different* but valid BIP-39 seed phrase.

## 🌟 Why use this?

Standard seed phrase backups (like metal plates or paper) are vulnerable to physical theft. If someone finds your list of 24 words, your funds are gone.
**Obfuscation** adds a layer of protection: even if your backup is stolen, the thief only finds a "decoy" seed phrase that looks perfectly valid but contains no funds. Your real funds are only accessible if you know the **Secret Key** used to obfuscate it.

## 🛠 Features

- **Mathematical Diffuse**: Uses SHA-256 for key derivation and XOR for entropy transformation, ensuring every single word changes.
- **Valid Output**: The resulting phrase is a valid BIP-39 mnemonic with a correct checksum.
- **Reversible**: XOR is its own inverse. Applying the same secret key to an obfuscated seed recovers the original one perfectly.
- **Support for All Lengths**: Works with 12, 15, 18, 21, and 24-word phrases.
- **Multi-Format Support**: Reads phrases in horizontal (one per line) or vertical (one word per line) formats.
- **Zero Dependencies**: Built using standard Python 3 libraries (`hashlib`, `tkinter`). No `pip install` required.

## 🚀 Usage

1. **Run the application**:
   ```bash
   python3 bip39_obfuscator.py
   ```
2. **Select Files**: Choose one or more `.txt` files containing your seed phrases.
3. **Set Secret Key**: Enter a strong passphrase and confirm it.
4. **Transform**:
   - **Ofuscar**: Generates `output.txt` with the encoded "decoy" phrases.
   - **Revertir**: Use this on a decoy file with the same key to get your original phrases back in `revert.txt`.

## ⚙️ How it works (Technical)

1. **Entropy Extraction**: The tool converts the BIP-39 words back to their raw binary entropy (128-256 bits).
2. **Key Derivation**: Your secret key is expanded using iterative SHA-256 to match the entropy length.
3. **XOR Transformation**: `New_Entropy = Original_Entropy XOR Derived_Key`.
4. **Re-Checksum**: A new valid BIP-39 checksum is calculated for the new entropy.
5. **Mnemonic Encoding**: The tool maps the new bits back to the BIP-39 wordlist.

## 🛡 Security Best Practice

- **Always run offline**: Use an air-gapped computer or a Live USB.
- **The Secret Key is everything**: If you lose your secret key, you cannot recover the original seed phrase. Treat it with the same care as a password.
