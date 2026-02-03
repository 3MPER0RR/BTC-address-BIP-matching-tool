use anyhow::Result;
use bip39::{Language, Mnemonic};
use bitcoin::{
    bip32::{DerivationPath, Xpriv},
    Address, Network, PublicKey,
};
use secp256k1::Secp256k1;
use std::io::{self, Write};
use std::str::FromStr;

#[derive(Debug, Clone, Copy)]
enum AddressType {
    Legacy,        // BIP44  p2pkh
    SegWit,        // BIP49  p2sh-p2wpkh
    NativeSegWit,  // BIP84  p2wpkh
}

impl AddressType {
    fn all() -> Vec<(AddressType, &'static str)> {
        vec![
            (AddressType::Legacy, "m/44'/0'/0'/0/0"),
            (AddressType::SegWit, "m/49'/0'/0'/0/0"),
            (AddressType::NativeSegWit, "m/84'/0'/0'/0/0"),
        ]
    }

    fn name(&self) -> &'static str {
        match self {
            AddressType::Legacy => "Legacy (BIP44, p2pkh)",
            AddressType::SegWit => "SegWit (BIP49, p2sh-p2wpkh)",
            AddressType::NativeSegWit => "Native SegWit (BIP84, bech32)",
        }
    }
}

fn get_user_input(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn derive_address(
    xprv: &Xpriv,
    secp: &Secp256k1<secp256k1::All>,
    path: &DerivationPath,
    addr_type: AddressType,
) -> Result<Address> {
    let child = xprv.derive_priv(secp, path)?;
    let secp_pubkey = child.private_key.public_key(secp);
    let btc_pubkey = PublicKey::new(secp_pubkey);

    let address = match addr_type {
        AddressType::Legacy => {
            Address::p2pkh(&btc_pubkey, Network::Bitcoin)
        }
        AddressType::SegWit => {
            Address::p2shwpkh(&btc_pubkey, Network::Bitcoin)?
        }
        AddressType::NativeSegWit => {
            Address::p2wpkh(&btc_pubkey, Network::Bitcoin)?
        }
    };

    Ok(address)
}

fn main() -> Result<()> {
    println!("=== BTC Address – BIP maching tool (beta) ===\n");

    let mnemonic_str = get_user_input("Mnemonic BIP39: ");
    let passphrase = get_user_input("Passphrase (seed extension, invio se vuota): ");

    let mnemonic =
        Mnemonic::parse_in_normalized(Language::English, &mnemonic_str)?;
    let seed = mnemonic.to_seed(passphrase.as_str());

    let secp = Secp256k1::new();
    let master = Xpriv::new_master(Network::Bitcoin, &seed)?;

    println!("\nIndirizzi derivati:\n");

    for (addr_type, path_str) in AddressType::all() {
        let path = DerivationPath::from_str(path_str)?;
        let address = derive_address(&master, &secp, &path, addr_type)?;

        println!(
            "{}\n  Path: {}\n  Address: {}\n",
            addr_type.name(),
            path_str,
            address
        );
    }

    Ok(())
}
