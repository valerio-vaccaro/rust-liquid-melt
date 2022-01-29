use clap::{Arg, App};
use colored::*;
use elements::bitcoin::network::constants::Network;
use elements::Address;
use bitcoin::hashes::hex::{ToHex};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use std::process;


fn main() {
    let banner = "
    :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
    ::::::::::::::::         Liquid melt - import you mini private key on node - 2022 Valerio Vaccaro          ::::::::::::::::
    ::::::::::::::::                  https://github.com/valerio-vaccaro/rust-liquid-melt                      ::::::::::::::::
    :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
    ";
    println!("{}", banner.green());
    let matches = App::new("derive")
        .version("0.0.1")
        .author("Valerio Vaccaro <melt@valeriovaccaro.it>")
        .about("")
        .arg(Arg::with_name("minikey")
                 .short("m")
                 .long("minikey")
                 .takes_value(true)
                 .help("Mini private key"))
        .arg(Arg::with_name("network")
                 .short("n")
                 .long("network")
                 .takes_value(true)
                 .help("main, test (default=test)"))
        .get_matches();

    let minikey_str = matches.value_of("minikey");
    let mut network = matches.value_of("network").unwrap_or("test");
    /*if network != "main" {
        network = "test";
    }*/

    // check minikey format -> sha256(minikey+'?') has to start with 00
    let check_minikey = sha256::Hash::hash(format!("{}?", minikey_str.unwrap()).as_bytes()).into_inner();
    if check_minikey[0] != 0x00 {
        println!("{}", "MiniKey not valid".red());
        process::exit(0x0010);
    }

    // calculate privkey
    let minikey_str_hash = sha256::Hash::hash(minikey_str.unwrap().as_bytes()).into_inner();
    let secp = Secp256k1::new();
    let private = bitcoin::util::key::PrivateKey {
            compressed: true,
            key: SecretKey::from_slice(&minikey_str_hash).expect("32 bytes, within curve order"),
            network: Network::Bitcoin,
    };

    // calculate address
    let public = private.public_key(&secp);
    let unconfidential_address = Address::p2pkh(&public, None, &elements::AddressParams::LIQUID);

    // calculate blinding key
    let suffix = b"blindingkey";
    let blinding_bytes = [&minikey_str_hash[..], &suffix[..]].concat();
    let blinding_secret_key = SecretKey::from_slice(&sha256::Hash::hash(&blinding_bytes).into_inner()).expect("32 bytes, within curve order");
    let blinding_public = elements::secp256k1_zkp::PublicKey::from_secret_key(&secp, &blinding_secret_key);
    let confidential_address = unconfidential_address.to_confidential(blinding_public);

    // print instructions for core
    println!("{} {}", "liquid-cli importaddress".yellow(), unconfidential_address.to_string().green());
    println!("{} {} {}", "liquid-cli importprivkey".yellow(), private.to_wif().red(), "false".yellow());
    println!("{} {} {}", "liquid-cli importblindingkey".yellow(), confidential_address.to_string().green(), blinding_secret_key.to_string().red());
}
