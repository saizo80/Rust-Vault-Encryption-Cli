/*
Vault Encrypt
Written by Matthew Thornton
April 24 2022

*/
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_must_use)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(non_snake_case)]
// import functions from file
mod functions;
mod masterfile;
mod encryptionFunctions;

use zeroize::Zeroize;
use std::{
    fs, 
    env,
    path::Path,
    fs::File,
    io::{
        self,
        BufRead,
        Write,
    },
    collections::HashMap,
};
use anyhow::anyhow;
use shellexpand;
use rand::{rngs::OsRng, RngCore,};

fn main_menu(
    mut vaults: HashMap<String, String>,
    config_file: &String,
) -> Result<(), anyhow::Error>{
    loop {
        print!("{}[2J", 27 as char);
        println!("##Rusty Vault##");
        if vaults.len() > 0 {
            let input: String = functions::get_input(&format!("[1] Lock/Unlock Vault
[2] Create Vault
[3] Encrypt/Decrypt Single File
[4] Delete Vault
[5] Quit")[..]);
            if input == "1" {
                vault_unlock_stage(&vaults)?;
            }
            else if input == "2" {
                functions::create_vault(&mut vaults, config_file)?;
            }
            else if input == "5" || input.to_lowercase() == "q" ||
                input.to_lowercase() == "quit" {break}
        }
        else {
            let input = functions::get_input(&format!("[1] Create Vault
[2] Encrypt/Decrypt Single File
[3] Delete Vault
[4] Quit")[..]);
            if input == "1" {
                functions::create_vault(&mut vaults, config_file)?;
            }
            else if input == "4" || input.to_lowercase() == "q" ||
                input.to_lowercase() == "quit" {break}
        }
    }
    Ok(())
}

fn vault_unlock_stage(
    vaults: &HashMap<String, String>,
) -> Result<(), anyhow::Error> {
    print!("{}[2J", 27 as char);
    println!("##Lock/Unlock Vault##");
    let mut temp: HashMap<String, &String> = HashMap::new();
    let mut counter: i32 = 1;
    for (key, data) in vaults {
        println!("[{}] {}", counter, key);
        temp.insert(counter.to_string(), data);
        counter += 1;
    }
    let input = functions::get_input(">");
    if temp.contains_key(&input) {
        functions::unlock_lock_vault(temp[&input].clone())?;
    }
    else {
        functions::get_input("Bad input. Press ENTER to return to main menu.");
    }
    Ok(())
}

fn main() -> Result<(), anyhow::Error> {
    let args: Vec<String> = env::args().collect();
    let config_path = shellexpand::tilde("~/.rusty-vault/config").to_string();
    functions::check_config_file(&config_path)?;
    let vaults: HashMap<String, String> = functions::read_config_file(&config_path);
    main_menu(vaults, &config_path)?;
    Ok(())
}
