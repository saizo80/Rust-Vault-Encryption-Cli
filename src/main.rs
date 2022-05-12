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
mod vault;

use vault::vault::Vault;
use colored::Colorize;
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
    vaults: &mut Vec<Vault>,
    config_file: &String,
) -> Result<(), anyhow::Error>{
    loop {
        print!("{}[2J", 27 as char);
        println!("##Rusty Vault##");
        if &vaults.len() > &0 {
            let input: String = functions::get_input(&format!("[1] Lock/Unlock Vault
[2] Create Vault
[3] Add Existing Vault
[4] Delete Vault
[5] Quit")[..]);
            if input == "1" {
                vault_unlock_stage(&vaults)?;
                recheck_vault_status(vaults)?;
            }
            else if input == "2" {
                functions::create_vault(vaults, config_file)?;
            }
            else if input == "3" {
                add_existing_vault(vaults, config_file)?;
            }
            else if input == "4" {
                vault_remove_stage(vaults, config_file)?;
            }
            else if input == "5" || input.to_lowercase() == "q" ||
                input.to_lowercase() == "quit" {break}
        }
        else {
            let input = functions::get_input(&format!("[1] Create Vault
[2] Add Existing Vault
[3] Quit")[..]);
            if input == "1" {
                functions::create_vault(vaults, config_file)?;
            }
            else if input == "2" {
                add_existing_vault(vaults, config_file)?;
            }
            else if input == "3" || input.to_lowercase() == "q" ||
                input.to_lowercase() == "quit" {break}
        }
    }
    Ok(())
}

fn vault_unlock_stage(
    vaults: &Vec<Vault>,
) -> Result<(), anyhow::Error> {
    print!("{}[2J", 27 as char);
    println!("##Lock/Unlock Vault##");

    // Define statuses
    let LOCKED = format!("LOCKED").green();
    let UNLOCKED = format!("UNLOCKED").yellow();
    let MIXED = format!("MIXED").red();
    let UNKNOWN = format!("STATUS UNKNOWN").red();

    //let mut temp: HashMap<String, &String> = HashMap::new();
    let mut temp: Vec<VaultStage> = Vec::new();
    let mut counter: i32 = 1;
    for i in vaults {
        if i.status == 0 {println!("[{}] {} - {}", counter, i.name, LOCKED);}
        else if i.status == 1 {println!("[{}] {} - {}", counter, i.name, UNLOCKED);}
        else if i.status == 2 {println!("[{}] {} - {}", counter, i.name, MIXED);}
        else {println!("[{}] {} - {}", counter, i.name, UNKNOWN);}
        temp.push(
            VaultStage {
                vault_ref: i,
                index: counter.to_string(),
            }
        );
        //temp.insert(counter.to_string(), &i.master_file_path);
        counter += 1;
    }
    let input = functions::get_input(">");
    for i in temp {
        if i.index == input {
            if i.vault_ref.status == 1 {
                functions::unlock_lock_vault
                    (i.vault_ref.master_file_path.clone(), true)?;
            } else if i.vault_ref.status == 0 {
                functions::unlock_lock_vault
                    (i.vault_ref.master_file_path.clone(), false)?;
            }
        }
    }
    /*
    else {
        functions::get_input("Bad input. Press ENTER to return to main menu.");
    }
    */
    Ok(())
}

struct VaultStage<'a>{
    pub vault_ref: &'a Vault,
    pub index: String,
}

fn recheck_vault_status(
    temp: &mut Vec<Vault>
) -> Result<(), anyhow::Error> {
    for i in temp {
        i.check_status();
    }
    Ok(())
}

fn vault_remove_stage(
    vaults: &mut Vec<Vault>,
    config_path: &String,
) -> Result<(), anyhow::Error> {
    print!("{}[2J", 27 as char);
    println!("##Delete Vault##");

    let mut counter = 1;

    // Define statuses
    let LOCKED = format!("LOCKED").green();
    let UNLOCKED = format!("UNLOCKED").yellow();
    let MIXED = format!("MIXED").red();
    let UNKNOWN = format!("STATUS UNKNOWN").red();
    for i in vaults.clone() {
        if i.status == 0 {println!("[{}] {} - {}", counter, i.name, LOCKED);}
        else if i.status == 1 {println!("[{}] {} - {}", counter, i.name, UNLOCKED);}
        else if i.status == 2 {println!("[{}] {} - {}", counter, i.name, MIXED);}
        else {println!("[{}] {} - {}", counter, i.name, UNKNOWN);}
        counter += 1;
    }
    let input = functions::get_input(">");
    let index = input.parse::<i32>().unwrap() - 1;
    let confirmation = functions::get_input(&format!
        ("This vault will be unlocked if locked and deleted. Are you sure this is what you want? [Y/N]")[..]);
    if confirmation.to_lowercase() == "y" {
        let master_file_path = vaults[index as usize].master_file_path.clone();
        if vaults[index as usize].status == 0 {
            functions::unlock_lock_vault(master_file_path.clone(), false)?;
        }
        fs::remove_file(master_file_path)?;
        vaults.remove(index as usize);
        functions::write_vaults(vaults, config_path)?;
    }
    Ok(())
}

fn add_existing_vault(
    vaults: &mut Vec<Vault>,
    config_path: &String,
) -> Result<(), anyhow::Error> {
    print!("{}[2J", 27 as char);
    println!("##Add Existing Vault##");
    let path_to_create = functions::get_input("Enter path of masterfile.e: ");
    let name = functions::get_input("Enter name for new vault: ");

    if path_to_create.clone().ends_with("masterfile.e") && fs::metadata(path_to_create.clone())?.len() == 192 {
        vaults.push(
            Vault::new(name.clone(), path_to_create)
        );
        functions::write_vaults(vaults, config_path)?;
    } else {
        println!("Bad masterfile or path.");
    }
    Ok(())
}

fn main() -> Result<(), anyhow::Error> {
    let args: Vec<String> = env::args().collect();
    let config_path = shellexpand::tilde("~/.rusty-vault/config").to_string();
    functions::check_config_file(&config_path)?;
    let mut vaults: Vec<Vault> = functions::read_config_file(&config_path);
    recheck_vault_status(&mut vaults)?;
    main_menu(&mut vaults, &config_path)?;
    Ok(())
}
