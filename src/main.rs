/*
Rusty-Vault
Written by Olympia (Matthew) Thornton
April 24 2022

This program will create a masterfile at the top of a file tree and 
encrypt/decrypt all files and folders therein.

*/

#![allow(non_snake_case)]

// import functions from other files
mod functions;
mod masterfile;
mod encryptionFunctions;
mod vault;
use vault::vault::Vault;

// import external crates
use colored::Colorize;
use std::{
    fs, 
};


///
/// Display the main menu in a loop and calls
/// appropriate functions
/// # Arguments
/// - `vaults: &mut Vec<Vault>`
///     - An array of Vault objects read from the config file
/// - `config_file: &String`
///     - path to the config file to be passed to other functions
/// 
/// Returns `Result<(), anyhow::Error>`
/// 
fn main_menu(
    vaults: &mut Vec<Vault>,
    config_file: &str,
) -> Result<(), anyhow::Error>{
    // Start the main loop
    loop {
        // Clear the terminal screen and display header
        print!("{}[2J", 27 as char);
        println!("##Rusty Vault##");

        // Check if there are loaded vaults, if not display alternate menu
        // to allow vault creation or importation
        if !vaults.is_empty() {
            let input: String = functions::get_input("[1] Lock/Unlock Vault
[2] Create Vault
[3] Add Existing Vault
[4] Delete Vault
[5] Quit")?;
            if input == "1" {
                // Call function to lock/unlock vaults and recheck the file status
                vault_unlock_stage(vaults)?;
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
            let input = functions::get_input("[1] Create Vault
[2] Add Existing Vault
[3] Quit")?;
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
///
/// Called by the main menu to stage locking and unlocking vaults.
/// Will display all vaults and take input, then call the appropriate function.
/// # Arguments
/// - `vaults: &Vec<Vault>`
///     - Array of Vault objects read from the config file
/// 
/// Returns `Result<(), anyhow::Error>`
/// 
fn vault_unlock_stage(
    vaults: &[Vault],
) -> Result<(), anyhow::Error> {
    // Clear the terminal and print header
    print!("{}[2J", 27 as char);
    println!("##Lock/Unlock Vault##");

    // Define statuses
    let LOCKED = "LOCKED".to_string().green();
    let UNLOCKED = "UNLOCKED".to_string().yellow();
    let MIXED = "MIXED".to_string().red();
    let UNKNOWN = "STATUS UNKNOWN".to_string().red();

    // Instantiate a container to hold an index and a reference to 
    // the vault it refers to 
    let mut temp: Vec<VaultStage> = Vec::new();
    let mut counter: i32 = 1;

    // Print out the vaults and their status
    for i in vaults {
        if i.status == 0 {println!("[{}] {} - {}", counter, i.name, LOCKED);}
        else if i.status == 1 {println!("[{}] {} - {}", counter, i.name, UNLOCKED);}
        else if i.status == 2 {println!("[{}] {} - {}", counter, i.name, MIXED);}
        else {println!("[{}] {} - {}", counter, i.name, UNKNOWN);}

        // Save the vault to the temporary structure
        temp.push(
            VaultStage {
                vault_ref: i,
                index: counter.to_string(),
            }
        );
        counter += 1;
    }

    // Return to main menu check
    println!("[{}] Return to Main Menu", counter);
    let input = functions::get_input(">")?;
    if input == counter.to_string() || input.to_lowercase() == "q" 
        || input.to_lowercase() == "quit" {
            return Ok(())
    }
    let input = functions::get_input(">")?;
    for i in temp {
        if i.index == input {
            if i.vault_ref.status == 1 {
                // Call the vault lock/unlock function
                // if passed true the function will encrypt the vault
                // if passed false the function will decrypt the vault
                functions::unlock_lock_vault
                    (i.vault_ref.master_file_path.clone(), true, i.vault_ref.hashed_password.clone())?;
            } else if i.vault_ref.status == 0 {
                functions::unlock_lock_vault
                    (i.vault_ref.master_file_path.clone(), false, i.vault_ref.hashed_password.clone())?;
            }
        }
    }
    Ok(())
}

///
/// Data structure for holding the temporary access to the 
/// vaults and their index. Used when printing out the vault
/// names to be selected by the index later.
/// # Arguments
/// - `vault_ref: &'a Vault`
///     - Staticly lived reference to a Vault object
/// - `index: String`
///     - The index for reference to a printed array.
///     Saved as a string to make comparison to input value easier.
/// 
struct VaultStage<'a>{
    pub vault_ref: &'a Vault,
    pub index: String,
}

///
/// Will force the vaults in the passed array to recheck the status
/// of their files. Called after unlocking or locking a vault.
/// # Arguments
/// - `vaults: &mut Vec<Vault>`
///     - Array of Vault objects
/// 
/// Returns `Result<(), anyhow::Error>`
/// 
fn recheck_vault_status(
    vaults: &mut Vec<Vault>
) -> Result<(), anyhow::Error> {
    for i in vaults {
        i.check_status()?;
    }
    Ok(())
}

///
/// Called by the main menu to stage the 
/// removing of a vault.
/// # Arguments
/// - `vaults: &mut Vec<Vault>`
///     - Array of Vault objects
/// - `config_path: &String`
///     - Path to the config file storing vault info
/// 
/// Returns `Result<(), anyhow::Error>`
/// 
fn vault_remove_stage(
    vaults: &mut Vec<Vault>,
    config_path: &str,
) -> Result<(), anyhow::Error> {
    // Clear the terminal and prints the header
    print!("{}[2J", 27 as char);
    println!("##Delete Vault##");

    // Initialize a counter
    let mut counter: u8 = 1;

    // Define statuses
    let LOCKED = "LOCKED".to_string().green();
    let UNLOCKED = "UNLOCKED".to_string().yellow();
    let MIXED = "MIXED".to_string().red();
    let UNKNOWN = "STATUS UNKNOWN".to_string().red();

    // Print vaults and their status
    for i in vaults.clone() {
        if i.status == 0 {println!("[{}] {} - {}", counter, i.name, LOCKED);}
        else if i.status == 1 {println!("[{}] {} - {}", counter, i.name, UNLOCKED);}
        else if i.status == 2 {println!("[{}] {} - {}", counter, i.name, MIXED);}
        else {println!("[{}] {} - {}", counter, i.name, UNKNOWN);}
        counter += 1;
    }
    println!("[{}] Return to Main Menu", counter);

    // Get input and confirmation for deletion
    let input = functions::get_input(">")?;

    // Check for return to Main Menu
    if input == counter.to_string() || input.to_lowercase() == "q"
        || input.to_lowercase() == "quit" {
            return Ok(())
    }

    let input = functions::get_input(">")?;
    let index = input.parse::<i32>().unwrap() - 1;
    let confirmation = functions::get_input(&format!
        ("The vault {} will be unlocked if locked and deleted. Are you sure this is what you want? [Y/N]", 
            vaults[index as usize].name)[..])?;
    
    if confirmation.to_lowercase() == "y" {
        // Get a copy of the master file path
        let master_file_path = vaults[index as usize].master_file_path.clone();
        let hashed_password = vaults[index as usize].hashed_password.clone();

        // Unlock the vault if locked
        if vaults[index as usize].status == 0 {
            functions::unlock_lock_vault(master_file_path.clone(), false, hashed_password)?;
        }

        // Remove the master file, remove the vault from the array, and 
        // write the vaults array to the config file
        fs::remove_file(master_file_path)?;
        vaults.remove(index as usize);
        functions::write_vaults(vaults, config_path)?;
    }
    Ok(())
}

///
/// Function for importing an already existing vault. Called from the main
/// menu.
/// # Arguments
/// - `vaults: &mut Vec<Vault>`
///     - Array of Vault objects
/// - `config_path: &String`
///     - Path to the config file storing vault info
/// 
/// Returns `Result<(), anyhow::Error>`
fn add_existing_vault(
    vaults: &mut Vec<Vault>,
    config_path: &str,
) -> Result<(), anyhow::Error> {
    // Clear the terminal and print the header
    print!("{}[2J", 27 as char);
    println!("##Add Existing Vault##");

    // Get the path to the masterfile.e and the name of the vault
    let path_to_create = functions::get_input("Enter path of masterfile.e or quit to return to Main Menu: ")?;
    
    // Check for return to main menu
    if path_to_create.to_lowercase() == "q" || path_to_create.to_lowercase() == "quit" {
        return Ok(())
    }

    let path_to_create = functions::get_input("Enter path of masterfile.e: ")?;
    let name = functions::get_input("Enter name for new vault: ")?;
    let password = functions::get_password_double("Enter Vault password: ")?;

    // Check that the path is correct and the size of the file is correct (192 bytes)
    if path_to_create.ends_with("masterfile.e") && fs::metadata(path_to_create.clone())?.len() == 192 {
        // Push the new info to the vaults array and write the array to the config file
        vaults.push(
            Vault::new(name, path_to_create, functions::hash_password_vec(password)?)
        );
        functions::write_vaults(vaults, config_path)?;
    } else {
        println!("Bad masterfile or path.");
    }
    Ok(())
}

///
/// Main function of the program. Will call for creation of the Vaults array and pass
/// it to the main menu function when called.
/// 
/// Returns `Result<(), anyhow::Error>`
/// 
fn main() -> Result<(), anyhow::Error> {
    // Expand the path to the config file 
    let config_path = shellexpand::tilde("~/.rusty-vault/config").to_string();

    // Verify the config file exists, if not it will be created
    functions::check_config_file(&config_path)?;

    // Create the vaults array
    let mut vaults: Vec<Vault> = functions::read_config_file(&config_path);

    // Check the vaults file status
    recheck_vault_status(&mut vaults)?;

    // Call the main menu
    main_menu(&mut vaults, &config_path)?;
    Ok(())
}
