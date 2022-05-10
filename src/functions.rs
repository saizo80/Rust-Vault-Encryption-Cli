use anyhow::anyhow;
use chacha20poly1305::{
    aead::{stream, Aead, NewAead, generic_array::GenericArray},
    XChaCha20Poly1305,
};
use chacha20poly1305;
use rand::{rngs::OsRng, RngCore,};
use std::{
    fs,
    fs::File,
    io::{self, Read, Write, BufRead},
    path::Path,
    collections::HashMap,
};
use zeroize::Zeroize;
use hex;
use crate::{
    encryptionFunctions,
    masterfile,
    vault::vault::Vault,
};

pub fn get_input(output: &str) -> String {
    let mut line = String::new();
    println!("{} ", output);
    std::io::stdin().read_line(&mut line).unwrap();
    //println!();
    return clean_input(line);
}

fn clean_input(mut input: String) -> String {
    // * Remove carriage return characters
    if let Some('\n')=input.chars().next_back() {input.pop();}
    if let Some('\r')=input.chars().next_back() {input.pop();}

    // * Remove the first and last characters if they are ' or whitespace (macos)
    if let Some('\'')=input.chars().next_back() {input.pop();}
    if let Some(' ')=input.chars().next_back() {input.pop();}
    if let Some('\'')=input.chars().next() {input.remove(0);}
    return input;
}

pub fn argon2_config<'a>() -> argon2::Config<'a> {
    return argon2::Config {
        variant: argon2::Variant::Argon2id,
        hash_length: 32,
        lanes: 8,
        mem_cost: 16 * 1024,
        time_cost: 8,
        ..Default::default()
    };
}

pub fn get_password_input(output: &str) -> String {
    /*
    TODO: Double check password before returning
    */
    return rpassword::prompt_password(output).unwrap();
}

pub fn check_file(path: &String) -> bool {
    return fs::metadata(path).unwrap().file_type().is_file()
}

pub fn check_dir(path: &String) -> bool {
    return fs::metadata(path).unwrap().file_type().is_dir()
}

pub fn into_array<T, const N: usize>(v: Vec<T>) -> [T; N] {
    v.try_into()
        .unwrap_or_else(|v: Vec<T>| panic!("Expected a Vec of length {} but it was {}", N, v.len()))
}

pub fn dir_recur(path: &String, data: &masterfile::MasterfileData) -> Result<(), anyhow::Error> {
    let paths = fs::read_dir(path).unwrap();
        for path_inv in paths {
            let x = path_inv?.path().into_os_string().into_string().unwrap();
            if check_dir(&x) {
                dir_recur(&x, data)?;
                if x.ends_with(".encrypted"){
                    encryptionFunctions::decrypt_foldername(&x, data)?;
                } else {
                    encryptionFunctions::encrypt_foldername(&x, data)?;
                }
            }
            else {
                if !x.ends_with("masterfile.e") && !x.ends_with(".DS_Store"){
                    if x.ends_with(".encrypted") {
                        let dist = x.strip_suffix(".encrypted").unwrap().to_string();
                        encryptionFunctions::decrypt_file(&x, &data.master_key).ok();
                    }
                    else {
                        let dist = format!("{}.encrypted", &x);
                        encryptionFunctions::encrypt_file(&x, &data.master_key).ok();
                    }
                }
            }
        }
    Ok(())
}

/// Check to see if the config file is present.
/// If not, it will create it
/// # Arguments
/// - `config_path` string that points to the config file
/// 
pub fn check_config_file(config_path: &String) -> Result<(), anyhow::Error> {
    if !Path::new(&config_path).exists() {
        if !Path::new(&config_path.strip_suffix("/config").unwrap()).exists() {
            fs::create_dir(&config_path.strip_suffix("/config").unwrap());
            fs::File::create(&config_path);
        }
        else {
            fs::File::create(&config_path);
        }
    }
    Ok(())
}

// The output is wrapped in a Result to allow matching on errors
// Returns an Iterator to the Reader of the lines of the file.
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

pub fn read_config_file(config_path: &str) -> Vec<Vault> {
    let mut vaults: Vec<Vault> = Vec::new();
    if let Ok(lines) = read_lines(config_path) {
        for line in lines {
            if let Ok(data) = line {
                // data will be a string
                // split by comma and enter into dict
                let datal = data.split(",").collect::<Vec<&str>>();
                if &datal.len() > &1 {
                    vaults.push(
                        Vault::new(String::from(datal[0]), 
                        String::from(datal[1])
                    )
                    )
                }
            }
        }
    }
    return vaults;
}

pub fn create_vault(
    vaults: &mut Vec<Vault>,
    config_path: &String,
) -> Result<(), anyhow::Error> {
    // clear screen
    print!("{}[2J", 27 as char);
    println!("##Create Vault##");
    // get all inputs
    let path_to_create = get_input("Enter path for new vault: ");
    let name = get_input("Enter name for new vault: ");
    let password = get_password_input("Enter password for vault: ");

    // format string with masterfile and add new vault to list
    if path_to_create.ends_with("/") {
        let master_file_path = format!("{}masterfile.e", &path_to_create);
        vaults.push(
            Vault::new(name.clone(), master_file_path)
        );
    } else {
        let master_file_path = format!("{}/masterfile.e", &path_to_create);
        vaults.push(
            Vault::new(name.clone(), master_file_path)
        );
    }

    // create the masterfile with the password 
    masterfile::create_masterfile(&path_to_create.to_string(), &password.to_string())?;

    // open the config file and write the vault data
    let mut config_file = fs::OpenOptions::new()
        .write(true)
        .append(true)
        .open(&config_path)?;
    config_file.write_all(format!("{},{}/masterfile.e\n", name, path_to_create).as_bytes())?;
    
    Ok(())
}

pub fn unlock_lock_vault(
    masterfile_path: String
) -> Result<(), anyhow::Error> {
    // read in data from masterfile
    let masterfile_data = 
        masterfile::read_masterfile(&masterfile_path, 
        &get_password_input("Enter vault password: "));
    
    // get directory to parse through
    let mut top_dir = masterfile_path.split("/").collect::<Vec<&str>>();
    top_dir.pop();
    let top_dir_path = top_dir.join("/");
    
    // loop through folder tree and encrypt/decrypt
    dir_recur(&top_dir_path, &masterfile_data)?;
    
    Ok(())
}

pub fn check_vault_status(path: &String) -> u8 {
    let paths = fs::read_dir(path).unwrap();
    let mut en = 0;
    let mut de = 0;
        for path_inv in paths {
            let x = path_inv.unwrap().path().into_os_string().into_string().unwrap();
            if check_file(&x) && !x.ends_with("masterfile.e") 
                && !x.ends_with(".DS_Store") && x.ends_with(".encrypted") {
                    en += 1;
                }
            else if check_file(&x) && !x.ends_with("masterfile.e") 
            && !x.ends_with(".DS_Store") && !x.ends_with(".encrypted") {
                de += 1;
            }
        }
        if en != 0 && de != 0 {
            return 2;
        }
        else if en == 0 && de > 0 {
            return 1;
        }
        else if en > 0 && de == 0 {
            return 0;
        }
        else {
            return 3;
        }
}