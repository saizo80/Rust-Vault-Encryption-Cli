/*
Vault Encrypt
Written by Matthew Thornton
April 24 2022

*/
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_must_use)]
// import functions from file
mod functions;
mod masterfile;
//use zeroize::Zeroize;
use std::fs;
use std::env;
//use anyhow::anyhow;
use shellexpand;
use std::path::Path;
use rand::{rngs::OsRng, RngCore,};

fn dir_recur(path: &String, password: &String) -> Result<(), anyhow::Error> {
    let paths = fs::read_dir(path).unwrap();
        for path_inv in paths {
            let x = path_inv?.path().into_os_string().into_string().unwrap();
            if functions::check_dir(&x) {
                dir_recur(&x, &password)?;
            }
            else {
                if !x.ends_with("masterfile.e"){
                    if x.ends_with(".encrypted") {
                        let dist = x.strip_suffix(".encrypted").unwrap().to_string();
                        functions::decrypt_file(&x, &dist, &password).ok();
                    }
                    else {
                        let dist = format!("{}.encrypted", &x);
                        functions::encrypt_file(&x, &dist, &password).ok();
                    }
                }
            }
        }
    Ok(())
}

/// Check to see if the config file is present.
/// If not, it will create it
/// # Arguments
/// * `config_path` string that points to the config file
/// 
fn check_config_file(config_path: &String) -> Result<(), anyhow::Error> {
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

/*
UX Intro 
let args: Vec<String> = env::args().collect();
let config_path = shellexpand::tilde("~/.rusty-vault/config").to_string();
check_config_file(&config_path)?;
*/

/*
Split String and Join Vec
let path = String::from("/home/wsl/testing/test.txt");
let mut test = path.split("/").collect::<Vec<&str>>();
let mut filename = test[test.len()-1];
test.pop();
test.push("test.lol");
let joined = test.join("/");
*/

fn main() -> Result<(), anyhow::Error> {
    let argon2_config = functions::argon2_config();
    let password = "password";
    let path = "/home/wsl/testing/test.txt";

    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let mut key = argon2::hash_raw(password.as_bytes(), &salt, &argon2_config)?;
    functions::encrypt_filename(&path, &key, &nonce);
    Ok(())
}
