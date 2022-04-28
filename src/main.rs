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

fn main() -> Result<(), anyhow::Error> {
    let args: Vec<String> = env::args().collect();
    let config_path = shellexpand::tilde("~/.rusty-vault/config").to_string();
    check_config_file(&config_path)?;
    Ok(())
}
