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

fn main() -> Result<(), anyhow::Error> {
    let args: Vec<String> = env::args().collect();
    let mut path: String = String::from("~/.rusty-vault");
    let path_no_tilde = &path.remove(0);
    let home = std::env::var("HOME").unwrap();
    //assert_eq!(shellexpand::tilde(&path), format!("{}{}", home, path_no_tilde));
    println!("{}", path_no_tilde);
    Ok(())
}
