/*
Vault Encrypt
Written by Matthew Thornton
April 24 2022

*/
#![allow(dead_code)]
#![allow(unused_variables)]
// import functions from file
mod functions;
use zeroize::Zeroize;
use anyhow::anyhow;

fn main() -> Result<(), anyhow::Error> {
    let file = functions::get_input();
    let mut password = functions::get_password_input();

    if file.ends_with(".encrypted") {
        let dist = file.strip_suffix(".encrypted").unwrap().to_string() + ".decrypted";
        functions::decrypt_file(&file, &dist, &password)?;
    }
    else {
        let dist = format!("{}.encrypted", &file);
        functions::encrypt_file(&file, &dist, &password)?;
    }

    password.zeroize();
    Ok(())
}
