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
use std::fs;

fn dir_recur(path: &String, password: &String) -> Result<(), anyhow::Error> {
    let paths = fs::read_dir(path).unwrap();
        for path_inv in paths {
            let x = path_inv?.path().into_os_string().into_string().unwrap();
            if functions::check_dir(&x) {
                dir_recur(&x, &password)?;
            }
            else {
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
    Ok(())
}

fn main() -> Result<(), anyhow::Error> {
    let path = functions::get_input();
    let mut password = functions::get_password_input();

    if functions::check_dir(&path) {
        dir_recur(&path, &password)?;
    }
    else {
        if path.ends_with(".encrypted") {
            let dist = path.strip_suffix(".encrypted").unwrap().to_string();
            functions::decrypt_file(&path, &dist, &password).ok();
        }
        else {
            let dist = format!("{}.encrypted", &path);
            functions::encrypt_file(&path, &dist, &password).ok();
        }
    }

    password.zeroize();
    Ok(())
}
