/*
Encode Walk
Written by Matthew Thornton
April 16 2022

Terminal tool for encrypting/decrypting files, either single, in folders
or recursively in a tree of folders.
*/
#![allow(dead_code)]
#![allow(unused_variables)]
// import functions from file
mod functions;
use rand::{rngs::OsRng, RngCore};

fn main() {
    let path_to_encrypt: String = functions::get_input();
    //let mut path_to_encrypt: String = String::from("'/Users/olympia/Downloads/Nextcloud-backup-codes.txt'");

    // Collect to vector
    let mut path_vector = path_to_encrypt.split("/").collect::<Vec<_>>();

    // remove any empty items in the vector
    path_vector.retain(|value| *value != "");

    let file_to_encrypt = &path_vector[&path_vector.len()-1];
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut key);
    OsRng.fill_bytes(&mut nonce);

    functions::encrypt_small_file(format!("/{}", path_vector.join("/"))
        ,format!("/{}.binff", path_vector.join("/"))
        ,&key, &nonce).ok();
}
