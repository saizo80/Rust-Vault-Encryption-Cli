use rand::{rngs::OsRng, RngCore, Rng, distributions::Alphanumeric};
use std::{
    fs,
    io::{Read, Write},
};
use zeroize::Zeroize;
use crate::functions;
#[allow(unused_imports)]
#[allow(unused_assignments)]

pub fn create_masterfile(
    path: &String, 
    password: &String,
) -> Result<(), anyhow::Error> {
    let mut folder_salt = [0u8; 32];
    let mut folder_nonce = [0u8; 19];
    //let mut key_temp = [0u8; 32];
    let mut key: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    println!("{}", key);
    
    OsRng.fill_bytes(&mut folder_salt);
    OsRng.fill_bytes(&mut folder_nonce);
    //OsRng.fill_bytes(&mut key_temp);

    if !path.ends_with("/") {
        let mut masterfile = fs::File::create
            (format!("{}/masterfile", path))?;
        masterfile.write(&key.as_bytes())?;
        masterfile.write(&folder_salt)?;
        masterfile.write(&folder_nonce)?;

        let temp = format!("{}/masterfile", &path);
        let temp_dist = format!("{}/masterfile.e", &path);
        let temp_slice: &str = &temp[..];
        let temp_dist_slice: &str = &temp_dist[..];
        functions::encrypt_file(temp_slice, temp_dist_slice, &password)?;
    }
    else {
        let mut masterfile = fs::File::create
            (format!("{}masterfile", path))?;
        masterfile.write(&key.as_bytes())?;
        masterfile.write(&folder_salt)?;
        masterfile.write(&folder_nonce)?;

        let temp = format!("{}masterfile", &path);
        let temp_dist = format!("{}masterfile.e", &path);
        let temp_slice: &str = &temp[..];
        let temp_dist_slice: &str = &temp_dist[..];
        functions::encrypt_file(temp_slice, temp_dist_slice, &password)?;
    }
    folder_salt.zeroize();
    folder_nonce.zeroize();
    key.zeroize();

    Ok(())
}

pub fn read_masterfile(path: &String, password: &String) -> ([u8; 32], [u8; 32], [u8; 19]) {
    /*
    TODO:
        - move masterfile functions to seperate file
        - read to ram and decrypt there rather than decrypting to file
    */
    // unencrypt with password here
    println!("{}", &path);
    let dist = path.strip_suffix(".e").unwrap().to_string();
    functions::decrypt_file(&path, &dist, &password).ok();

    let mut folder_salt = [0u8; 32];
    let mut folder_nonce = [0u8; 19];
    let mut key_temp = [0u8; 32];

    let mut masterfile = fs::File::open(&dist).unwrap();

    // if let Ok(read_count) = masterfile.read()
    // else
    //let mut read_count = masterfile.read(&mut key_temp);
    masterfile.read(&mut key_temp);
    /*
    if read_count != key_temp.len() {
        return ReadMasterfileEnum::Res
            (Err(anyhow!("Error reading key.")));
    }*/

    //read_count = masterfile.read(&mut folder_salt);
    masterfile.read(&mut folder_salt);
    /*
    if read_count != folder_salt.len() {
        return ReadMasterfileEnum::Res
        (Err(anyhow!("Error reading salt.")));
    }*/

    //read_count = masterfile.read(&mut folder_nonce);
    masterfile.read(&mut folder_nonce);
    /*
    if read_count != folder_nonce.len() {
        return ReadMasterfileEnum::Res
        (Err(anyhow!("Error reading nonce.")));
    }*/
    
    // encrypt with password before returning
    functions::encrypt_file(&dist, &path, &password);
    return (key_temp, folder_salt, folder_nonce);
}
