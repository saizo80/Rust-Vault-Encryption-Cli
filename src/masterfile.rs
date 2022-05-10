use rand::{rngs::OsRng, RngCore,};
use std::{
    fs,
    io::{Read, Write},
};
use chacha20poly1305::{
    aead::{Aead, NewAead, generic_array::GenericArray},
    XChaCha20Poly1305,
};
use zeroize::Zeroize;
use crate::functions;
#[allow(unused_imports)]
#[allow(unused_assignments)]

pub struct MasterfileData {
    pub master_key: [u8; 32],
    pub folder_salt: [u8; 32],
    pub folder_nonce: [u8; 24],
}

pub fn create_masterfile(
    path: &String, 
    password: &String,
) -> Result<(), anyhow::Error> {
    
    let mut folder_salt = [0u8; 32];
    let mut folder_nonce = [0u8; 24];
    let mut master_salt = [0u8; 32];
    let mut master_nonce = [0u8; 24];
    let mut master_key = [0u8; 32];

    OsRng.fill_bytes(&mut folder_salt);
    OsRng.fill_bytes(&mut folder_nonce);
    OsRng.fill_bytes(&mut master_nonce);
    OsRng.fill_bytes(&mut master_salt);
    OsRng.fill_bytes(&mut master_key);

    let argon2_config = functions::argon2_config();
    let mut key = argon2::hash_raw(password.as_bytes(), &master_salt, &argon2_config)?;
    let key_ga = GenericArray::clone_from_slice(&key[..]);
    let nonce_ga = GenericArray::clone_from_slice(&master_nonce[..]);
    let aead = XChaCha20Poly1305::new(&key_ga);
    
    if !path.ends_with("/") {
        let mut masterfile = fs::File::create
            (format!("{}/masterfile.e", path))?;
        masterfile.write(&master_salt)?;
        masterfile.write(&master_nonce)?;
        masterfile.write(&aead.encrypt(&nonce_ga, master_key.as_ref()).expect("Failure")[..])?;
        masterfile.write(&aead.encrypt(&nonce_ga, folder_salt.as_ref()).expect("Failure")[..])?;
        masterfile.write(&aead.encrypt(&nonce_ga, folder_nonce.as_ref()).expect("Failure")[..])?;
    }
    else {
        let mut masterfile = fs::File::create
            (format!("{}masterfile.e", path))?;
        masterfile.write(&master_salt)?;
        masterfile.write(&master_nonce)?;
        masterfile.write(&aead.encrypt(&nonce_ga, master_key.as_ref()).expect("Failure")[..])?;
        masterfile.write(&aead.encrypt(&nonce_ga, folder_salt.as_ref()).expect("Failure")[..])?;
        masterfile.write(&aead.encrypt(&nonce_ga, folder_nonce.as_ref()).expect("Failure")[..])?;
    }

    folder_salt.zeroize();
    folder_nonce.zeroize();
    master_salt.zeroize();
    master_nonce.zeroize();
    master_key.zeroize();
    key.zeroize();

    Ok(())
}

pub fn read_masterfile(
    path: &String, 
    password: &String,
) -> MasterfileData {
    
    // Initialize all byte arrays
    let mut encrypted_folder_salt = [0u8; 48];
    let mut encrypted_folder_nonce = [0u8; 40];
    let mut encrypted_master_key = [0u8; 48];
    let mut masterfile_salt = [0u8; 32];
    let mut masterfile_nonce = [0u8; 24];

    // open file
    let mut masterfile = fs::File::open(&path).unwrap();
    
    // Read all data in 
    masterfile.read(&mut masterfile_salt);
    masterfile.read(&mut masterfile_nonce);
    masterfile.read(&mut encrypted_master_key);
    masterfile.read(&mut encrypted_folder_salt);
    masterfile.read(&mut encrypted_folder_nonce);

    // initialize aead and nonce_ga
    let argon2_config = functions::argon2_config();
    let mut key = argon2::hash_raw(password.as_bytes(), &masterfile_salt, &argon2_config).unwrap();
    let key_ga = GenericArray::clone_from_slice(&key[..]);
    let nonce_ga = GenericArray::clone_from_slice(&masterfile_nonce[..]);
    let aead = XChaCha20Poly1305::new(&key_ga);

    // decrypt
    let master_key = aead.decrypt(&nonce_ga, encrypted_master_key.as_ref()).unwrap();
    let folder_salt = aead.decrypt(&nonce_ga, encrypted_folder_salt.as_ref()).unwrap();
    let folder_nonce = aead.decrypt(&nonce_ga, encrypted_folder_nonce.as_ref()).unwrap();
    
    // clean up and return
    key.zeroize();
    masterfile_salt.zeroize();
    masterfile_nonce.zeroize();
    return MasterfileData {
        master_key: functions::into_array(master_key), 
        folder_salt: functions::into_array(folder_salt), 
        folder_nonce: functions::into_array(folder_nonce),
    };
}