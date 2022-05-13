// Import functions from external crates
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

// Import functions from files
use crate::functions;

// TODO: Remove this
#[allow(unused_imports)]
#[allow(unused_assignments)]

///
/// Define struct to hold the decrypted data from the masterfile.
/// # Data
/// - `master_key: [u8;32]`
/// - `folder_salt: [u8; 32]`
/// - `folder_nonce: [u8; 24]`
/// 
#[derive(Clone)]
pub struct MasterfileData {
    pub master_key: [u8; 32],
    pub folder_salt: [u8; 32],
    pub folder_nonce: [u8; 24],
}

///
/// Randomly generates data and writes it encrypted to a created masterfile.
/// # Arguments
/// - `path: &String`
///     - Path to the top directory of the vault to be created
/// - `password: &String`
///     - Password to use when encryping the masterfile data
/// 
/// Returns `Result<(), anyhow::Error>`
/// 
pub fn create_masterfile(
    path: &String, 
    password: &String,
) -> Result<(), anyhow::Error> {
    // Creates arrays for different data
    let mut folder_salt = [0u8; 32];
    let mut folder_nonce = [0u8; 24];
    let mut master_salt = [0u8; 32];
    let mut master_nonce = [0u8; 24];
    let mut master_key = [0u8; 32];

    // Fills the array with random bytes
    OsRng.fill_bytes(&mut folder_salt);
    OsRng.fill_bytes(&mut folder_nonce);
    OsRng.fill_bytes(&mut master_nonce);
    OsRng.fill_bytes(&mut master_salt);
    OsRng.fill_bytes(&mut master_key);

    // Initialize variables for encryption
    let argon2_config = functions::argon2_config();
    let mut key = argon2::hash_raw(password.as_bytes(), &master_salt, &argon2_config)?;
    let key_ga = GenericArray::clone_from_slice(&key[..]);
    let nonce_ga = GenericArray::clone_from_slice(&master_nonce[..]);
    let aead = XChaCha20Poly1305::new(&key_ga);
    
    // Create the masterfile and write encrypted data
    if !path.ends_with("/") {
        let mut masterfile = fs::File::create
            (format!("{}/masterfile.e", path))?;

        // Write master salt and nonce unencrypted
        // for later decryption
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

    // Zerioize all sensitive variables in memory
    folder_salt.zeroize();
    folder_nonce.zeroize();
    master_salt.zeroize();
    master_nonce.zeroize();
    master_key.zeroize();
    key.zeroize();

    Ok(())
}

///
/// Read the masterfile and return unencrypted data in a data structure.
/// # Arguments
/// - `path: &String`
///     - Path to the masterfile
/// - `password: &String`
///     - Password to decrypt the masterfile data
/// 
/// Returns `MasterfileData`
/// 
pub fn read_masterfile(
    path: &String, 
    password: &String,
) -> MasterfileData {
    //TODO: Return Result<MasterfileData, anyhow::Error>
    
    // Initialize all byte arrays
    let mut encrypted_folder_salt = [0u8; 48];
    let mut encrypted_folder_nonce = [0u8; 40];
    let mut encrypted_master_key = [0u8; 48];
    let mut masterfile_salt = [0u8; 32];
    let mut masterfile_nonce = [0u8; 24];

    // Open file
    let mut masterfile = fs::File::open(&path).unwrap();
    
    // Read all data in 
    masterfile.read(&mut masterfile_salt).unwrap();
    masterfile.read(&mut masterfile_nonce).unwrap();
    masterfile.read(&mut encrypted_master_key).unwrap();
    masterfile.read(&mut encrypted_folder_salt).unwrap();
    masterfile.read(&mut encrypted_folder_nonce).unwrap();

    // Initialize aead and nonce_ga
    let argon2_config = functions::argon2_config();
    let mut key = argon2::hash_raw(password.as_bytes(), &masterfile_salt, &argon2_config).unwrap();
    let key_ga = GenericArray::clone_from_slice(&key[..]);
    let nonce_ga = GenericArray::clone_from_slice(&masterfile_nonce[..]);
    let aead = XChaCha20Poly1305::new(&key_ga);

    // Decrypt data
    let master_key = aead.decrypt(&nonce_ga, encrypted_master_key.as_ref()).unwrap();
    let folder_salt = aead.decrypt(&nonce_ga, encrypted_folder_salt.as_ref()).unwrap();
    let folder_nonce = aead.decrypt(&nonce_ga, encrypted_folder_nonce.as_ref()).unwrap();
    
    // Clean up and return
    key.zeroize();
    masterfile_salt.zeroize();
    masterfile_nonce.zeroize();
    return MasterfileData {
        master_key: functions::into_array(master_key), 
        folder_salt: functions::into_array(folder_salt), 
        folder_nonce: functions::into_array(folder_nonce),
    };
}
