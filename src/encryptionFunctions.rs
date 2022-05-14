// Import functions from external crates
use anyhow::anyhow;
use chacha20poly1305::{
    aead::{stream, Aead, NewAead, generic_array::GenericArray},
    XChaCha20Poly1305,
};

use rand::{rngs::OsRng, RngCore,};
use std::{
    fs,
    fs::File,
    io::{Read, Write},
};
use zeroize::Zeroize;


// Import functions from files
use crate::{
    functions,
    masterfile
};

// Set buffer length variable
const BUFFER_LEN: usize = 500;

///
/// Function to encrypt the filename. Will encrypt the filename and 
/// return the new path to be used in file creation.
/// # Arguments
/// - `source_file_path: &str`
///     - Path to the original source file
/// - `key: &Vec<u8>`
///     - Key that is generated in the calling function
/// - `nonce: &[u8; 19]` 
///     - Array of 19 bytes from the calling function
/// 
/// Returns `String`
/// 
pub fn encrypt_filename(
    source_file_path: &str,
    key: &[u8],
    nonce: &[u8; 19],
) -> String {
    // Add an extra 5 bytes to the end of the nonce for use in standalone encryption
    let whole_nonce: [u8; 24] = {
        let mut whole_nonce: [u8; 24] = [0; 24];
        let (one, two) = whole_nonce.split_at_mut(nonce.len());
        one.copy_from_slice(nonce);
        two.copy_from_slice(b"00000");
        whole_nonce
    };

    // Split the path and get the filename
    let mut split_path = source_file_path.split('/').collect::<Vec<&str>>();
    let path_size = split_path.len();
    let filename = split_path[path_size-1];

    // Prepare the generic arrays and aead
    let key_ga = GenericArray::clone_from_slice(key);
    let nonce_ga = GenericArray::clone_from_slice(&whole_nonce[..]);
    let aead = XChaCha20Poly1305::new(&key_ga);

    // Encrypt the filename
    let encoded = aead.encrypt(&nonce_ga, filename.as_bytes().as_ref()).expect("Encryption failure");

    // Replace the filename in the split path
    let encoded_str = format!("{}.encrypted", hex::encode(encoded));
    split_path[path_size-1] = &encoded_str;

    // Join the split path and return
    split_path.join("/")
}

///
/// Function to decrypt the filename. Will decrypt the filename and 
/// return the new path to be used in file creation.
/// # Arguments
/// - `encrypted_file_path: &str`
///     - Path to the original source file
/// - `key: &Vec<u8>`
///     - Key that is generated in the calling function
/// - `nonce: &[u8; 19]` 
///     - Array of 19 bytes from the calling function
/// 
/// Returns `String`
/// 
pub fn decrypt_filename(
    encrypted_file_path: &str,
    key: &[u8],
    nonce: &[u8; 19],
) -> String {
    // Add an extra 5 bytes to the end of the nonce for use in standalone encryption
    let whole_nonce: [u8; 24] = {
        let mut whole_nonce: [u8; 24] = [0; 24];
        let (one, two) = whole_nonce.split_at_mut(nonce.len());
        one.copy_from_slice(nonce);
        two.copy_from_slice(b"00000");
        whole_nonce
    };

    // Split the path and get the filename
    let mut split_path = encrypted_file_path.split('/').collect::<Vec<&str>>();
    let path_size = split_path.len();
    let mut encrypted_filename = String::from(split_path[path_size-1]);
    
    // Remove the '.encrypted' from the end of the filename
    encrypted_filename = encrypted_filename.strip_suffix(".encrypted").unwrap().to_string();

    // Get the bytes to decode
    // has to use hex, cannot use as_bytes
    let to_decrypt = hex::decode(encrypted_filename).unwrap();

    // Prepare generic arrays and aead
    let key_ga = GenericArray::clone_from_slice(key);
    let nonce_ga = GenericArray::clone_from_slice(&whole_nonce[..]);
    let aead = XChaCha20Poly1305::new(&key_ga);

    // Decrypt the filename
    let decoded = aead.decrypt(&nonce_ga, to_decrypt.as_ref()).expect("Encryption failure");

    // Replace the encrypted filename in the split path
    let decoded_str = std::str::from_utf8(&decoded).unwrap();
    split_path[path_size-1] = decoded_str;

    // Join the path and return
    split_path.join("/")
}

/// 
/// Function called to encrypt a file. Will create a new file with an encrypted filename
/// and stream encrypt data into the new file. Will also store the nonce and salt used for 
/// encryption in the file to be used later during decryption.
/// # Arguments
/// - `source_file_path: &str`
///     - Path to the original file
/// - `password: &[u8; 32]` 
///     - Array of bytes to be used as the password for encryption.
///       Taken from the decrypted masterfile.
/// 
/// Returns `Result<(), anyhow::Error>`
/// 
pub fn encrypt_file(
    source_file_path: &str,
    password: &[u8; 32],
) -> Result<(), anyhow::Error> {
    // Get config for the password hashing
    let argon2_config = functions::argon2_config();

    // Create and fill byte arrays for the salt and nonce
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 19];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    // Get the key from the hashed password using the randomly
    // created salt
    let mut key = argon2::hash_raw(password, &salt, &argon2_config)?;

    // Create the aead and stream cypher using the key
    let aead = XChaCha20Poly1305::new(key[..32].as_ref().into());
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

    // Open the source file and create the dist file with the 
    // encrypted filename from the function call
    let mut source_file = File::open(source_file_path)?;
    let mut dist_file = File::create(encrypt_filename(source_file_path, &key, &nonce))?;

    // Write the salt and nonce in the dist file
    dist_file.write_all(&salt)?;
    dist_file.write_all(&nonce)?;
    
    let mut buffer = [0u8; BUFFER_LEN];

    // Loop through the source file, encrypt the data, and write
    // to the dist file until completion
    loop {
        let read_count = source_file.read(&mut buffer)?;

        if read_count == BUFFER_LEN {
            let ciphertext = stream_encryptor
                .encrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
            dist_file.write_all(&ciphertext)?;
        } else {
            let ciphertext = stream_encryptor
                .encrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
            dist_file.write_all(&ciphertext)?;
            break;
        }
    }

    // Delete the source file and zerioize sensitive variables in memory
    fs::remove_file(source_file_path)?;
    salt.zeroize();
    nonce.zeroize();
    key.zeroize();

    Ok(())
}

///
/// Function for decrypting a file. Will decrypt the filename with the salt and nonce
/// stored in the encrypted file, then stream decrypt into the destination file.
/// # Arguments
/// - `encrypted_file_path: &str`
///     - Path to the encrypted file
/// - `password: &[u8; 32]` 
///     - Array of bytes to be used as the password for encryption.
///       Taken from the decrypted masterfile.
/// 
/// Returns `Result<(), anyhow::Error>`
/// 
pub fn decrypt_file(
    encrypted_file_path: &str,
    password: &[u8; 32],
) -> Result<(), anyhow::Error> {
    // Instantiate arrays for salt and nonce
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 19];

    // Open the encrypted file
    let mut encrypted_file = File::open(encrypted_file_path)?;
    
    // Read the salt and nonce
    let mut read_count = encrypted_file.read(&mut salt)?;
    if read_count != salt.len() {
        return Err(anyhow!("Error reading salt."));
    }

    read_count = encrypted_file.read(&mut nonce)?;
    if read_count != nonce.len() {
        return Err(anyhow!("Error reading nonce."));
    }

    // Get config for the password hashing
    let argon2_config = functions::argon2_config();

    // Make key from config, salt, and password
    let mut key = argon2::hash_raw(password, &salt, &argon2_config)?;

    // Prepare aead and decryptor
    let aead = XChaCha20Poly1305::new(key[..32].as_ref().into());
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());

    // Add 16 bytes to the buffer length because aead stream encryptors
    // add an extra 16 bytes to the file
    let mut buffer = [0u8; BUFFER_LEN+16];

    // Create the dist file with the decrypted filename function call
    let mut dist_file = File::create(decrypt_filename(encrypted_file_path, &key, &nonce))?;

    // Read bytes from the encrypted file, decrypt, and write to destination file
    loop {
        let read_count = encrypted_file.read(&mut buffer)?;

        if read_count == BUFFER_LEN+16 {
            let plaintext = stream_decryptor
                .decrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
            dist_file.write_all(&plaintext)?;
        } 
        else if read_count == 0 {
            break;
        }
        else {
            let plaintext = stream_decryptor
                .decrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
            dist_file.write_all(&plaintext)?;
            break;
        }
    }

    // Remove the encrypted file and zeroize sensitive variables in memory
    fs::remove_file(encrypted_file_path)?;
    salt.zeroize();
    nonce.zeroize();
    key.zeroize();

    Ok(())
}

///
/// Function for encrypting the foldername. Will use the password, folder_nonce,
/// and folder_salt from the masterfile data structure to encrypt the foldername.
/// # Arguments
/// - `source_path: &String`
///     - Path to the folder
/// - `data:& masterfile::MasterfileData`
///     - Data structure that holds the decrypted data from the masterfile
/// 
/// Returns `Result<(), anyhow::Error>`
/// 
pub fn encrypt_foldername(
    source_path: &str, 
    data: &masterfile::MasterfileData,
) -> Result<(), anyhow::Error> {
    // Create the hashing config and create the key
    let argon2_config = functions::argon2_config();
    let key = argon2::hash_raw(&data.master_key, &data.folder_salt, &argon2_config)?;

    // Split the path and get the foldername
    let mut split_path = source_path.split('/').collect::<Vec<&str>>();
    let path_size = split_path.len();
    let mut foldername = split_path[path_size-1];
    if foldername.is_empty() {
        foldername = split_path[path_size-2];
    }

    // Prepare the generic arrays and aead
    let key_ga = GenericArray::clone_from_slice(&key[..]);
    let nonce_ga = GenericArray::clone_from_slice(&data.folder_nonce[..]);
    let aead = XChaCha20Poly1305::new(&key_ga);

    // Encrypt the foldername
    let encoded = aead.encrypt(&nonce_ga, foldername.as_bytes().as_ref()).expect("Encryption failure");

    // Replace the foldername in the split path
    let encoded_str = format!("{}.encrypted", hex::encode(encoded));
    if split_path[path_size-1].is_empty(){
        split_path[path_size-2] = &encoded_str;
    } else {
        split_path[path_size-1] = &encoded_str;
    }

    // Join the path and rename the folder
    let dist_path = split_path.join("/");
    fs::rename(source_path, dist_path)?;
    
    Ok(())
}

///
/// Function for decrypting the foldername. Will use the password, folder_nonce,
/// and folder_salt from the masterfile data structure to decrypt the foldername. 
/// # Arguments
/// - `encrypted_path: &String`
///     - Path to the encrypted folder
/// - `data: &masterfile::MasterfileData`
///     - Data structure that holds the decrypted data from the masterfile
/// 
/// Returns `Result<(), anyhow::Error>`
/// 
pub fn decrypt_foldername(
    encrypted_path: &str,
    data: &masterfile::MasterfileData,
) -> Result<(), anyhow::Error> {
    // Create the hashing config and the key
    let argon2_config = functions::argon2_config();
    let key = argon2::hash_raw(&data.master_key, &data.folder_salt, &argon2_config)?;

    // Split the path and get the encrypted foldername
    let mut split_path = encrypted_path.split('/').collect::<Vec<&str>>();
    let path_size = split_path.len();
    let mut encrypted_foldername = String::from(split_path[path_size-1]);
    if encrypted_foldername.is_empty() {
        encrypted_foldername = String::from(split_path[path_size-2]);
    }

    // Remove the '.encrypted' from the foldername
    encrypted_foldername = encrypted_foldername
        .strip_suffix(".encrypted").unwrap().to_string();

    // Get bytes from encrypted foldername
    // cannot use as_bytes
    let to_decrypt = hex::decode(encrypted_foldername).unwrap();

    // Prepare the generic arrays and aead
    let key_ga = GenericArray::clone_from_slice(&key[..]);
    let nonce_ga = GenericArray::clone_from_slice(&data.folder_nonce[..]);
    let aead = XChaCha20Poly1305::new(&key_ga);

    // Decode the foldername and convert to utf8
    let decoded = aead.decrypt(&nonce_ga, to_decrypt.as_ref()).expect("Encryption failure");
    let decoded_str = std::str::from_utf8(&decoded).unwrap();

    // Replace the encrypted foldername in the split path
    if split_path[path_size-1].is_empty(){
        split_path[path_size-2] = decoded_str;
    } else {
        split_path[path_size-1] = decoded_str;
    }

    // Join the path and rename the folder
    let dist_path = split_path.join("/");
    fs::rename(encrypted_path, dist_path)?;
    Ok(())
}
