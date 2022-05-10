use anyhow::anyhow;
use chacha20poly1305::{
    aead::{stream, Aead, NewAead, generic_array::GenericArray},
    XChaCha20Poly1305,
};
use chacha20poly1305;
use rand::{rngs::OsRng, RngCore,};
use std::{
    fs,
    fs::File,
    io::{Read, Write},
};
use zeroize::Zeroize;
use hex;
use crate::{
    functions,
    masterfile};

const BUFFER_LEN: usize = 500;

pub fn encrypt_filename(
    source_file_path: &str,
    key: &Vec<u8>,
    nonce: &[u8; 19],
) -> String {
    let whole_nonce: [u8; 24] = {
        let mut whole_nonce: [u8; 24] = [0; 24];
        let (one, two) = whole_nonce.split_at_mut(nonce.len());
        one.copy_from_slice(nonce);
        two.copy_from_slice(b"00000");
        whole_nonce
    };

    let mut split_path = source_file_path.split("/").collect::<Vec<&str>>();
    let path_size = split_path.len();
    let filename = split_path[path_size-1];

    let key_ga = GenericArray::clone_from_slice(&key[..]);

    let nonce_ga = GenericArray::clone_from_slice(&whole_nonce[..]);

    let aead = XChaCha20Poly1305::new(&key_ga);

    let encoded = aead.encrypt(&nonce_ga, filename.as_bytes().as_ref()).expect("Encryption failure");

    let encoded_str = format!("{}.encrypted", hex::encode(encoded.clone()));
    split_path[path_size-1] = &encoded_str;

    return split_path.join("/");
}

pub fn decrypt_filename(
    encrypted_file_path: &str,
    key: &Vec<u8>,
    nonce: &[u8; 19],
) -> String {
    let whole_nonce: [u8; 24] = {
        let mut whole_nonce: [u8; 24] = [0; 24];
        let (one, two) = whole_nonce.split_at_mut(nonce.len());
        one.copy_from_slice(nonce);
        two.copy_from_slice(b"00000");
        whole_nonce
    };

    let mut split_path = encrypted_file_path.split("/").collect::<Vec<&str>>();
    let path_size = split_path.len();
    let mut encrypted_filename = String::from(split_path[path_size-1]);
    
    encrypted_filename.truncate(encrypted_filename.len()-10);

    let to_decrypt = hex::decode(encrypted_filename.clone()).unwrap();

    let key_ga = GenericArray::clone_from_slice(&key[..]);

    let nonce_ga = GenericArray::clone_from_slice(&whole_nonce[..]);

    let aead = XChaCha20Poly1305::new(&key_ga);

    let decoded = aead.decrypt(&nonce_ga, to_decrypt.as_ref()).expect("Encryption failure");

    let decoded_str = std::str::from_utf8(&decoded).unwrap();
    split_path[path_size-1] = &decoded_str;

    return split_path.join("/");
}

pub fn encrypt_file(
    source_file_path: &str,
    password: &[u8; 32],
) -> Result<(), anyhow::Error> {
    let argon2_config = functions::argon2_config();

    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 19];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let mut key = argon2::hash_raw(password, &salt, &argon2_config)?;

    let aead = XChaCha20Poly1305::new(key[..32].as_ref().into());
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

    let mut source_file = File::open(source_file_path)?;
    // call function to encrypt filename
    let mut dist_file = File::create(encrypt_filename(&source_file_path, &key, &nonce))?;

    dist_file.write(&salt)?;
    dist_file.write(&nonce)?;
    
    let mut buffer = [0u8; BUFFER_LEN];

    loop {
        let read_count = source_file.read(&mut buffer)?;

        if read_count == BUFFER_LEN {
            let ciphertext = stream_encryptor
                .encrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
            dist_file.write(&ciphertext)?;
        } else {
            let ciphertext = stream_encryptor
                .encrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
            dist_file.write(&ciphertext)?;
            break;
        }
    }
    fs::remove_file(source_file_path)?;
    salt.zeroize();
    nonce.zeroize();
    key.zeroize();

    Ok(())
}

pub fn decrypt_file(
    encrypted_file_path: &str,
    password: &[u8; 32],
) -> Result<(), anyhow::Error> {
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 19];

    let mut encrypted_file = File::open(encrypted_file_path)?;
    

    let mut read_count = encrypted_file.read(&mut salt)?;
    if read_count != salt.len() {
        return Err(anyhow!("Error reading salt."));
    }

    read_count = encrypted_file.read(&mut nonce)?;
    if read_count != nonce.len() {
        return Err(anyhow!("Error reading nonce."));
    }

    let argon2_config = functions::argon2_config();

    let mut key = argon2::hash_raw(password, &salt, &argon2_config)?;

    let aead = XChaCha20Poly1305::new(key[..32].as_ref().into());
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());

    let mut buffer = [0u8; BUFFER_LEN+16];
    // call function to decrypt filename
    let mut dist_file = File::create(decrypt_filename(&encrypted_file_path, &key, &nonce))?;

    loop {
        let read_count = encrypted_file.read(&mut buffer)?;

        if read_count == BUFFER_LEN+16 {
            let plaintext = stream_decryptor
                .decrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
            dist_file.write(&plaintext)?;
        } 
        else if read_count == 0 {
            break;
        }
        else {
            let plaintext = stream_decryptor
                .decrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
            dist_file.write(&plaintext)?;
            break;
        }
    }
    fs::remove_file(encrypted_file_path)?;
    salt.zeroize();
    nonce.zeroize();
    key.zeroize();

    Ok(())
}

pub fn encrypt_foldername(
    source_path: &String, 
    data: &masterfile::MasterfileData,
) -> Result<(), anyhow::Error> {
    let argon2_config = functions::argon2_config();
    let key = argon2::hash_raw(&data.master_key, &data.folder_salt, &argon2_config)?;

    let mut split_path = source_path.split("/").collect::<Vec<&str>>();
    let path_size = split_path.len();
    let mut foldername = split_path[path_size-1];
    if foldername == "" {
        foldername = split_path[path_size-2];
    }

    let key_ga = GenericArray::clone_from_slice(&key[..]);

    let nonce_ga = GenericArray::clone_from_slice(&data.folder_nonce[..]);

    let aead = XChaCha20Poly1305::new(&key_ga);

    let encoded = aead.encrypt(&nonce_ga, foldername.as_bytes().as_ref()).expect("Encryption failure");

    let encoded_str = format!("{}.encrypted", hex::encode(encoded.clone()));
    if split_path[path_size-1] == ""{
        split_path[path_size-2] = &encoded_str;
    } else {
        split_path[path_size-1] = &encoded_str;
    }

    let dist_path = split_path.join("/");
    fs::rename(source_path, dist_path)?;
    
    Ok(())
}

pub fn decrypt_foldername(
    encrypted_path: &String,
    data: &masterfile::MasterfileData,
) -> Result<(), anyhow::Error> {
    let argon2_config = functions::argon2_config();
    let key = argon2::hash_raw(&data.master_key, &data.folder_salt, &argon2_config)?;

    let mut split_path = encrypted_path.split("/").collect::<Vec<&str>>();
    let path_size = split_path.len();
    let mut encrypted_foldername = String::from(split_path[path_size-1]);
    if encrypted_foldername == "" {
        encrypted_foldername = String::from(split_path[path_size-2]);
    }
    encrypted_foldername.truncate(encrypted_foldername.len()-10);

    let to_decrypt = hex::decode(encrypted_foldername.clone()).unwrap();

    let key_ga = GenericArray::clone_from_slice(&key[..]);

    let nonce_ga = GenericArray::clone_from_slice(&data.folder_nonce[..]);

    let aead = XChaCha20Poly1305::new(&key_ga);

    let decoded = aead.decrypt(&nonce_ga, to_decrypt.as_ref()).expect("Encryption failure");

    let decoded_str = std::str::from_utf8(&decoded).unwrap();

    if split_path[path_size-1] == ""{
        split_path[path_size-2] = &decoded_str;
    } else {
        split_path[path_size-1] = &decoded_str;
    }

    let dist_path = split_path.join("/");

    fs::rename(encrypted_path, dist_path)?;
    Ok(())
}