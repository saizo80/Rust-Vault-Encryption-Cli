use anyhow::anyhow;
use chacha20poly1305::{
    aead::{stream, Aead, NewAead, AeadInPlace},
    XChaCha20Poly1305,
};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::{rngs::OsRng, RngCore,};
use std::{
    fs,
    fs::File,
    io::{Read, Write},
};
use zeroize::Zeroize;

const BUFFER_LEN: usize = 500;

pub fn get_input() -> String {
    let mut line = String::new();
    println!("Enter a filepath: ");
    std::io::stdin().read_line(&mut line).unwrap();
    println!();
    return clean_input(line);
}

fn clean_input(mut input: String) -> String {
    // * Remove carriage return characters
    if let Some('\n')=input.chars().next_back() {input.pop();}
    if let Some('\r')=input.chars().next_back() {input.pop();}

    // * Remove the first and last characters if they are ' or whitespace (macos)
    if let Some('\'')=input.chars().next_back() {input.pop();}
    if let Some(' ')=input.chars().next_back() {input.pop();}
    if let Some('\'')=input.chars().next() {input.remove(0);}
    return input;
}

pub fn argon2_config<'a>() -> argon2::Config<'a> {
    return argon2::Config {
        variant: argon2::Variant::Argon2id,
        hash_length: 32,
        lanes: 8,
        mem_cost: 16 * 1024,
        time_cost: 8,
        ..Default::default()
    };
}

pub fn get_password_input() -> String {
    return rpassword::prompt_password_stdout("Enter password: ").unwrap();
}

pub fn encrypt_filename(
    source_file_path: &str,
    key: &Vec<u8>,
    nonce: &[u8; 24],
) {
    let mut split_path = source_file_path.split("/").collect::<Vec<&str>>();
    let mut filename = split_path[split_path.len()-1];
    let mut buffer: Vec<u8, 128> = Vec::new();
    buffer.extend_from_slice(filename.as_bytes());
    let cipher = XChaCha20Poly1305::new(key[..32].as_ref().into());
    let encrypted_filename = cipher.encrypt_in_place(&nonce, b"", &mut buffer).expect("encryption failure!");
    let temp = std::str::from_utf8(&encrypted_filename).unwrap();
    println!("{}", temp);
    //split_path.pop();
    //split_path.push(std::str::from_utf8(&encrypted_filename).unwrap());
    
}

pub fn encrypt_file(
    source_file_path: &str,
    dist_file_path: &str,
    password: &str,
) -> Result<(), anyhow::Error> {
    let argon2_config = argon2_config();

    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 19];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let mut key = argon2::hash_raw(password.as_bytes(), &salt, &argon2_config)?;

    let aead = XChaCha20Poly1305::new(key[..32].as_ref().into());
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());
    //encrypt_filename(&source_file_path, &key, &nonce);

    let mut source_file = File::open(source_file_path)?;
    // call function to encrypt filename
    let mut dist_file = File::create(dist_file_path)?;

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
    dist: &str,
    password: &str,
) -> Result<(), anyhow::Error> {
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 19];

    let mut encrypted_file = File::open(encrypted_file_path)?;
    // call function to decrypt filename
    let mut dist_file = File::create(dist)?;

    let mut read_count = encrypted_file.read(&mut salt)?;
    if read_count != salt.len() {
        return Err(anyhow!("Error reading salt."));
    }

    read_count = encrypted_file.read(&mut nonce)?;
    if read_count != nonce.len() {
        return Err(anyhow!("Error reading nonce."));
    }

    let argon2_config = argon2_config();

    let mut key = argon2::hash_raw(password.as_bytes(), &salt, &argon2_config)?;

    let aead = XChaCha20Poly1305::new(key[..32].as_ref().into());
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());

    let mut buffer = [0u8; BUFFER_LEN+16];

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

pub fn check_file(path: &String) -> bool {
    return fs::metadata(path).unwrap().file_type().is_file()
}

pub fn check_dir(path: &String) -> bool {
    return fs::metadata(path).unwrap().file_type().is_dir()
}
