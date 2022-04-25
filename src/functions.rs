use std::fs;
use anyhow::anyhow;
use chacha20poly1305::{
    aead::{stream, Aead, NewAead},
    XChaCha20Poly1305,
};

pub fn get_input() -> String {
    let mut line = String::new();
    println!("Enter a filepath: ");
    std::io::stdin().read_line(&mut line).unwrap();
    println!();
    if let Some('\n')=line.chars().next_back() {line.pop();}
    if let Some('\r')=line.chars().next_back() {line.pop();}
    return clean_input(line);
}

fn clean_input(mut input: String) -> String {
    // * Remove the first and last characters if they are ' (macos)
    if let Some('\'')=input.chars().next_back() {input.pop();}
    if let Some('\'')=input.chars().next() {input.remove(0);}
    return input;
}

pub fn encrypt_small_file(
    filepath: String,
    dist: String,
    key: &[u8; 32],
    nonce: &[u8; 24],
) -> Result<(), anyhow::Error> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let file_data = fs::read(filepath)?;
    let encrypted_file = cipher
        .encrypt(nonce.into(), file_data.as_ref())
        .map_err(|err| anyhow!("Encrypting small file: {}", err))?;
    fs::write(&dist, encrypted_file)?;

    Ok(())
}