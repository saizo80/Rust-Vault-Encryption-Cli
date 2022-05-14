// Import external crates
use std::{
    fs,
    fs::File,
    io::{self, Write, BufRead},
    path::Path,
    thread,
    sync::atomic::{
        AtomicUsize,
        Ordering,
    },
    time::Duration,
};

// Import functions from other files
use crate::{
    encryptionFunctions,
    masterfile,
    vault::vault::Vault,
};

// Set static variable for later thread collection
static GLOBAL_THREAD_COUNT: AtomicUsize = AtomicUsize::new(0);

///
/// Will get input from the user after displaying the passed string.
/// # Arguments
/// - `output: &str`
///     - Will display this when asking for input
/// 
/// Returns `String`
/// 
pub fn get_input(output: &str) -> String {
    // TODO Return Result<String, anyhow::Error>
    // Instantiate the String for reading the line
    let mut line = String::new();
    
    // Print out the passed value
    println!("{} ", output);

    // Read input into the line variable and call the 
    // function to clean the input and return the result
    std::io::stdin().read_line(&mut line).unwrap();
    return clean_input(line);
}

///
/// Clean the input from the user, removing unneccesary things
/// from the String.
/// # Arguments
/// - `mut input: String`
///     - String to be cleaned
/// 
/// Returns `String`
/// 
fn clean_input(mut input: String) -> String {
    // Remove carriage return characters
    if let Some('\n')=input.chars().next_back() {input.pop();}
    if let Some('\r')=input.chars().next_back() {input.pop();}

    // Remove the first and last characters if they are ' or whitespace (macos)
    if let Some('\'')=input.chars().next_back() {input.pop();}
    if let Some(' ')=input.chars().next_back() {input.pop();}
    if let Some('\'')=input.chars().next() {input.remove(0);}
    return input;
}

///
/// Instantiate the argon2 config object
/// 
/// Returns `argon2::Config<'a>`
/// 
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

///
/// Get password input from the user. Will ask twice to make sure passwords
/// match.
/// # Arguments
/// - `output: &str`
///     - Will output this when asking for the password
/// 
/// Returns `String`
/// 
pub fn get_password_input(output: &str) -> String {
    // TODO Return Result<String, anyhow::Error>
    let mut _password1 = String::new();
    loop {
        _password1 = rpassword::prompt_password(output).unwrap();
        let password2 = rpassword::prompt_password("Confirm password: ").unwrap();
        if _password1 == password2 {
            break
        }
        println!("Passwords do not match. Try again.");
    }
    return _password1;
}

///
/// Check whether the given path is a file.
/// # Arguments
/// - `path: &String`
///     - Path to be checked
/// 
/// Returns `bool`
/// 
pub fn check_file(path: &String) -> bool {
    return fs::metadata(path).unwrap().file_type().is_file()
}

///
/// Check whether the given path is a directory
/// # Arguments
/// - `path: &String`
///     - Path to be checked
/// 
/// Returns `bool`
/// 
pub fn check_dir(path: &String) -> bool {
    return fs::metadata(path).unwrap().file_type().is_dir()
}

///
/// Given a Vector (Vec<u8>), will return an Array [u8] of 
/// appropriate size.
/// # Arguments 
/// - `v: Vec<T>`
///     - Vector of generic type to be moved into Array
/// 
/// Returns `[T; N]`
/// 
pub fn into_array<T, const N: usize>(v: Vec<T>) -> [T; N] {
    v.try_into()
        .unwrap_or_else(|v: Vec<T>| panic!("Expected a Vec of length {} but it was {}", N, v.len()))
}

///
/// Main function for directory recursion. Will scan each directory for files and 
/// directories. If a file is found it will be encrypted or decrypted depending on the
/// passed value for `force_encrypt`. If a directory is found, a new thread will be spawned
/// and the function will be recursively called with the updated path of the directory.
/// # Arguments
/// - `path: &String`
///     - The path of the directory to scan.
/// - `data: &masterfile::MasterfileData`
///     - The data of the decrypted masterfile. 
///         - Masterkey for decryption/encryption
///         - Folder Nonce and Salt for directory name encryption/decryption
/// - `force_encrypt: bool`
///     - The bool will determine whether files are encrypted or decrypted.
/// 
/// Returns `Result<(), anyhow::Error>`
/// 
pub fn dir_recur(
    path: &String, 
    data: &masterfile::MasterfileData,
    force_encrypt: bool,
) -> Result<(), anyhow::Error> {
    let paths = fs::read_dir(path).unwrap();
        for path_inv in paths {
            let x = path_inv?.path().into_os_string().into_string().unwrap();
            if check_dir(&x) {
                // Clone data for moving to new thread
                let tx = x.clone();
                let tdata = data.clone();
                let tbool = force_encrypt.clone();

                // Increment the global thread count
                GLOBAL_THREAD_COUNT.fetch_add(1, Ordering::SeqCst);
                thread::spawn(move|| {
                    dir_recur(&tx, &tdata, tbool).unwrap();
                    
                    // Once recursion is finished, decrement the global thread count
                    GLOBAL_THREAD_COUNT.fetch_sub(1, Ordering::SeqCst);
                });      
            }
            else {
                // If the path is a file, decrypt or encrypt depending on the passed
                // bool `force_encrypt`
                if !x.ends_with("masterfile.e") && !x.ends_with(".DS_Store")
                    && !x.ends_with("Icon") {
                    if x.ends_with(".encrypted") && !force_encrypt {
                        encryptionFunctions::decrypt_file(&x, &data.master_key).ok();
                    }
                    else if !x.ends_with(".encrypted") && force_encrypt {
                        encryptionFunctions::encrypt_file(&x, &data.master_key).ok();
                    }
                }
            }
        }
    Ok(())
}

///
/// Function for encrypting/decrypting directory names. This cannot be called
/// during the initial recursion of the directory tree due to the multithreading.
/// Some threads will finish before others, and will change the directory name, preventing
/// other threads from finished due to the incorrect path.
/// # Arguments
/// - `path: &String`
///     - Path to the directory
/// - `data: &masterfile::MasterfileData`
///     - Data from the decrypted masterfile
/// - `force_encrypt: bool`
///     - Determines whether to encrypt or decrypt
/// 
/// Returns `Result<(), anyhow::Error>`
/// 
fn folder_recur(
    path: &String, 
    data: &masterfile::MasterfileData,
    force_encrypt: bool,
) -> Result<(), anyhow::Error> {
    let paths = fs::read_dir(path).unwrap();
        for path_inv in paths {
            let x = path_inv?.path().into_os_string().into_string().unwrap();
            if check_dir(&x) {
                folder_recur(&x, &data, force_encrypt)?;
                if x.ends_with(".encrypted") && !force_encrypt{
                    encryptionFunctions::decrypt_foldername(&x, &data)?;
                } else if !x.ends_with(".encrypted") && force_encrypt{
                    encryptionFunctions::encrypt_foldername(&x, &data)?;
                }
            }
        }
    Ok(())
}

///
/// Check to see if the config file is present.
/// If not, it will create it
/// # Arguments
/// - `config_path` string that points to the config file
/// 
pub fn check_config_file(config_path: &String) -> Result<(), anyhow::Error> {
    if !Path::new(&config_path).exists() {
        if !Path::new(&config_path.strip_suffix("/config").unwrap()).exists() {
            fs::create_dir(&config_path.strip_suffix("/config").unwrap())?;
            fs::File::create(&config_path)?;
        }
        else {
            fs::File::create(&config_path)?;
        }
    }
    Ok(())
}

///
/// Allows for reading files by lines. Returns an iterator to read 
/// over the lines of data.
/// # Arguments
/// - `filename: P`
///     - Path of file to read
/// 
/// Returns `io::Result<io::Lines<io::BufReader<File>>>`
/// 
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

///
/// Read the config file and returns a Vector of Vault objects
/// created from the data.
/// # Arguments
/// - `config_path: &str`
///     - Path to the config file
/// 
/// Returns `Vec<Vault>`
/// 
pub fn read_config_file(config_path: &str) -> Vec<Vault> {
    // Instantiate the Vector
    let mut vaults: Vec<Vault> = Vec::new();

    if let Ok(lines) = read_lines(config_path) {
        for line in lines {
            if let Ok(data) = line {
                // data is a string, split by comma
                let datal = data.split(",").collect::<Vec<&str>>();

                // Make sure data is appropriate length
                if &datal.len() > &1 {
                    // Create a new Vault object and push into the Vector
                    // datal[0] will be the name
                    // datal[1] will be the path 
                    vaults.push(
                        Vault::new(String::from(datal[0]), 
                        String::from(datal[1])
                    )
                    )
                }
            }
        }
    }
    return vaults;
}

///
/// Function for vault creation. Will add the created vault to
/// the vaults vector, encrypt the masterfile data and write to the 
/// created file, and update the config file with the data for the vault.
/// # Arguments
/// - `vaults: &mut Vec<Vault>`
///     - Vector containing the Vault objects
/// - `config_path: &String`
///     - Path to the config file
/// 
/// Returns `Result<(), anyhow::Error>`
/// 
pub fn create_vault(
    vaults: &mut Vec<Vault>,
    config_path: &String,
) -> Result<(), anyhow::Error> {
    // Clear terminal and print the header
    print!("{}[2J", 27 as char);
    println!("##Create Vault##");

    // Get all the necessary inputs
    let path_to_create = get_input("Enter path for new vault: ");
    let name = get_input("Enter name for new vault: ");
    let password = get_password_input("Enter password for vault: ");

    // Format string with masterfile and add new vault to list
    if path_to_create.ends_with("/") {
        let master_file_path = format!("{}masterfile.e", &path_to_create);
        vaults.push(
            Vault::new(name.clone(), master_file_path)
        );
    } else {
        let master_file_path = format!("{}/masterfile.e", &path_to_create);
        vaults.push(
            Vault::new(name.clone(), master_file_path)
        );
    }

    // Create the masterfile with the password 
    masterfile::create_masterfile(&path_to_create.to_string(), &password.to_string())?;

    // Open the config file and write the vault data
    let mut config_file = fs::OpenOptions::new()
        .write(true)
        .append(true)
        .open(&config_path)?;
    config_file.write_all(format!("{},{}/masterfile.e\n", name, path_to_create).as_bytes())?;
    
    Ok(())
}

///
/// Function for unlocking/locking of a vault. Will call multiple functions
/// to go through the directory tree. 
/// # Arguments
/// - `masterfile_path: String`
///     - Path to the masterfile 
/// - `force_encrypt: bool`
///     - Determines whether to encrypt or decrypt
/// 
/// Returns `Result<(), anyhow::Error>`
/// 
pub fn unlock_lock_vault(
    masterfile_path: String,
    force_encrypt: bool,
) -> Result<(), anyhow::Error> {
    // Read in the data from the masterfile and store in a data structure
    let masterfile_data = 
        masterfile::read_masterfile(&masterfile_path, 
        &get_password_input("Enter vault password: "));
    
    // Get the top of the directory tree
    let top_dir_path = masterfile_path.strip_suffix("/masterfile.e").unwrap().to_string();
    
    // This process tends to take some time so print the process steps
    // out in the terminal
    if force_encrypt {
        println!("Encrypting Files");
    } else {
        println!("Decrypting Files");
    }

    // Recurse through the directory tree
    dir_recur(&top_dir_path, &masterfile_data, force_encrypt)?;

    // Wait for all threads to be finished recurssing
    while GLOBAL_THREAD_COUNT.load(Ordering::SeqCst) != 0 {
        thread::sleep(Duration::from_millis(1));
    }

    // Print process of foldernames
    if force_encrypt {
        println!("Encrypting Foldernames");
    } else {
        println!("Decrypting Foldernames");
    }

    // Encrypt/decrypt foldernames
    folder_recur(&top_dir_path, &masterfile_data, force_encrypt)?;

    Ok(())
}

///
/// Checks the encryption status of the vault files and returns
/// a u8 to signify the status.
/// # Arguments
/// - `path: &String`
///     - Path to the top dir of the vault
/// 
/// Returns `u8`
/// 
pub fn check_vault_status(path: &String) -> u8 {
    // Initialize variables
    let paths = fs::read_dir(path).unwrap();
    let mut en = 0; // Counter for encrypted files
    let mut de = 0; // Counter for decrypted files

        for path_inv in paths {
            let x = path_inv.unwrap().path().into_os_string().into_string().unwrap();

            // If file is encrypted increment the en counter
            if check_file(&x) && !x.ends_with("masterfile.e") 
                && !x.ends_with(".DS_Store") && x.ends_with(".encrypted") {
                    en += 1;
                }

            // If file is plaintext increment the de counter
            else if check_file(&x) && !x.ends_with("masterfile.e") 
            && !x.ends_with(".DS_Store") && !x.ends_with(".encrypted") {
                de += 1;
            }
        }
        // Return the mixed if there are encrypted and plaintext files
        if en != 0 && de != 0 {
            return 2;
        }
        // Return decrypted if there are no encrypted and more than 0 plaintext
        else if en == 0 && de > 0 {
            return 1;
        }
        // Return encrypted if there are no plaintext and more than 0 encrypted
        else if en > 0 && de == 0 {
            return 0;
        }
        // Else return Error number
        else {
            return 3;
        }
}

///
/// Writes the currents vaults in the vaults vector.
/// Will overwrite the current contents of the config file.
/// # Arguments
/// - `vaults: &Vec<Vault>`
///     - Vector of Vault objects
/// - `config_path: &String`
///     - Path to the config file
/// 
/// Returns `Result<(), anyhow::Error>`
/// 
pub fn write_vaults(
    vaults: &Vec<Vault>,
    config_path: &String,
) -> Result<(), anyhow::Error> {
    // Open the config file with options
    let mut config_file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&config_path)?;

    // Write all the data in the vaults
    for i in vaults {
        config_file.write(format!
            ("{},{}", i.name, i.master_file_path)
            .as_bytes())?;
    }
    Ok(())
}
