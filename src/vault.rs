/// 
/// Module for Vault object
/// 
#[allow(clippy::module_inception)]
pub mod vault {
    // Import functions from file
    use crate::functions;

    ///
    /// Data structure for Vault
    /// # Argument
    /// - `name: String`
    ///     - Name of the vault
    /// - `master_file_path: String`
    ///     - Path to the masterfile
    /// - `path: String`
    ///     - Path to the top directory of the vault
    /// - `status: u8`
    ///     - Indicated encryption status of the vault
    ///         - 0: locked
    ///         - 1: unlocked
    ///         - 2: mixed
    ///         - 3: None/Error
    /// 
    #[derive(Clone)]
    pub struct Vault {
        pub name: String,
        pub master_file_path: String,
        pub path: String,
        pub status: u8, 
    }
    
    impl Vault{
        ///
        /// Initialization for the Vault object
        /// # Arguments
        /// - `name: String`
        ///     - Name of the vault
        /// - `master_file_path: String`
        ///     - Path of the masterfile
        /// 
        /// Returns `Vault`
        /// 
        pub fn new(
            name: String, 
            master_file_path: String,
        ) -> Vault{
            // Strip suffix to get the top dir path
            let path: String = String::from(master_file_path
                .strip_suffix("/masterfile.e").unwrap());

            // Set initial encryption status
            // TODO: Status is immediated rechecked so set this as a simple initialized variable
            let status = functions::check_vault_status(&path);
            Vault {
                name,
                master_file_path,
                path,
                status,
            }
        }

        ///
        /// Checks the status and gives choice to encrypt when mixed status.
        /// 
        pub fn check_status(&mut self) -> Result<(), anyhow::Error> {
            self.status = functions::check_vault_status(&self.path);
            if self.status == 2 {
                print!("{}[2J", 27 as char);
                println!("##Warning##");
                let input = functions::get_input(
                    &format!("Status of vault [{}] is MIXED. Encrypted unencrypted files? [Y/N]\nWarning leaving unencrypted files WILL cause problems",
                     self.name)[..]);
                if input.to_lowercase() == "y" {
                    functions::unlock_lock_vault
                        (self.master_file_path.clone(), true)?;
                    self.check_status()?;
                }
            }
            Ok(())
        }
    }
}
