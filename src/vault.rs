pub mod vault {
    use crate::functions;
    #[derive(Clone)]
    pub struct Vault {
        pub name: String,
        pub master_file_path: String,
        pub path: String,
        pub status: u8, 
    }
    
    impl Vault{
        /// Name 
        ///  
        /// Master File Path
        /// 
        /// Status:
        /// - 0 = locked
        /// - 1 = unlocked
        /// - 2 = mixed
        /// - 3 = None/Error
        pub fn new(
            name: String, 
            master_file_path: String,
        ) -> Vault{
            let path: String = String::from(master_file_path
                .strip_suffix("/masterfile.e").unwrap());
            let status = functions::check_vault_status(&path);
            Vault {
                name,
                master_file_path,
                path,
                status,
            }
        }

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
