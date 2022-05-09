pub mod vault {
    use crate::functions;
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
        pub fn to_string(&self) -> String {
            let mut temp = "Error";
            if self.status == 0 {
                temp = "Locked";
            } else if self.status == 1 {
                temp = "Unlocked";
            } else if self.status == 2 {
                temp = "Mixed";
            }
            return format!("Name:{}\nPath:{}\nStatus:{}", self.name,
                self.path, temp);
        }

        pub fn check_status(&mut self) {
            self.status = functions::check_vault_status(&self.path);
        }
    }
}