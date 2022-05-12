# Rust Vault Encryption
***
## About
This program is meant to create '*vaults*' that are at the top of a directory tree and can encrypt and decrypt the files and folders therein. The masterfile, named *masterfile.e* is encrypted with the vault password, and holds all the information to encrypt and decrypt the vault files and foldernames. The masterfile's contents are never written to the disk unencrypted, even during creation. The contents are only decrypted into memory, and are zeroized when finished being used.  
It needs to be said that this program is written for UNIX systems, MacOS and Linux, and has **not** been tested on Windows.

## Installation
- First, install rustc and cargo using this script -> `curl https://sh.rustup.rs -sSf | sh` 
	- **Note, script is taken straight from the rust website so it should be safe to run, but as always please verify all script files before running.**
- After installing rust, the binary of this program can be installed simply by running `cargo install --git https://github.com/saizo80/Rust-Vault-Encryption.git`
- Then simply type `rusty-vault` in a terminal and the program will run

## Usage
The usage of the program is straightforward in the menus that are presented. When it asks for a file path it is possible to drag and drop the file from any file explorer into the terminal window. The program should be able to clean up any input that is given in that manner.

Upon launching, if there are vaults with mixed files (encrypted and unencrypted) you will be warned and given the option to encrypt the plaintext files. While a choice is given for this scenario, you will not be able to encrypt or decrypt the vault while the files are mixed, therefore I would recommend encrypting the loose files before proceeding. 

## TODO
- [ ] Write comments and document code
- [ ] Make option to return to main menu in branching menus