# Ask Ahmed

A Handy little buddy to ask if a file is ok  
Heavily inspired by [this reddit post](https://www.reddit.com/r/thomastheplankengine/comments/1l5zf4e/i_recreated_usignbear999s_ahmed_program_dream/?utm_source=share&utm_medium=web3x&utm_name=web3xcss&utm_term=1&utm_content=share_button)

# Installation

Go to the [Releases](https://github.com/ErmitaVulpe/ask-ahmed/releases) page, download the latest installer and run it

# Uninstalling

To uninstall go to:  
Settings > Apps > Apps & features  
Search for `ask-ahmed` and press `Uninstall`

# Changing the API key

Go to the installation folder (by default `C:\Program Files\ask-ahmed`) and edit the `settings.ini` file

# Compiling

To compile the program yourself, install the Rust compiler toolchain ([available here](https://www.rust-lang.org/tools/install)), and then run the following commands
```sh
git clone https://github.com/ErmitaVulpe/ask-ahmed
cd ask-ahmed
cargo b -r
```
The compiled program will be at `target/release/ask-ahmed.exe`

## Generating the installer

To generate the installer you will need the `Wix toolset v3` which you can download [here](https://github.com/wixtoolset/wix3/releases), and the cargo-wix tool
```sh
# To download cargo-wix
cargo install cargo-wix

# Then to compile
cargo wix
```
The compiled installer will be inside of `target/wix/`

# Showcase

![Context menu](https://github.com/ErmitaVulpe/ask-ahmed/blob/master/showcase/context_menu.png "Context menu")  
  
![Bad](https://github.com/ErmitaVulpe/ask-ahmed/blob/master/showcase/bad.png "Bad")  
  
![Good](https://github.com/ErmitaVulpe/ask-ahmed/blob/master/showcase/good.png "Good")  

# License

This project is licensed under the MIT License — see the [LICENSE](https://github.com/ErmitaVulpe/ask-ahmed/blob/master/LICENSE) file for details
