# SolNAS

*This program is the third installment of my file sharing programs.*

## Preface

The purpose of this program is to act as a file sharing and storage solution. 
>The suggested way to use this program is to install the program onto a dedicated computer to act as a Pseudo-cloud storage device.
However, this program is small enough and efficient enough to run on just about any computer.

**This entire series of projects was to design an alternative to Opera-GX's MyFlow, as well as dropbox and google drive**

##### If you have any schoolwork, pictures, or labwork to share between devices quickly, I hope you'll choose SolNAS!

# Features

* Can be run on most computers
* Cross-Platform (Windows, Linux, MacOs(?))
* Can be accessed by website or though Client program *(See Client Section)*
* Protected by HTTPS encryption
* Secured using custom API access keys and password protection for endpoints
* Low RAM impact
* Sleek and modern
* Easy to deploy
* Timestamps of user actions recorded in the terminal.
* Compatible with Tailscale VPN **(Recommended)**

--- 

### How to Obtain SolNAS:

**You have two options:**

1. (RECOMMENDED) If You are on windows, Go to the releases page, **download the RAR and extract**. If you are on Linux or a different OS, You might be able to utilize the Linux Mint release zip file. If not, fall back to option two.
2. Option two is to pull the git repository. Follow these instructions from your terminal:

```
# Ensure you have rust downloaded
rustup
```

> If you see an error or nothing, get rust. 
> https://rust-lang.org/tools/install/

```
# Go make a directory for the github.
mkdir SolNAS
cd SolNAS
git clone https://github.com/Bunto-man/SolNAS.git
```

> Next, you will need to use the cargo commands to build your executable.

```
# Assuming you are in the github directory:
cargo build --release
# Your exe file or your executible will be in /target/release
```
- I will leave making a custom launcher up to you. It's good practice on Linux.
- EXE files work out of the box on windows.

### Using the Client Program

> The Client program for SolNAS provides unparalleled felxibility and administative control over your experience using SolNAS, so much so that it should be required.

Here are a few of the perks to using the Client program. 
1. Use the Server config button to change upload speed and max upload file size.
2. Use the move buttons to shuffle folders and files to different directories.
3. Use the add folder button to add a folder of your choice.
4. Use the delete button to delete files and entire folders.

##### The Client Program can be found here:

[SolNAS Client](https://github.com/Bunto-man/SolNAS_Client)


