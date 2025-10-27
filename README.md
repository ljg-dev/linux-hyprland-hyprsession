# Hyprsession
## Overview
This repository is a fork of [joshurtree/hyprsession](https://github.com/joshurtree/hyprsession). It implements session persistence for Hyprland by periodically saving the command, workspace, and other properties of running clients found by `hyprctl clients`. These are then saved to a file formatted as a Hyprland config file which can be sourced so that the session is restored when Hyprland is restarted.

### Fork additions

Compared to upstream, this fork focuses on streamlining and hardening secret management:

- Automatically generates a strong random passphrase the first time Hyprsession runs and stores it in a Secret Service compatible keyring (GNOME Keyring or KWallet with the Secret Service plugin). No manual prompts or plaintext storage are required.
- Falls back to an interactive prompt only if the keyring is unavailable, preventing accidental runs with weak or reused passphrases.
- Documents end-to-end setup for GNOME and KDE environments, including NixOS/Home Manager snippets.

## Installation
#### Manual
As root run the command 
```
cargo install --root /usr/local hyprsession
``` 
Or install as a user by replacing `/usr/local` with your home directory. 

### Runtime dependencies

Hyprsession expects these components to be available when it runs:

- Hyprland (specifically the `hyprctl` binary) to enumerate and dispatch client state.
- A Secret Service compatible keyring that exposes the `secret-tool` CLI. Hyprsession works out of the box with GNOME Keyring and can also use KDE's KWallet when its Secret Service plugin is enabled (see below for setup steps).
- `secret-tool` (provided by most distributions through the `libsecret` package) for talking to the Secret Service API.
- A running user D-Bus session, which desktop environments typically already start.
- If `secret-tool` is missing, Hyprsession prints `Failed to create passphrase in GNOME Keyring automatically: I/O error: No such file or directory (os error 2)` and falls back to prompting for a passphrase. Install `libsecret` (or your distribution's equivalent) to resolve the issue.

### Build dependencies

If you are compiling from source you will need:

- A recent Rust toolchain (`cargo`, `rustc`) with edition 2021 support.
- `pkg-config` and development headers for `glib`/`libsecret` when building on distributions that require them for linking the `secret-tool` helper.

#### Arch Linux
Hyprsession can be installed via the AUR. By either running your aur package manager of choice or manually by running
```
git clone https://aur.archlinux.org/hyprsession.git
cd hyprsession
makepkg -i
```
#### NixOS
Add the input to your `flake.nix`
```
hyprsession.url = "github:ljg-dev/linux-hyprland-hyprsession"
```

Then either add the package to your `configuration.nix` or use `${inputs.hyprsession.packages.${pkgs.system}.hyprsession}/bin/hyprsession` in place of `hyprsession` to run the program.

When integrating the program on NixOS you can use one of the following examples (adapt them to match your display manager/PAM stack).

**System-wide (NixOS module)**

```nix
{
  # start GNOME Keyring inside the login session
  services.gnome.gnome-keyring.enable = true;
  security.pam.services.greetd.enableGnomeKeyring = true; # swap greetd for your display manager

  # expose hyprsession and secret-tool on PATH
  environment.systemPackages = with pkgs; [
    hyprsession
    gnome-keyring
    libsecret
  ];
}
```

**User-level (Home Manager)**

```nix
{
  services.gnome-keyring = {
    enable = true;
    components = [ "secrets" "ssh" ];
  };
}
```

With these dependencies in place Hyprsession will automatically generate and persist a strong passphrase in your keyring the first time it runs.

### Verification

You can confirm that everything is wired up before relying on automatic session restores:

1. Launch Hyprsession in simulation mode so it does not touch your running Hyprland session:

   ```bash
   hyprsession --mode save-only --simulate
   ```

2. Run `secret-tool lookup hyprsession passphrase`. If the setup succeeded, the stored passphrase is printed without prompting and subsequent Hyprsession runs will skip any interactive questions.

### GNOME Keyring setup

Most GNOME-based environments ship everything you need, but here is a quick checklist:

1. Install `gnome-keyring`, `libsecret`, and optionally `seahorse` if you want a GUI to inspect stored secrets.
2. Ensure the PAM service you log in through loads GNOME Keyring. On GDM this is done automatically; on SDDM/greetd follow the NixOS/Home Manager examples above or add `pam_gnome_keyring.so` to your PAM stack.
3. Log out and sign back in so the daemon starts, then run `secret-tool search hyprsession passphrase`. It should exit successfully even though it returns no results yet, confirming the Secret Service is available.
4. Start Hyprsession. It will generate a random passphrase, store it in the `login` keyring, and reuse it silently on subsequent launches. Verify with `secret-tool lookup hyprsession passphrase`.

### KDE / KWallet setup

KWallet can provide the same Secret Service API that GNOME Keyring does, but it needs a little preparation:

1. Install the required packages (names may vary slightly per distro):
   - `kwallet`, `kwalletmanager`, and `kwallet-pam`
   - `plasma-workspace` (contains the Secret Service plugin)
   - `libsecret` (for the `secret-tool` binary Hyprsession calls)
2. Open *KWallet Manager* → Settings → *Enable Secret Service support*. This turns on the Secret Service plugin so `secret-tool` can talk to the wallet.
3. Ensure `kwalletd5` starts when you log in. On Plasma this happens automatically once the PAM module is configured; otherwise add `kwallet-pam` to your login manager or run `kwalletd5` from your session startup.
4. Log out and sign back in so the wallet daemon launches and the Secret Service interface is registered on D-Bus.
5. Run `secret-tool lookup hyprsession passphrase`. The first call should return nothing, but it confirms the service is available. After Hyprsession starts once, the same command should print the stored passphrase without prompting.

Once KWallet exposes the Secret Service API, Hyprsession uses it the same way it uses GNOME Keyring — automatically generating and saving a strong passphrase on first launch.

### Limitations

- Only keyrings that implement the freedesktop Secret Service API are supported today. Alternate password stores such as 1Password CLI, KeePass, or `pass` are not yet integrated.
- Session signatures and salts are stored under `~/.local/share/hyprsession`. 
- Automatic passphrase creation writes secrets through `secret-tool`; if you use a different D-Bus implementation or disable the Secret Service plugin, the flow falls back to manual prompts.

### Security notes

- Hyprsession derives all cryptographic keys using Argon2 and immediately clears the plaintext passphrase from memory via the `Zeroizing` wrapper once the key material is ready.
- The stored files (`exec.json`, signature, and salt) are validated on load and reject world-writable executables or symlinks to avoid executing tampered data.
- Treat the generated keyring entry like a password: anyone with access to that secret can decrypt your session data.

## Usage
To automaticly run the program in future sessions add the following line to your Hyprland config file (Usually at ~/.config/hypr/hyprland.conf)
```
exec-once = hyprsession
```
The same line can be added to your `home.nix` hyprland configuration if your are using Nix Home Manager.
If you want to save a session that is already running then run
```
hyprsession --mode save-only &
```
or
```
hyprsession --mode save-and-exit
```

## Options
Various options can be used to modify the behavior of Hyprsession.

### --mode <mode>
Sets the mode the program runs in 
* Default - Loads the session at startup the saves the current session at regular intervals.
* SaveOnly - As above but skips loading the session
* LoadAndExit - Load the saved session then immediatly exit
* SaveAndExit - Save the current session then exit

### --save-interval n
This sets the interval in seconds between session saves. The default is 60 seconds.

### --session-path
This allows the user to save the session config in an alternative directory, by default its ~/.local/share/hyprsession. 

## Fork change log

- **2025-10-27** – Added automatic keyring-backed passphrase generation, GNOME/KWallet setup guides, verification steps, and improved documentation for NixOS and Home Manager users.

## TODO
* Create and use a rules file for alternative handling of applications (i.e. do not reload, ignore parameters, additional parameters etc).
* Handle application that create windows in forked processes by creating temporary window rules.

## Change log
### 0.1.1
* Changed --session-path option to point at base directory of session file
### 0.1.2
* Fixed bug which would crash program if no session file existed
### 0.1.3
* Fix fatal bug on Hyprland 0.4 that crashed the program while saving the session  
### 0.1.4
* Changed fullscreen dispatcher to use fullscreenmode and fixed FullscreenMode type issue (#2)
* Updated to latest alpha version of hyprland crate. Fixes panic on fetching clients (#1)
 
### 0.1.5
* Skip saving clients with duplicate pids (i.e. generated by the same application)
* Add option to retain clients with duplicate pids

## Thanks

Thank you to the following people for helping to improve this project

* Tie C (ticia)
* Isaac Hesslegrave (HeadedBranch)
