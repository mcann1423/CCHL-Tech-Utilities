# CCHL Tech Utilities

Windows utilities maintained by CCHL Technology.

## Mount MSU Files

`Mount-MSUFiles.ps1` is a Windows PowerShell 5.0+ utility for creating persistent drive mappings to Montclair State University file shares.  It provides a one-shot WinForms interface for adding, editing, connecting, and disconnecting saved mappings. `Mount-MSUFiles.bat` is the recommended launcher.

### Requirements

- Windows with PowerShell 5.0 or later
- Network access and permission to the relevant MSU file shares
- A valid MSU account

### Use

1. Download or clone this repository.
2. Double-click `Mount-MSUFiles.bat`, or run it from a Command Prompt.
3. On first use, enter your MSU username and password. The utility creates and reconnects the three standard mappings below.
4. Mappings use Windows `net use /persistent:yes` and remain available after the utility exits.

For unattended mounting of already saved mappings:

```powershell
.\Mount-MSUFiles.ps1 -NoUI
```

To remove the locally saved credential data:

```powershell
.\Mount-MSUFiles.ps1 -Uninstall
```

### Default mappings

| Drive | Share |
| --- | --- |
| N: | `\\msufiles.montclair.edu\facstaff_vol1\<username>` |
| O: | `\\msufiles.montclair.edu\groupshare_vol1\groups` |
| P: | `\\msufiles.montclair.edu\pubweb_vol1\<username>` |

### Credential data and security

Saved data is stored per user under `%USERPROFILE%\.msufiles\`; it is intentionally excluded from Git. The script encrypts the saved credential file, but its key-derivation value is embedded in the script. Treat that storage as local convenience protection—not equivalent to Windows credential vaulting or strong secret management. Never commit credential files or passwords.

### Status

This utility has not yet been validated against a Windows workstation and live MSU shares. Test with a non-critical account before broad deployment.
