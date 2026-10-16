#Requires -Version 5.0
<#
    .SYNOPSIS
        Mount MSU Files - encrypted credential manager with GUI for SMB mounts.

    .DESCRIPTION
        One-shot PowerShell utility providing:
          Connect / Disconnect  MSU Files drives
          Manage saved credentials (add / edit / delete)
          Update stored passwords
          Wipe all credentials

    .PARAMETER NoUI
        Skip the GUI; mount every currently-saved credential and exit.

    .PARAMETER Uninstall
        Permanently erase all credential data. Requires confirmation.

    .NOTES
        Drive mappings use /persistent:yes so they survive logoff / reboot.
        Three defaults are pre-configured:
          N: \\msufiles.montclair.edu\facstaff_vol1\<username>   Personal home
          O: \\msufiles.montclair.edu\groupshare_vol1\groups     Shared groups
          P: \\msufiles.montclair.edu\pubweb_vol1\<username>      Public web root
#>

param([switch]$NoUI, [switch]$Uninstall)

#  Pre-flight
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host 'PowerShell 5.0+ is required.' -ForegroundColor Red; exit 1
}

$headless = $false
try {
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
    Add-Type -AssemblyName System.Drawing              -ErrorAction Stop
    [System.Windows.Forms.Application]::EnableVisualStyles()
} catch { $headless = $true }
if ($headless -and -not $NoUI) { $NoUI = $true }

#  Globals
$Script:CredDir       = Join-Path $env:USERPROFILE '.msufiles'
$Script:CredFile      = Join-Path $Script:CredDir 'credentials.json'
$Script:ProfilesFile  = Join-Path $Script:CredDir 'profiles.json'
$Script:UserName      = $env:USERNAME
$Script:ServerBase    = 'msufiles.montclair.edu'
$Script:DefaultPepper = 'MSU-Files-Pepper-2026-NeverChangeThis1234'
$Script:AllDrives     = @('N', 'O', 'P')

#
#  Encryption helpers
#
function Get-KeyBytes {
    param([string]$salt)
    $pbkdf2 = New-Object Security.Cryptography.Rfc2898DeriveBytes(
        $Script:DefaultPepper,
        [Convert]::FromBase64String($salt),
        100000,
        [Security.Cryptography.HashAlgorithmName]::SHA256
    )
    return $pbkdf2.GetBytes(32)
}

function Encrypt-Value {
    param([string]$plaintext, [byte[]]$key)
    $aes = [Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256; $aes.Mode    = 'CBC'
    $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
    $aes.GenerateIV()

    $iv   = [byte[]]$aes.IV.Clone()
    $enc  = $aes.CreateEncryptor($key, $iv)
    $plainBytes = [Text.Encoding]::UTF8.GetBytes($plaintext)
    $ct = $enc.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
    $blob = New-Object byte[] ($iv.Length + $ct.Length)
    $iv.CopyTo($blob, 0); $ct.CopyTo($blob, $iv.Length)
    $enc.Dispose(); $aes.Dispose()
    return [Convert]::ToBase64String($blob)
}

function Decrypt-Value {
    param([string]$blob, [byte[]]$key)
    $raw = [Convert]::FromBase64String($blob)
    if ($raw.Length -lt 16) { throw 'Invalid credential blob.' }

    $aes = [Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256; $aes.Mode = 'CBC'
    $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7

    $iv = $raw[0..15]; $ct = $raw[16..($raw.Length - 1)]
    $dec = $aes.CreateDecryptor($key, $iv)
    $pt  = $dec.TransformFinalBlock($ct, 0, $ct.Length)
    $aes.Dispose(); $dec.Dispose()
    return [Text.Encoding]::UTF8.GetString($pt)
}

#
#  Credential file I/O
#
function Read-Meta {
    $f = Join-Path $Script:CredDir 'meta.json'
    if (-not (Test-Path $f)) { return $null }
    try { return (Get-Content $f -Raw) | ConvertFrom-Json }
    catch { return $null }
}

function Write-Meta {
    param($obj)
    $f = Join-Path $Script:CredDir 'meta.json'
    $obj | ConvertTo-Json -Depth 5 | Set-Content $f -Encoding UTF8
}

function Read-Credentials {
    # Returns an array of @{ id server share_path username label drive_letter _password }
    $meta = Read-Meta
    if (-not $meta.salt) { return @() }

    if (-not (Test-Path $Script:CredFile)) { return @() }

    $key   = Get-KeyBytes -salt $meta.salt
    $lines = (Get-Content $Script:CredFile -Raw) | ConvertFrom-Json
    $out   = @()

    foreach ($r in $lines) {
        try {
            $pwd = Decrypt-Value -blob $r.encrypted_password -key $key
        } catch {
            $pwd = '<decrypt error>'
        }
        $out += @{
            id               = $r.id
            server           = $r.server
            share_path       = $r.share_path
            username         = $r.username
            label            = $r.label
            drive_letter     = $r.drive_letter
            _password        = $pwd
        }
    }
    return $out
}

function Write-Credentials {
    param([object[]]$entries)

    $meta = Read-Meta
    if (-not $meta.salt) {
        $rng = New-Object Security.Cryptography.RNGCryptoServiceProvider
        $salt = New-Object byte[] 16
        $rng.GetBytes($salt)
        $rng.Dispose()
        $meta = @{ version = 1; salt = [Convert]::ToBase64String($salt) }
        Write-Meta -obj $meta
    }

    $key = Get-KeyBytes -salt $meta.salt

    # Build JSON array: accumulate objects then convert once
    $arr = @()
    foreach ($e in $entries) {
        $obj = @{
            id                 = $e.id
            server             = $e.server
            share_path         = $e.share_path
            username           = $e.username
            label              = $e.label
            drive_letter       = $e.drive_letter
            encrypted_password = $(Encrypt-Value -plaintext $e._password -key $key)
        }
        $arr += $obj
    }

    # Atomic write via temp file
    $tmp  = Join-Path $Script:CredDir ("creds-{0}.tmp" -f (New-Guid).Guid)
    ($arr | ConvertTo-Json -Depth 10) | Set-Content $tmp -Encoding UTF8
    Move-Item -Path $tmp -Destination $Script:CredFile -Force
}

function Read-Profiles {
    $meta = Read-Meta
    if (-not $meta.salt -or -not (Test-Path $Script:ProfilesFile)) { return @() }
    $key = Get-KeyBytes -salt $meta.salt
    $out = @()
    foreach ($p in @((Get-Content $Script:ProfilesFile -Raw | ConvertFrom-Json)) ) {
        try { $pwd = Decrypt-Value -blob $p.encrypted_password -key $key } catch { continue }
        $out += [pscustomobject]@{ id=$p.id; name=$p.name; username=$p.username; _password=$pwd }
    }
    return $out
}

function Write-Profiles {
    param([object[]]$profiles)
    $meta = Read-Meta
    $key = Get-KeyBytes -salt $meta.salt
    $disk = @()
    foreach ($p in $profiles) {
        $disk += [pscustomobject]@{ id=$p.id; name=$p.name; username=$p.username; encrypted_password=(Encrypt-Value -plaintext $p._password -key $key) }
    }
    ($disk | ConvertTo-Json -Depth 5) | Set-Content $Script:ProfilesFile -Encoding UTF8
}

function Get-DriveMappings {
    param([object]$profile)
    $pathUser = $profile.username
    if ($pathUser.Contains('\')) { $pathUser = $pathUser.Substring($pathUser.LastIndexOf('\') + 1) }
    $networkUser = if ($profile.username.Contains('\')) { $profile.username } else { "admsu\$($profile.username)" }
    return @(
        [pscustomobject]@{ id=(New-Guid).ToString(); drive_letter='N'; server=$Script:ServerBase; share_path="facstaff_vol1\$pathUser"; username=$networkUser; label='Faculty/Staff Home (N:)'; _password=$profile._password }
        [pscustomobject]@{ id=(New-Guid).ToString(); drive_letter='O'; server=$Script:ServerBase; share_path='groupshare_vol1\groups'; username=$networkUser; label='Group Shares (O:)'; _password=$profile._password }
        [pscustomobject]@{ id=(New-Guid).ToString(); drive_letter='P'; server=$Script:ServerBase; share_path="pubweb_vol1\$pathUser"; username=$networkUser; label='Public Web Root (P:)'; _password=$profile._password }
    )
}

function Activate-Profile {
    param([object]$profile)
    $records = Get-DriveMappings -profile $profile
    Write-Credentials -entries $records
    $meta = Read-Meta
    $meta | Add-Member -NotePropertyName active_profile_id -NotePropertyValue $profile.id -Force
    Write-Meta -obj $meta
    return Reconnect-SavedDrives -entries $records
}

function Init-CredDir {
    if (-not (Test-Path $Script:CredDir)) {
        New-Item -ItemType Directory -Path $Script:CredDir -Force | Out-Null
    }
    $meta = Read-Meta
    if (-not $meta.salt) {
        $rng = New-Object Security.Cryptography.RNGCryptoServiceProvider
        $salt = New-Object byte[] 16
        $rng.GetBytes($salt)
        $rng.Dispose()
        $meta = @{ version = 1; salt = [Convert]::ToBase64String($salt) }
        Write-Meta -obj $meta
    }
    if (-not (Test-Path $Script:ProfilesFile)) {
        $legacy = @(Read-Credentials)
        if ($legacy.Count) {
            $user = $legacy[0].username
            $name = 'Default'
            $profile = [pscustomobject]@{ id=(New-Guid).ToString(); name=$name; username=$user; _password=$legacy[0]._password }
            Write-Profiles -profiles @($profile)
            $meta = Read-Meta
            $meta | Add-Member -NotePropertyName active_profile_id -NotePropertyValue $profile.id -Force
            Write-Meta -obj $meta
        }
    }
}

#
#  Mount / Unmount
#
function Expand-SharePath {
    param([string]$p)
    $p -replace 'USERNAME_PLACEHOLDER', $Script:UserName `
       -replace '<username>', $Script:UserName
}

function Mount-OneDrive {
    param([string]$letter, [string]$sharePath, [string]$user,
          [string]$password, [string]$server = $Script:ServerBase)

    if (-not $server) { $server = $Script:ServerBase }
    $spec = '{0}:' -f $letter.ToUpper()
    $unc  = '\\{0}\{1}' -f $server, (Expand-SharePath $sharePath)

    # Already mounted?
    $cur = & net use $spec 2>&1 | Select-String "\\$server"
    if ($cur) { return "$spec already connected" }

    $netOutput = @(& net use $spec $unc $password "/user:$user" /persistent:yes 2>&1)
    $rc = $LASTEXITCODE

    switch ($rc) {
        0     { "$spec mounted -> $unc" }
        5     { "$spec access denied - check username / password" }
        86    { "$spec syntax error - verify UNC path" }
        1219  { "$spec multiple connections not allowed" }
        1326  { "$spec login failed" }
        1314  { "$spec insufficient privileges" }
        default {
            $detail = ($netOutput | ForEach-Object { $_.ToString().Trim() } | Where-Object { $_ }) -join ' '
            if ($detail) { "$spec net-use error code ${rc}: $detail" }
            else { "$spec net-use error code $rc" }
        }
    }
}

function Unmount-All {
    $results = @()
    foreach ($d in $Script:AllDrives) {
        try {
            & net use "${d}:" /delete /y 2>&1 | Out-Null
            $results += "$d disconnected"
        } catch {
            $results += "$d already disconnected"
        }
    }
    return $results
}

function Reconnect-SavedDrives {
    param([object[]]$entries)

    $results = @()
    foreach ($d in $Script:AllDrives) {
        & net use "${d}:" /delete /y 2>&1 | Out-Null
        $results += "${d}: disconnected"
    }
    foreach ($e in $entries) {
        $results += Mount-OneDrive -letter $e.drive_letter -sharePath $e.share_path `
            -user $e.username -password $e._password -server $e.server
    }
    return $results
}

#
#  Headless mode
#
function Run-Headless {
    $creds = Read-Credentials
    if (-not $creds.Count) {
        Write-Host 'No credentials found. Run without --NoUI first to set up.' -ForegroundColor Yellow
        return
    }
    foreach ($e in $creds) {
        $msg = Mount-OneDrive -letter $e.drive_letter -sharePath $e.share_path `
                              -user $e.username -password $e._password -server $e.server
        $isGood = -not ($msg -match '(error|denied|failed|privilege)')
        $col    = if ($isGood) { 'Green' } else { 'Yellow' }
        Write-Host $msg -ForegroundColor $col
    }
}

#
#  Logging helpers (direct textbox operations - no undefined wrapper needed)
#
function Write-LogLine {
    param([string]$msg, [switch]$good)
    $tag  = if ($good) { '+' } else { '-' }
    $clr  = if ($good) { 'Green' } elseif ($msg -match '(error|failed|privilege)') { 'Red' } else { 'Yellow' }
    $txtLog.AppendText("{0} [{1}] {2}{3}" -f (Get-Date 'HH:mm:ss'), $tag, $msg, [Environment]::NewLine)
    $txtLog.ScrollToCaret()
}

#
#  GUI - Main form
#
function Show-Gui {
    #  Top-level controls
    $form       = New-Object System.Windows.Forms.Form
    $form.Text      = 'Mount MSU Files'
    $form.Size      = New-Object System.Drawing.Size(720, 575)
    $form.StartPosition = 'CenterScreen'
    $form.Font      = New-Object System.Drawing.Font('Segoe UI', 9)

    $tc           = New-Object System.Windows.Forms.TabControl
    $tc.Location  = New-Object System.Drawing.Point(10, 10)
    $tc.Size      = New-Object System.Drawing.Size(695, 400)
    $tc.Anchor    = 'Top,Left,Right,Bottom'

    #
    #  TAB 1: Connect / Disconnect
    #
    $flow = New-Object System.Windows.Forms.FlowLayoutPanel
    $flow.Location = New-Object System.Drawing.Point(15, 15)
    $flow.Size     = New-Object System.Drawing.Size(665, 260)
    $flow.AutoScroll = $true
    $flow.Anchor   = 'Top,Left,Right,Bottom'

    $txtLog = New-Object System.Windows.Forms.TextBox
    $txtLog.Multiline    = $true; $txtLog.ReadOnly = $true
    $txtLog.Location     = New-Object System.Drawing.Point(15, 285)
    $txtLog.Size         = New-Object System.Drawing.Size(665, 70)
    $txtLog.Font         = New-Object System.Drawing.Font('Consolas', 8)
    $txtLog.Anchor       = 'Top,Left,Right,Bottom'

    $btnConnect = New-Object System.Windows.Forms.Button
    $btnConnect.Text = 'Connect Selected ->'; $btnConnect.Size = New-Object System.Drawing.Size(150, 35)
    $btnConnect.Location = New-Object System.Drawing.Point(15, 365)

    $btnDisconnect = New-Object System.Windows.Forms.Button
    $btnDisconnect.Text = 'Disconnect All v'; $btnDisconnect.Size = New-Object System.Drawing.Size(150, 35)
    $btnDisconnect.Location = New-Object System.Drawing.Point(175, 365)

    # State dictionary keyed by drive letter
    $g_Checkboxes = @{}

    function Refresh-Checkboxes {
        $flow.Controls.Clear(); $g_Checkboxes.Clear()
        $items = Read-Credentials
        if (-not $items.Count) {
            $grp = New-Object System.Windows.Forms.GroupBox
            $grp.Text  = 'No credentials saved yet'
            $grp.Size  = New-Object System.Drawing.Size(655, 95)
            $grp.Margin = '5,5,5,5'

            $lblMain = New-Object System.Windows.Forms.Label
            $lblMain.Text  = 'Set your MSU username and password to configure N:, O:, and P:.'
            $lblMain.Location = New-Object System.Drawing.Point(10, 20)
            $lblMain.AutoSize = $true

            $btnFirst = New-Object System.Windows.Forms.Button
            $btnFirst.Text = 'Set Up Drives'
            $btnFirst.Location = New-Object System.Drawing.Point(10, 45)
            $btnFirst.Size = New-Object System.Drawing.Size(160, 28)
            $btnFirst.Add_Click({
                if (Save-CredentialForm -newEntry $true) {
                    Refresh-CredList; Refresh-Checkboxes; Refresh-PwdList
                    LogMgmt 'Credentials saved and drives refreshed.'
                }
            })

            $grp.Controls.Add($lblMain)
            $grp.Controls.Add($btnFirst)
            $flow.Controls.Add($grp)
            return
        }
        foreach ($entry in $items) {
            $grp = New-Object System.Windows.Forms.GroupBox
            $grp.Text  = "$($entry.label) [$($entry.drive_letter.ToUpper())]"
            $grp.Size  = New-Object System.Drawing.Size(655, 105)
            $grp.Margin = '2,2,2,2'

            $chk = New-Object System.Windows.Forms.CheckBox; $chk.Checked = $true
            $chk.Location = New-Object System.Drawing.Point(12, 37)
            $chk.Size = New-Object System.Drawing.Size(18, 18)

            $info = New-Object System.Windows.Forms.Label
            $info.Text = 'User: {0}{1}Server: {2}{3}Share: {4}' -f
                            $entry.username, [Environment]::NewLine,
                            $entry.server, [Environment]::NewLine,
                            $entry.share_path
            $info.Location = New-Object System.Drawing.Point(40, 27)
            $info.MaximumSize = New-Object System.Drawing.Size(595, 70)
            $info.Font      = New-Object System.Drawing.Font('Segoe UI', 8)
            $info.AutoSize  = $true

            $grp.Controls.Add($chk); $grp.Controls.Add($info)
            $flow.Controls.Add($grp)
            $g_Checkboxes[$entry.drive_letter] = @{ chk=$chk; entry=$entry }
        }
    }

    $btnConnect.Add_Click({
        $txtLog.Clear(); $ok=0; $fail=0
        foreach ($dl in $g_Checkboxes.Keys) {
            $item = $g_Checkboxes[$dl]
            if (-not $item.chk.Checked) { continue }
            $m = Mount-OneDrive -letter $item.entry.drive_letter `
                                -sharePath $item.entry.share_path `
                                -user $item.entry.username -password $item.entry._password `
                                -server $item.entry.server
            $good = -not ($m -match '(error|denied|failed|privilege)')
            if ($good) { $ok++ } else { $fail++ }
            Write-LogLine -msg $m -good:$good
        }
        $anyChecked = @($g_Checkboxes.Values | Where-Object { $_.chk.Checked }).Count
        if (-not $anyChecked) {
            Write-LogLine -msg 'No drives selected.'; return
        }
        $summary = "Connection complete - success: {0}, failed: {1}" -f $ok, $fail
        Write-LogLine -msg $summary -good:($fail -eq 0)
        [System.Windows.Forms.MessageBox]::Show(
            $summary, 'Mount Complete', 'OK', 'Information'
        )
    })

    $btnDisconnect.Add_Click({
        $txtLog.Clear()
        Unmount-All | ForEach-Object { Write-LogLine -msg $_ -good:$true }
        [System.Windows.Forms.MessageBox]::Show('Done.', 'Unmounted', 'OK', 'Information')
    })

    #
    #  TAB 2: Credentials
    #
    $lstCreds = New-Object System.Windows.Forms.ListBox
    $lstCreds.Location = New-Object System.Drawing.Point(15, 45)
    $lstCreds.Size     = New-Object System.Drawing.Size(665, 200)
    $lstCreds.Anchor   = 'Top,Left,Right,Bottom'

    $btnAdd    = New-Object System.Windows.Forms.Button; $btnAdd.Text  = 'Set Credentials'
    $btnEdit   = New-Object System.Windows.Forms.Button; $btnEdit.Text = 'Update Credentials'
    $btnDelete = New-Object System.Windows.Forms.Button; $btnDelete.Text = 'Clear Saved Data'
    $btnSaveM  = New-Object System.Windows.Forms.Button; $btnSaveM.Text  = 'Refresh Lists'

    $logMgmt = New-Object System.Windows.Forms.TextBox
    $logMgmt.Multiline = $true; $logMgmt.ReadOnly = $true
    $logMgmt.Location  = New-Object System.Drawing.Point(15, 255)
    $logMgmt.Size      = New-Object System.Drawing.Size(665, 55)
    $logMgmt.Font      = New-Object System.Drawing.Font('Consolas', 8)
    $logMgmt.Anchor    = 'Top,Left,Right,Bottom'

    # Position buttons in a row
    $posX = 15
    foreach ($b in @($btnAdd, $btnEdit, $btnDelete, $btnSaveM)) {
        $b.Size   = New-Object System.Drawing.Size(135, 30)
        $b.Location = New-Object System.Drawing.Point($posX, 15)
        $posX += 140
    }

    $btnEdit.Enabled  = $false
    $btnDelete.Enabled = $false

    $lstCreds.Add_SelectedIndexChanged({
        $btnEdit.Enabled  = ($lstCreds.SelectedIndex -ge 0)
        $btnDelete.Enabled = ($lstCreds.SelectedIndex -ge 0)
    })

    function Refresh-CredList {
        $lstCreds.Items.Clear()
        $items = Read-Credentials
        foreach ($e in $items) {
            $lstCreds.Items.Add("$( $e.label ) [$( $e.drive_letter.ToUpper() )]  user: $( $e.username )")
        }
        if (-not $items.Count) { $lstCreds.Items.Add('(none)'); $lstCreds.Enabled = $false }
        else { $lstCreds.Enabled = $true }
    }

    function LogMgmt { param([string]$m) $logMgmt.AppendText("$m`n"); $logMgmt.ScrollToCaret() }

    $btnAdd.Add_Click({
        if (Save-CredentialForm -newEntry $true) {
            Refresh-CredList; Refresh-Checkboxes; Refresh-PwdList; LogMgmt 'Credentials saved and drives refreshed.'
        }
    })
    $btnEdit.Add_Click({
        if (Save-CredentialForm) {
            Refresh-CredList; Refresh-Checkboxes; Refresh-PwdList; LogMgmt 'Credentials saved and drives refreshed.'
        }
    })
    $btnDelete.Add_Click({
        if ($lstCreds.SelectedIndex -lt 0) { return }
        $y = [System.Windows.Forms.MessageBox]::Show(
            'Clear all saved MSU Files credentials?', 'Confirm', 'YesNo', 'Warning')
        if ($y -ne 'Yes') { return }
        if (Test-Path $Script:CredFile) { Remove-Item -Path $Script:CredFile -Force }
        if (Test-Path $Script:ProfilesFile) { Remove-Item -Path $Script:ProfilesFile -Force }
        Refresh-CredList; Refresh-Checkboxes; Refresh-PwdList; LogMgmt 'Saved credentials cleared.'
    })
    $btnSaveM.Add_Click({ Refresh-CredList; Refresh-Checkboxes; Refresh-PwdList; LogMgmt 'Lists refreshed.' })

    #
    #  TAB 3: Change Password
    #
    $banner = New-Object System.Windows.Forms.Label
    $banner.Text    = 'Update the MSU username or password used for all three MSU Files drive mappings.'
    $banner.Location = New-Object System.Drawing.Point(15, 8)
    $banner.Size    = New-Object System.Drawing.Size(665, 35)
    $banner.ForeColor = [Drawing.Color]::OrangeRed
    $banner.Font    = New-Object System.Drawing.Font -ArgumentList ('Segoe UI', [single]9, [System.Drawing.FontStyle]::Bold)
    $banner.Anchor  = 'Top,Left,Right'

    $lstPwd = New-Object System.Windows.Forms.ListBox
    $lstPwd.Location = New-Object System.Drawing.Point(15, 48)
    $lstPwd.Size     = New-Object System.Drawing.Size(665, 110)
    $lstPwd.Anchor   = 'Top,Left,Right'

    $btnUpdatePwd = New-Object System.Windows.Forms.Button
    $btnUpdatePwd.Text = 'Update Credentials'
    $btnUpdatePwd.Size = New-Object System.Drawing.Size(190, 30)
    $btnUpdatePwd.Location = New-Object System.Drawing.Point(15, 165)

    $btnWipe = New-Object System.Windows.Forms.Button
    $btnWipe.Text = 'Clear All Credentials'
    $btnWipe.Size = New-Object System.Drawing.Size(190, 30)
    $btnWipe.Location = New-Object System.Drawing.Point(215, 165)
    $btnWipe.ForeColor = [Drawing.Color]::Red

    $logPwd = New-Object System.Windows.Forms.TextBox
    $logPwd.Multiline = $true; $logPwd.ReadOnly = $true
    $logPwd.Location  = New-Object System.Drawing.Point(15, 205)
    $logPwd.Size      = New-Object System.Drawing.Size(665, 100)
    $logPwd.Font      = New-Object System.Drawing.Font('Consolas', 8)
    $logPwd.Anchor    = 'Top,Left,Right,Bottom'

    function Refresh-PwdList {
        $lstPwd.Items.Clear()
        foreach ($e in Read-Credentials) {
            $lstPwd.Items.Add("$( $e.label ) [$( $e.drive_letter.ToUpper() )] - $( $e.username )")
        }
        if (-not (Read-Credentials).Count) { $lstPwd.Items.Add('(none)'); $lstPwd.Enabled = $false }
        else { $lstPwd.Enabled = $true }
    }
    function LogPwd { param([string]$m) $logPwd.AppendText("$m`n"); $logPwd.ScrollToCaret() }

    $btnUpdatePwd.Add_Click({
        if (Save-CredentialForm) {
            Refresh-PwdList; Refresh-CredList; Refresh-Checkboxes; LogPwd 'Credentials saved and drives refreshed.'
        }
    })

    $btnWipe.Add_Click({
        $y = [System.Windows.Forms.MessageBox]::Show(
            'Permanently erase ALL credentials?  Cannot be undone.',
            'WARNING: Wipe Everything', 'YesNo', 'Warning')
        if ($y -ne 'Yes') { return }
        if (Test-Path $Script:CredDir) { Remove-Item -Path $Script:CredDir -Recurse -Force }
        LogPwd 'Credential store wiped.'
        [System.Windows.Forms.MessageBox]::Show(
            'Credential store wiped. Restart the utility to set up again.',
            'Wiped', 'OK', 'Information')
        $form.Close()
    })

    #
    #  Assemble tabs into tab control
    #
    $tab1 = New-Object System.Windows.Forms.TabPage
    $tab1.Text = 'Connect / Disconnect'
    $tabLbl = New-Object System.Windows.Forms.Label
    $tabLbl.Text = 'Select which drives to mount:'
    $tabLbl.Location = New-Object System.Drawing.Point(15, 0)
    $tabLbl.AutoSize = $true
    $tab1.Controls.AddRange(@($tabLbl, $flow, $txtLog, $btnConnect, $btnDisconnect))

    $tab2 = New-Object System.Windows.Forms.TabPage
    $tab2.Text = 'Credentials'
    $tab2.Controls.AddRange(@($btnAdd, $btnEdit, $btnDelete, $btnSaveM, $lstCreds, $logMgmt))

    $tab3 = New-Object System.Windows.Forms.TabPage
    $tab3.Text = 'Change Password'
    $tab3.Controls.AddRange(@($banner, $lstPwd, $btnUpdatePwd, $btnWipe, $logPwd))

    $tc.Controls.Add($tab1)
    $tc.Controls.Add($tab2)
    $tc.Controls.Add($tab3)

    # Footer
    $foot = New-Object System.Windows.Forms.Label
    $foot.Text  = "User: $($Script:UserName)@$($env:COMPUTERNAME)  |  Server: $($Script:ServerBase)"
    $foot.Location = New-Object System.Drawing.Point(15, 420)
    $foot.AutoSize = $true; $foot.ForeColor = [Drawing.Color]::Gray

    $profileLabel = New-Object System.Windows.Forms.Label
    $profileLabel.Text = 'Active profile:'
    $profileLabel.Location = New-Object System.Drawing.Point(15, 452)
    $profileLabel.AutoSize = $true
    $profileCombo = New-Object System.Windows.Forms.ComboBox
    $profileCombo.Location = New-Object System.Drawing.Point(105, 448)
    $profileCombo.Size = New-Object System.Drawing.Size(230, 25)
    $profileCombo.DropDownStyle = 'DropDownList'
    $btnSwitchProfile = New-Object System.Windows.Forms.Button
    $btnSwitchProfile.Text = 'Switch Profile'
    $btnSwitchProfile.Location = New-Object System.Drawing.Point(345, 446)
    $btnSwitchProfile.Size = New-Object System.Drawing.Size(110, 30)
    $btnNewProfile = New-Object System.Windows.Forms.Button
    $btnNewProfile.Text = 'Add Profile'
    $btnNewProfile.Location = New-Object System.Drawing.Point(465, 446)
    $btnNewProfile.Size = New-Object System.Drawing.Size(100, 30)

    function Refresh-ProfileCombo {
        $profileCombo.Items.Clear()
        $profiles = @(Read-Profiles)
        $meta = Read-Meta
        $index = 0; $selected = -1
        foreach ($profile in $profiles) {
            [void]$profileCombo.Items.Add($profile.name)
            if ($profile.id -eq $meta.active_profile_id) { $selected = $index }
            $index++
        }
        if ($selected -ge 0) { $profileCombo.SelectedIndex = $selected }
        elseif ($profileCombo.Items.Count) { $profileCombo.SelectedIndex = 0 }
    }

    $btnSwitchProfile.Add_Click({
        if ($profileCombo.SelectedIndex -lt 0) { return }
        $profiles = @(Read-Profiles)
        $profile = $profiles | Where-Object { $_.name -eq $profileCombo.SelectedItem.ToString() } | Select-Object -First 1
        if (-not $profile) { return }
        $results = Activate-Profile -profile $profile
        Refresh-Checkboxes; Refresh-CredList; Refresh-PwdList; Refresh-ProfileCombo
        [System.Windows.Forms.MessageBox]::Show(
            "Activated profile '$($profile.name)'. N:, O:, and P: were disconnected and remounted.`r`n`r`n$($results -join [Environment]::NewLine)",
            'Profile Switched', 'OK', 'Information') | Out-Null
    })
    $btnNewProfile.Add_Click({
        if (Save-CredentialForm -newEntry $true) {
            Refresh-Checkboxes; Refresh-CredList; Refresh-PwdList; Refresh-ProfileCombo
        }
    })

    $form.Controls.Add($tc)
    $form.Controls.Add($foot)
    $form.Controls.Add($profileLabel) | Out-Null
    $form.Controls.Add($profileCombo) | Out-Null
    $form.Controls.Add($btnSwitchProfile) | Out-Null
    $form.Controls.Add($btnNewProfile) | Out-Null
    $form.AcceptButton = $btnConnect

    #  Bootstrap
    Refresh-Checkboxes; Refresh-CredList; Refresh-PwdList; Refresh-ProfileCombo

    # First run: open the two-field setup dialog directly.
    $initItems = Read-Credentials
    if ($initItems.Count -eq 0 -and -not $headless) {
        $addedAnything = $false
        while (-not $addedAnything) {
            if (Save-CredentialForm -newEntry $true) {
                $addedAnything = $true
                Refresh-Checkboxes; Refresh-CredList; Refresh-PwdList
            } else {
                $ask = [System.Windows.Forms.MessageBox]::Show(
                    'Setup was not completed. Select Retry to enter credentials or Cancel to exit.',
                    'Continue Setup', 'RetryCancel', 'Question')
                if ($ask -ne 'Retry') { break }
            }
        }
        if (-not $addedAnything) { $form.Close(); return }
    }

    $form.ShowDialog() | Out-Null
    Refresh-Checkboxes
}

#
#  Sub-form: Add / Edit Credential
#
function Save-CredentialForm {
    param(
        [object]$editEntry,
        [bool]$newEntry
    )

    $Script:_EditorResult = $null

    $f  = New-Object System.Windows.Forms.Form
    $f.Text     = 'Set Up MSU Files'
    $f.Size     = New-Object System.Drawing.Size(560, 385)
    $f.StartPosition = 'CenterParent'
    $f.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $f.Font     = New-Object System.Drawing.Font('Segoe UI', 9)
    $f.MinimizeBox = $false
    $f.MaximizeBox = $false

    $info = New-Object System.Windows.Forms.Label
    $info.Text = "Enter your MSU username and password. The utility will replace and reconnect these drive mappings:`r`n`r`nN: Faculty/staff home    O: Group shares    P: Public web root"
    $info.Location = New-Object System.Drawing.Point(18, 18)
    $info.Size = New-Object System.Drawing.Size(510, 75)
    $f.Controls.Add($info) | Out-Null

    $lblProfile = New-Object System.Windows.Forms.Label
    $lblProfile.Text = 'Profile Name:'
    $lblProfile.Location = New-Object System.Drawing.Point(18, 110)
    $lblProfile.Size = New-Object System.Drawing.Size(130, 20)
    $f.Controls.Add($lblProfile) | Out-Null
    $txtProfile = New-Object System.Windows.Forms.TextBox
    $txtProfile.Location = New-Object System.Drawing.Point(155, 107)
    $txtProfile.Size = New-Object System.Drawing.Size(365, 25)
    $f.Controls.Add($txtProfile) | Out-Null

    $lblUser = New-Object System.Windows.Forms.Label
    $lblUser.Text = 'MSU Username:'
    $lblUser.Location = New-Object System.Drawing.Point(18, 150)
    $lblUser.Size = New-Object System.Drawing.Size(130, 20)
    $f.Controls.Add($lblUser) | Out-Null

    $txtUser = New-Object System.Windows.Forms.TextBox
    $txtUser.Location = New-Object System.Drawing.Point(155, 147)
    $txtUser.Size = New-Object System.Drawing.Size(365, 25)
    $f.Controls.Add($txtUser) | Out-Null

    # Password field
    $lblP = New-Object System.Windows.Forms.Label
    $lblP.Text = 'Password:'; $lblP.Location = New-Object System.Drawing.Point(18,190); $lblP.Size = New-Object System.Drawing.Size(130,20)
    $f.Controls.Add($lblP) | Out-Null
    $txtP = New-Object System.Windows.Forms.TextBox
    $txtP.Name        = 'password'; $txtP.Location = New-Object System.Drawing.Point(155,187)
    $txtP.Size        = New-Object System.Drawing.Size(365,25); $txtP.PasswordChar = '*'
    $f.Controls.Add($txtP) | Out-Null

    $errLbl = New-Object System.Windows.Forms.Label
    $errLbl.ForeColor = [Drawing.Color]::Red
    $errLbl.Location  = New-Object System.Drawing.Point(18,225)
    $errLbl.Size      = New-Object System.Drawing.Size(500,35)
    $f.Controls.Add($errLbl) | Out-Null

    $btnOk  = New-Object System.Windows.Forms.Button
    $btnOk.Text  = 'Save and Connect'
    $btnOk.Size  = New-Object System.Drawing.Size(120,30)
    $btnOk.Location = New-Object System.Drawing.Point(300,280)

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = 'Cancel'; $btnCancel.DialogResult = 'Cancel'
    $btnCancel.Size = New-Object System.Drawing.Size(90,30)
    $btnCancel.Location = New-Object System.Drawing.Point(430,280)

    $f.Controls.Add($btnOk) | Out-Null
    $f.Controls.Add($btnCancel) | Out-Null
    $f.AcceptButton = $btnOk; $f.CancelButton = $btnCancel

    $profiles = @(Read-Profiles)
    $meta = Read-Meta
    $active = $profiles | Where-Object { $_.id -eq $meta.active_profile_id } | Select-Object -First 1
    if (-not $newEntry -and $active) {
        $txtProfile.Text = $active.name
        $txtUser.Text = $active.username
        $txtP.Text = $active._password
    } elseif (-not $newEntry -and $profiles.Count) {
        $txtProfile.Text = $profiles[0].name
        $txtUser.Text = $profiles[0].username
        $txtP.Text = $profiles[0]._password
    } else {
        $txtProfile.Text = 'Standard'
    }

    $btnOk.Add_Click({
        $profileName = $txtProfile.Text.Trim()
        $usr  = $txtUser.Text.Trim()
        $pwd  = $txtP.Text

        $errs = @()
        if (-not $profileName) { $errs += 'Profile name is required.' }
        if (-not $usr)  { $errs += 'Username is required.' }
        if (-not $pwd)  { $errs += 'Password is required.' }

        if ($errs.Count) {
            $errLbl.Text = ($errs -join [Environment]::NewLine)
            return
        }

        $allProfiles = @(Read-Profiles)
        $match = $allProfiles | Where-Object { $_.name -ieq $profileName } | Select-Object -First 1
        $profileId = if ($match) { $match.id } else { (New-Guid).ToString() }
        $profile = [pscustomobject]@{ id=$profileId; name=$profileName; username=$usr; _password=$pwd }
        $updated = @()
        foreach ($old in $allProfiles) {
            if ($old.id -ne $profileId) { $updated += $old }
        }
        $updated += $profile
        Write-Profiles -profiles $updated
        $Script:_EditorResult = $profile
        $results = Activate-Profile -profile $profile
        [System.Windows.Forms.MessageBox]::Show(
            "Activated profile '$profileName' and refreshed N:, O:, and P:.`r`n`r`n$($results -join [Environment]::NewLine)",
            'MSU Files Setup', 'OK', 'Information') | Out-Null
        $f.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $f.Close()
    })

    $f.ShowDialog() | Out-Null
    return $Script:_EditorResult
}

#
#  Sub-form: Change Password
#  Same pattern: Script-scope return flag
#
$Script:_PwdResult = $null

function Prompt-NewPassword {
    param([object]$entry, [scriptblock]$cb)

    $Script:_PwdResult = $false

    $f  = New-Object System.Windows.Forms.Form
    $f.Text     = "Update Password - $($entry.label)"
    $f.Size     = New-Object System.Drawing.Size(420, 260)
    $f.StartPosition = 'CenterParent'
    $f.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $f.Font     = New-Object System.Drawing.Font('Segoe UI', 9)

    $buildField = { param($parent, $labelText, $topY)
        $l = New-Object System.Windows.Forms.Label
        $l.Text       = $labelText; $l.Location = New-Object System.Drawing.Point(20,$topY)
        $l.Size       = New-Object System.Drawing.Size(120,20)
        $parent.Controls.Add($l)
        $t = New-Object System.Windows.Forms.TextBox
        $t.Location = New-Object System.Drawing.Point(150,$topY-3)
        $t.Size     = New-Object System.Drawing.Size(250,25)
        $t.PasswordChar = '*'
        $parent.Controls.Add($t)
        return $t
    }

    $txtOld = & $buildField $f 'Current Password:' 18
    $txtNew = & $buildField $f 'New Password:' 65
    $txtCfm = & $buildField $f 'Confirm New:' 112

    $errL = New-Object System.Windows.Forms.Label
    $errL.ForeColor = [Drawing.Color]::Red
    $errL.Location  = New-Object System.Drawing.Point(20,155)
    $errL.Size      = New-Object System.Drawing.Size(390,20)
    $f.Controls.Add($errL)

    $btnOk  = New-Object System.Windows.Forms.Button
    $btnOk.Text = 'Update'; $btnOk.Size = New-Object System.Drawing.Size(100,30)
    $btnOk.Location = New-Object System.Drawing.Point(150,180)

    $btnX = New-Object System.Windows.Forms.Button
    $btnX.Text = 'Cancel'; $btnX.Size = New-Object System.Drawing.Size(90,30)
    $btnX.Location = New-Object System.Drawing.Point(260,180); $btnX.DialogResult = 'Cancel'

    $f.Controls.Add($btnOk)
    $f.Controls.Add($btnX)
    $f.AcceptButton = $btnOk; $f.CancelButton = $btnX

    $btnOk.Add_Click({
        $cur = $txtOld.Text; $n1 = $txtNew.Text; $n2 = $txtCfm.Text
        $e = @()
        if ($cur -ne $entry._password) { $e += 'Current password does not match' }
        if ($n1.Length -lt 8)           { $e += 'Minimum 8 characters' }
        if ($n1 -ne $n2)                { $e += 'Passwords do not match' }
        if ($e.Count) { $errL.Text = ($e -join '; '); return }

        $entry._password = $n1
        $list = Read-Credentials
        for ($i = 0; $i -lt $list.Count; $i++) {
            if ($list[$i].id -eq $entry.id) {
                $list[$i]._password = $n1; break
            }
        }
        Write-Credentials -entries $list
        $errL.Text = ''
        [System.Windows.Forms.MessageBox]::Show('Password updated.','Updated','OK','Information')
        $Script:_PwdResult = $true
        $f.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $f.Close()
    })

    $f.ShowDialog() | Out-Null
    if ($Script:_PwdResult -and $cb) { & $cb }
}

#
#  Entry point
#
if ($Uninstall) {
    if (Test-Path $Script:CredDir) {
        Remove-Item -Path $Script:CredDir -Recurse -Force
        [System.Windows.Forms.MessageBox]::Show('All MSU Files credentials removed.')
    } else {
        [System.Windows.Forms.MessageBox]::Show('Nothing to remove.')
    }
    exit 0
}

Init-CredDir

if ($headless -or $NoUI) { Run-Headless } else { Show-Gui }

Write-Host 'Done.' -ForegroundColor Green
