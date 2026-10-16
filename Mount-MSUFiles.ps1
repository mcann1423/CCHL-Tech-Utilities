#Requires -Version 5.0
<#
    .SYNOPSIS
        Mount MSU Files — encrypted credential manager with GUI for SMB mounts.

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

# ── Pre-flight ──────────────────────────────────────────────────────────────
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

# ── Globals ─────────────────────────────────────────────────────────────────
$Script:CredDir       = Join-Path $env:USERPROFILE '.msufiles'
$Script:CredFile      = Join-Path $Script:CredDir 'credentials.json'
$Script:UserName      = $env:USERNAME
$Script:ServerBase    = 'msufiles.montclair.edu'
$Script:DefaultPepper = 'MSU-Files-Pepper-2026-NeverChangeThis1234'
$Script:AllDrives     = ('A'..'Z')

# ════════════════════════════════════════════════════════════════════════════
#  Encryption helpers
# ════════════════════════════════════════════════════════════════════════════
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

    $enc  = $aes.CreateEncryptor($key, $aes.IV)
    $ct   = $enc.TransformFinalBlock(
        [Text.Encoding]::UTF8.GetBytes($plaintext), 0, $plaintext.Length
    )
    $aes.Dispose(); $enc.Dispose()

    $blob = New-Object byte[] ($aes.IV.Length + $ct.Length)
    $aes.IV.CopyTo($blob, 0); $ct.CopyTo($blob, $aes.IV.Length)
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

# ════════════════════════════════════════════════════════════════════════════
#  Credential file I/O
# ════════════════════════════════════════════════════════════════════════════
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
}

# ════════════════════════════════════════════════════════════════════════════
#  Mount / Unmount
# ════════════════════════════════════════════════════════════════════════════
function Expand-SharePath {
    param([string]$p)
    $p -replace 'USERNAME_PLACEHOLDER', $Script:UserName `
       -replace '<username>', $Script:UserName
}

function Mount-OneDrive {
    param([string]$letter, [string]$sharePath, [string]$user,
          [string]$password)

    $spec = '{0}:' -f $letter.ToUpper()
    $unc  = '\\{0}\{1}' -f $Script:ServerBase, (Expand-SharePath $sharePath)

    # Already mounted?
    $cur = & net use $spec 2>&1 | Select-String "\\$Script:ServerBase"
    if ($cur) { return "$spec already connected" }

    & net use $spec $unc /user:"$user" $password /persistent:yes 2>&1 | Out-Null
    $rc = $LASTEXITCODE

    switch ($rc) {
        0     { "$spec mounted -> $unc" }
        5     { "$spec access denied — check username / password" }
        86    { "$spec syntax error — verify UNC path" }
        1219  { "$spec multiple connections not allowed" }
        1326  { "$spec login failed" }
        1314  { "$spec insufficient privileges" }
        default { "$spec net-use error code $rc" }
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

# ════════════════════════════════════════════════════════════════════════════
#  Headless mode
# ════════════════════════════════════════════════════════════════════════════
function Run-Headless {
    $creds = Read-Credentials
    if (-not $creds.Count) {
        Write-Host 'No credentials found. Run without --NoUI first to set up.' -ForegroundColor Yellow
        return
    }
    foreach ($e in $creds) {
        $msg = Mount-OneDrive -letter $e.drive_letter -sharePath $e.share_path `
                              -user $e.username -password $e._password
        $isGood = -not ($msg -match '(error|denied|failed|privilege)')
        $col    = if ($isGood) { 'Green' } else { 'Yellow' }
        Write-Host $msg -ForegroundColor $col
    }
}

# ════════════════════════════════════════════════════════════════════════════
#  Logging helpers (direct textbox operations — no undefined wrapper needed)
# ════════════════════════════════════════════════════════════════════════════
function Write-LogLine {
    param([string]$msg, [switch]$good)
    $tag  = if ($good) { '+' } else { '-' }
    $clr  = if ($good) { 'Green' } elseif ($msg -match '(error|failed|privilege)') { 'Red' } else { 'Yellow' }
    $txtLog.AppendText("{0} [{1}] {2}{3}" -f (Get-Date 'HH:mm:ss'), $tag, $msg, [Environment]::NewLine)
    $txtLog.ScrollToCaret()
}

# ════════════════════════════════════════════════════════════════════════════
#  Helper: add placeholder hint to a textbox via Leave/Enter events
# ════════════════════════════════════════════════════════════════════════════
function Set-Placeholder {
    param(
        [System.Windows.Forms.TextBox]$box,
        [string]$hint,
        [bool]$isPassword = $false
    )
    $box.Tag = $hint                           # store hint as Tag
    if ($isPassword) {
        # For password fields: show hint as masked chars, restore real char on focus
        $box.Text = $hint                      # displayed as dots
        $box.PasswordChar = '*'                # show dots during hint
        $originalChar = '*'                    # default char while showing hint

        $box.Add_Enter({
            param($sender)
            $tb = $sender
            if ($tb.Tag -and $tb.PasswordChar -eq '*') {
                # Currently showing hint — reveal real password input
                $tb.Text = ''
                $tb.PlaceholderText = ""         # clear internal
                $tb.Tag = $tb.Tag + '__REAL__'   # mark entered real-input mode
            }
        })
        $box.Add_Leave({
            param($sender)
            $tb = $sender
            if ($tb.Tag -like '*__REAL__') {
                # Was in real-input mode — only restore hint if empty
                if (-not $tb.Text) {
                    $tb.Text = $tb.Tag.ToString().Replace('__REAL__', '')
                }
            } else {
                # Still showing hint — nothing to do
            }
        })
    } else {
        $box.Text = $hint
        $box.ForeColor = [Drawing.Color]::LightGray

        $box.Add_Enter({
            param($sender)
            $tb = $sender
            if ($tb.Text -eq $tb.Tag -and $tb.ForeColor -eq [Drawing.Color]::LightGray) {
                $tb.Text = ''; $tb.ForeColor = [Drawing.Color]::Black
            }
        })
        $box.Add_Leave({
            param($sender)
            $tb = $sender
            if (-not $tb.Text) {
                $tb.Text = $tb.Tag
                $tb.ForeColor = [Drawing.Color]::LightGray
            }
        })
    }
}

# ════════════════════════════════════════════════════════════════════════════
#  GUI — Main form
# ════════════════════════════════════════════════════════════════════════════
function Show-Gui {
    # ── Top-level controls ────────────────────────────────────────────────
    $form       = New-Object System.Windows.Forms.Form
    $form.Text      = 'Mount MSU Files'
    $form.Size      = New-Object System.Drawing.Size(720, 520)
    $form.StartPosition = 'CenterScreen'
    $form.Font      = New-Object System.Drawing.Font('Segoe UI', 9)

    $tc           = New-Object System.Windows.Forms.TabControl
    $tc.Location  = New-Object System.Drawing.Point(10, 10)
    $tc.Size      = New-Object System.Drawing.Size(695, 400)
    $tc.Anchor    = 'Top,Left,Right,Bottom'

    # ══════════════════════════════════════════════════════════════════════
    #  TAB 1: Connect / Disconnect
    # ══════════════════════════════════════════════════════════════════════
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
    $btnConnect.Text = 'Connect Selected →'; $btnConnect.Size = New-Object System.Drawing.Size(150, 35)
    $btnConnect.Location = New-Object System.Drawing.Point(15, 365)

    $btnDisconnect = New-Object System.Windows.Forms.Button
    $btnDisconnect.Text = 'Disconnect All ↓'; $btnDisconnect.Size = New-Object System.Drawing.Size(150, 35)
    $btnDisconnect.Location = New-Object System.Drawing.Point(175, 365)

    # State dictionary keyed by drive letter
    $g_Checkboxes = @{}

    function Refresh-Checkboxes {
        $flow.Controls.Clear(); $g_Checkboxes.Clear()
        $items = Read-Credentials
        if (-not $items.Count) {
            $grp = New-Object System.Windows.Forms.GroupBox
            $grp.Text  = 'No credentials saved yet'
            $grp.Size  = New-Object System.Drawing.Size(655, 70)
            $grp.Margin = '5,5,5,5'

            $lblMain = New-Object System.Windows.Forms.Label
            $lblMain.Text  = 'Use "Manage Credentials" tab to add your first entry.'
            $lblMain.Location = New-Object System.Drawing.Point(10, 20)
            $lblMain.AutoSize = $true

            $btnFirst = New-Object System.Windows.Forms.Button
            $btnFirst.Text = '+ Add First Entry →'
            $btnFirst.Location = New-Object System.Drawing.Point(10, 45)
            $btnFirst.Size = New-Object System.Drawing.Size(160, 28)
            $btnFirst.Add_Click({
                Save-CredentialForm -newEntry $true -cb {
                    Refresh-CredList; Refresh-Checkboxes; Refresh-PwdList
                    LogMgmt 'Entry added.'
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
            $grp.Size  = New-Object System.Drawing.Size(655, 85)
            $grp.Margin = '2,2,2,2'

            $chk = New-Object System.Windows.Forms.CheckBox; $chk.Checked = $true
            $chk.Dock = 'Left'; $chk.AutoSize = $true

            $info = New-Object System.Windows.Forms.Label
            $info.Text = 'User: {0}{1}Server: {2}{3}Share: {4}' -f
                            $entry.username, [Environment]::NewLine,
                            $entry.server, [Environment]::NewLine,
                            $entry.share_path
            $info.Location = New-Object System.Drawing.Point(28, 8)
            $info.MaximumSize = New-Object System.Drawing.Size(600, 60)
            $info.Font      = New-Object System.Drawing.Font('Segoe UI', 8)
            $info.AutoSize  = $true

            $grp.Controls.Add($chk); $grp.Controls.Add($info)
            $flow.Controls.Add($grp)
            $g_Checkboxes[$entry.drive_letter] = @{ chk=$chk; entry=$entry }
        }
    }

    $btnConnect.Click += {
        $txtLog.Clear(); $ok=0; $fail=0
        foreach ($dl in $g_Checkboxes.Keys) {
            $item = $g_Checkboxes[$dl]
            if (-not $item.chk.Checked) { continue }
            $m = Mount-OneDrive -letter $item.entry.drive_letter `
                                -sharePath $item.entry.share_path `
                                -user $item.entry.username -password $item.entry._password
            $good = -not ($m -match '(error|denied|failed|privilege)')
            if ($good) { $ok++ } else { $fail++ }
            Write-LogLine -msg $m -good:$good
        }
        $anyChecked = @($g_Checkboxes.Values | Where-Object { $_.chk.Checked }).Count
        if (-not $anyChecked) {
            Write-LogLine -msg 'No drives selected.'; return
        }
        $summary = "Connection complete — success: {0}, failed: {1}" -f $ok, $fail
        Write-LogLine -msg $summary -good:($fail -eq 0)
        [System.Windows.Forms.MessageBox]::Show(
            $summary, 'Mount Complete', 'OK', 'Information'
        )
    }

    $btnDisconnect.Click += {
        $txtLog.Clear()
        Unmount-All | ForEach-Object { Write-LogLine -msg $_ -good:$true }
        [System.Windows.Forms.MessageBox]::Show('Done.', 'Unmounted', 'OK', 'Information')
    }

    # ══════════════════════════════════════════════════════════════════════
    #  TAB 2: Manage Credentials
    # ══════════════════════════════════════════════════════════════════════
    $lstCreds = New-Object System.Windows.Forms.ListBox
    $lstCreds.Location = New-Object System.Drawing.Point(15, 45)
    $lstCreds.Size     = New-Object System.Drawing.Size(665, 200)
    $lstCreds.Anchor   = 'Top,Left,Right,Bottom'

    $btnAdd    = New-Object System.Windows.Forms.Button; $btnAdd.Text  = '+ Add Entry'
    $btnEdit   = New-Object System.Windows.Forms.Button; $btnEdit.Text = 'Edit Selected'
    $btnDelete = New-Object System.Windows.Forms.Button; $btnDelete.Text = 'Delete Selected'
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

    $btnAdd.Click += {
        Save-CredentialForm -newEntry $true -cb {
            Refresh-CredList; Refresh-Checkboxes; LogMgmt 'Entry added.'
        }
    }
    $btnEdit.Click += {
        if ($lstCreds.SelectedIndex -lt 0) { return }
        $sel = Read-Credentials[$lstCreds.SelectedIndex]
        Save-CredentialForm -editEntry $sel -cb {
            Refresh-CredList; Refresh-Checkboxes; LogMgmt 'Entry updated.'
        }
    }
    $btnDelete.Click += {
        if ($lstCreds.SelectedIndex -lt 0) { return }
        $y = [System.Windows.Forms.MessageBox]::Show(
            'Delete this entry?', 'Confirm', 'YesNo', 'Question')
        if ($y -ne 'Yes') { return }
        $a = Read-Credentials; $a.RemoveAt($lstCreds.SelectedIndex)
        Write-Credentials -entries $a
        Refresh-CredList; Refresh-Checkboxes; LogMgmt 'Entry deleted.'
    }
    $btnSaveM.Click += { Refresh-CredList; Refresh-Checkboxes; LogMgmt 'Lists refreshed.' }

    # ══════════════════════════════════════════════════════════════════════
    #  TAB 3: Change Password
    # ══════════════════════════════════════════════════════════════════════
    $banner = New-Object System.Windows.Forms.Label
    $banner.Text    = 'WARNING: This utility manages your MSU Files password only. It cannot change your NetID / AD password.'
    $banner.Location = New-Object System.Drawing.Point(15, 8)
    $banner.Size    = New-Object System.Drawing.Size(665, 35)
    $banner.ForeColor = [Drawing.Color]::OrangeRed
    $banner.Font    = New-Object System.Drawing.Font('Segoe UI', 9, 'Bold')
    $banner.Anchor  = 'Top,Left,Right'

    $lstPwd = New-Object System.Windows.Forms.ListBox
    $lstPwd.Location = New-Object System.Drawing.Point(15, 48)
    $lstPwd.Size     = New-Object System.Drawing.Size(665, 110)
    $lstPwd.Anchor   = 'Top,Left,Right'

    $btnUpdatePwd = New-Object System.Windows.Forms.Button
    $btnUpdatePwd.Text = 'Update Selected Password'
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
            $lstPwd.Items.Add("$( $e.label ) [$( $e.drive_letter.ToUpper() )] — $( $e.username )")
        }
        if (-not (Read-Credentials).Count) { $lstPwd.Items.Add('(none)'); $lstPwd.Enabled = $false }
        else { $lstPwd.Enabled = $true }
    }
    function LogPwd { param([string]$m) $logPwd.AppendText("$m`n"); $logPwd.ScrollToCaret() }

    $btnUpdatePwd.Click += {
        if ($lstPwd.SelectedIndex -lt 0) { return }
        $items = Read-Credentials; $sel = $items[$lstPwd.SelectedIndex]
        Prompt-NewPassword -entry $sel -cb { Refresh-PwdList; Refresh-Checkboxes; LogPwd 'Password updated.' }
    }

    $btnWipe.Click += {
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
    }

    # ══════════════════════════════════════════════════════════════════════
    #  Assemble tabs into tab control
    # ══════════════════════════════════════════════════════════════════════
    $tab1 = New-Object System.Windows.Forms.TabPage
    $tab1.Text = 'Connect / Disconnect'
    $tabLbl = New-Object System.Windows.Forms.Label
    $tabLbl.Text = 'Select which drives to mount:'
    $tabLbl.Location = New-Object System.Drawing.Point(15, 0)
    $tabLbl.AutoSize = $true
    $tab1.Controls.AddRange(@($tabLbl, $flow, $txtLog, $btnConnect, $btnDisconnect))

    $tab2 = New-Object System.Windows.Forms.TabPage
    $tab2.Text = 'Manage Credentials'
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

    $form.Controls.Add($tc)
    $form.Controls.Add($foot)
    $form.AcceptButton = $btnConnect

    # ── Bootstrap ─────────────────────────────────────────────────────────
    Refresh-Checkboxes; Refresh-CredList; Refresh-PwdList

    # FIRST-RUN WIZARD: if zero credentials, auto-open Add dialog
    $initItems = Read-Credentials
    if ($initItems.Count -eq 0 -and -not $headless) {
        [System.Windows.Forms.MessageBox]::Show(
            'Welcome to Mount MSU Files.`n`nYou have no saved credentials yet.' + "`n" +
            'Click OK to open the wizard to add your first mount.',
            'Setup Required', 'OK', 'Information')

        $addedAnything = $false
        while (-not $addedAnything) {
            $result = Save-CredentialForm -newEntry $true
            if ($result) {
                $addedAnything = $true
                Refresh-Checkboxes; Refresh-CredList; Refresh-PwdList
            } else {
                # User cancelled — ask if they want to abort
                $ask = [System.Windows.Forms.MessageBox]::Show(
                    'No entry was added. Quit now or keep trying?',
                    'Continue Setup', 'YesNo', 'Question')
                if ($ask -eq 'Yes') { break }
            }
        }
        if (-not $addedAnything) { $form.Close(); return }
    }

    $form.ShowDialog() | Out-Null
    Refresh-Checkboxes
}

# ════════════════════════════════════════════════════════════════════════════
#  Sub-form: Add / Edit Credential
#  Uses Script-scope return variable to avoid closure-callback fragility
# ════════════════════════════════════════════════════════════════════════════
$Script:_EditorResult = $null   # caller reads this after function returns

function Save-CredentialForm {
    param(
        [object]$editEntry,
        [bool]$newEntry,
        [scriptblock]$cb
    )

    $Script:_EditorResult = $null  # reset

    $f  = New-Object System.Windows.Forms.Form
    $f.Text     = if ($editEntry) { 'Edit Credential' } else { 'Add New Credential' }
    $f.Size     = New-Object System.Drawing.Size(500, 400)
    $f.StartPosition = 'CenterParent'
    $f.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $f.Font     = New-Object System.Drawing.Font('Segoe UI', 9)

    $fields = @(
        @{ name='drive_letter';  label='Drive Letter:';   y=18; ph='N' }
        @{ name='server';       label='Server:';          y=68; ph='msufiles.montclair.edu' }
        @{ name='share_path';   label='Share Path:';      y=118; ph='<username>' }
        @{ name='username';     label='Username:';         y=168; ph='admsu\$USERNAME_PLACEHOLDER' }
        @{ name='label';        label='Label:';            y=218; ph='Faculty Home (N:)' }
    )

    $txts = @{}
    foreach ($fld in $fields) {
        $lbl = New-Object System.Windows.Forms.Label
        $lbl.Text       = $fld.label; $lbl.Location = New-Object System.Drawing.Point(15,$fld.y)
        $lbl.Size       = New-Object System.Drawing.Size(100,20)
        $f.Controls.Add($lbl)

        $box = New-Object System.Windows.Forms.TextBox
        $box.Name        = $fld.name
        $box.Location    = New-Object System.Drawing.Point(125,$fld.y-3)
        $box.Size        = New-Object System.Drawing.Size(350,25)
        $f.Controls.Add($box)
        $txts[$fld.name] = $box
    }

    # Placeholder hints via event-based approach (no native PlaceholderText in PS5)
    Set-Placeholder -box $txts['drive_letter']  -hint 'N'
    Set-Placeholder -box $txts['server']         -hint 'msufiles.montclair.edu'
    Set-Placeholder -box $txts['share_path']     -hint '<username>'
    Set-Placeholder -box $txts['username']        -hint 'admsu\$USERNAME_PLACEHOLDER'
    Set-Placeholder -box $txts['label']           -hint 'Faculty Home (N:)'

    $hintUsr = New-Object System.Windows.Forms.Label
    $hintUsr.Text  = 'Use <username> for auto-expansion'
    $hintUsr.Location = New-Object System.Drawing.Point(125, 140)
    $hintUsr.Size    = New-Object System.Drawing.Size(350,20)
    $hintUsr.ForeColor = [Drawing.Color]::Gray
    $f.Controls.Add($hintUsr)

    # Password field
    $lblP = New-Object System.Windows.Forms.Label
    $lblP.Text = 'Password:'; $lblP.Location = New-Object System.Drawing.Point(15,268); $lblP.Size = New-Object System.Drawing.Size(100,20)
    $f.Controls.Add($lblP)
    $txtP = New-Object System.Windows.Forms.TextBox
    $txtP.Name        = 'password'; $txtP.Location = New-Object System.Drawing.Point(125,265)
    $txtP.Size        = New-Object System.Drawing.Size(350,25); $txtP.PasswordChar = '*'
    $f.Controls.Add($txtP)

    $errLbl = New-Object System.Windows.Forms.Label
    $errLbl.ForeColor = [Drawing.Color]::Red
    $errLbl.Location  = New-Object System.Drawing.Point(15,300)
    $errLbl.Size      = New-Object System.Drawing.Size(460,20)
    $f.Controls.Add($errLbl)

    $btnOk  = New-Object System.Windows.Forms.Button
    $btnOk.Text  = 'Save'; $btnOk.DialogResult = 'OK'
    $btnOk.Size  = New-Object System.Drawing.Size(90,30)
    $btnOk.Location = New-Object System.Drawing.Point(260,330)

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = 'Cancel'; $btnCancel.DialogResult = 'Cancel'
    $btnCancel.Size = New-Object System.Drawing.Size(90,30)
    $btnCancel.Location = New-Object System.Drawing.Point(360,330)

    $f.Controls.Add(@($btnOk, $btnCancel, $errLbl))
    $f.AcceptButton = $btnOk; $f.CancelButton = $btnCancel

    # Populate existing entry
    if ($editEntry) {
        $txts['drive_letter'].Text = $editEntry.drive_letter
        $txts['server'].Text       = $editEntry.server
        $txts['share_path'].Text   = $editEntry.share_path
        $txts['username'].Text     = $editEntry.username
        $txts['label'].Text        = $editEntry.label
        $txtP.Text                 = $editEntry._password
    }

    $result = $f.ShowDialog()
    if ($result -ne 'OK') { return }

    # Collect values
    $drv  = $txts['drive_letter'].Text.Trim().ToUpper()
    $srv  = $txts['server'].Text.Trim()
    $shp  = $txts['share_path'].Text.Trim()
    $usr  = $txts['username'].Text.Trim()
    $lblv = $txts['label'].Text.Trim()
    $pwd  = $txtP.Text

    # Strip placeholder hints left behind by user not interacting
    if ($txts['share_path'].Tag -and $txts['share_path'].Text -eq $txts['share_path'].Tag) {
        $shp = $txts['share_path'].Text.Replace('<username>', $Script:UserName)
    }
    if ($txts['username'].Tag -and $txts['username'].Text -eq $txts['username'].Tag) {
        $usr = $txts['username'].Text.Replace('$USERNAME_PLACEHOLDER', $Script:UserName).Replace('\\','\')
        if (-not $usr.Contains('\')) { $usr = "admsu\$usr" }
    }

    $errs = @()
    if ($drv   -notmatch '^[A-Z]$') { $errs += "Bad drive letter: $drv" }
    if (-not $srv)                      { $errs += 'Server required' }
    if (-not $shp)                      { $errs += 'Share path required' }
    if (-not $usr)                      { $errs += 'Username required' }
    if (-not $lblv)                     { $errs += 'Label required' }
    if (-not $pwd)                      { $errs += 'Password required' }

    # Conflict check
    if (-not $errs) {
        foreach ($existing in Read-Credentials) {
            if ($existing.drive_letter -eq $drv) {
                if (-not $editEntry -or $existing.id -ne $editEntry.id) {
                    $errs += "$drv already assigned to: $($existing.label)"; break
                }
            }
        }
    }

    if ($errs.Count) { $errLbl.Text = ($errs -join '; '); return }

    # Build record object
    $rec = @{
        id         = if ($editEntry) { $editEntry.id } else { (New-Guid).ToString() }
        drive_letter = $drv; server = $srv; share_path = $shp
        username = $usr; label = $lblv; _password = $pwd
    }

    # Merge into existing list
    $list = Read-Credentials
    if ($editEntry) {
        for ($i = 0; $i -lt $list.Count; $i++) {
            if ($list[$i].id -eq $editEntry.id) { $list[$i] = $rec; break }
        }
    } else {
        $list += $rec
    }
    Write-Credentials -entries $list

    $Script:_EditorResult = $rec   # signal success to caller

    # Fire caller's callback
    if ($cb) { & $cb }
}

# ════════════════════════════════════════════════════════════════════════════
#  Sub-form: Change Password
#  Same pattern: Script-scope return flag
# ════════════════════════════════════════════════════════════════════════════
$Script:_PwdResult = $null

function Prompt-NewPassword {
    param([object]$entry, [scriptblock]$cb)

    $Script:_PwdResult = $false

    $f  = New-Object System.Windows.Forms.Form
    $f.Text     = "Update Password — $($entry.label)"
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
    $btnOk.Location = New-Object System.Drawing.Point(150,180); $btnOk.DialogResult = 'OK'

    $btnX = New-Object System.Windows.Forms.Button
    $btnX.Text = 'Cancel'; $btnX.Size = New-Object System.Drawing.Size(90,30)
    $btnX.Location = New-Object System.Drawing.Point(260,180); $btnX.DialogResult = 'Cancel'

    $f.Controls.Add(@($btnOk, $btnX, $errL))
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
        $f.Close()
    })

    $f.ShowDialog() | Out-Null
    if ($Script:_PwdResult -and $cb) { & $cb }
}

# ════════════════════════════════════════════════════════════════════════════
#  Entry point
# ════════════════════════════════════════════════════════════════════════════
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
