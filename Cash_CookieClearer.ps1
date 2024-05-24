# Define reusable functions for color-coded messages
function Write-Section {
    param ([string]$text)
    Write-Host -ForegroundColor Blue "-------------------"
    Write-Host -ForegroundColor Green $text
    Write-Host -ForegroundColor Blue "-------------------"
}

function Write-Confirm {
    param ([string]$text)
    Write-Host -ForegroundColor Green $text
}

function Write-Info {
    param ([string]$text)
    Write-Host -ForegroundColor Yellow $text
}

function Write-LogError {
    param ([string]$text)
    Write-Host -ForegroundColor Red $text
}

function Write-Console {
    param ([string]$text)
    Write-Host -ForegroundColor Cyan $text
}

# Define global variables
$global:userInput = ""
$global:rootPath = "C:\"
$global:logFilePath = "C:\scriptLogs\cleanupLog.txt"
$global:currentUserInfo = ""
$global:currentUsername = ""
$global:installedPrograms = @()

# Function to get validated user input for menu selection
function Get-ValidatedInput {
    param (
        [string]$prompt,
        [string[]]$validOptions
    )
    try {
        do {
            $global:userInput = (Read-Host -Prompt $prompt).Trim().ToUpper()
            if ($validOptions -contains $global:userInput) {
                return $global:userInput
            } else {
                Write-LogError "Invalid input. Please enter a valid option."
            }
        } while ($true)
    } catch {
        Write-LogError "An error occurred while reading user input: $_"
    }
}

# Function to get validated integer input, allowing ranges and comma-separated values
function Get-ValidatedIntListInput {
    param (
        [string]$prompt
    )
    try {
        do {
            $global:userInput = (Read-Host -Prompt $prompt).Trim()
            if ($global:userInput -match '^[0-9,-\s]+$') {
                $ranges = $global:userInput -split ','
                $numbers = @()

                foreach ($range in $ranges) {
                    if ($range -match '^\s*(\d+)\s*-\s*(\d+)\s*$') {
                        $start = [int]$matches[1]
                        $end = [int]$matches[2]
                        if ($start -le $end) {
                            $numbers += $start..$end
                        } else {
                            Write-LogError "Invalid range: $range"
                        }
                    } elseif ($range -match '^\s*(\d+)\s*$') {
                        $numbers += [int]$matches[1]
                    } else {
                        Write-LogError "Invalid input: $range"
                    }
                }

                return $numbers
            } else {
                Write-LogError "Invalid input. Please enter valid numbers or ranges."
            }
        } while ($true)
    } catch {
        Write-LogError "An error occurred while reading user input: $_"
    }
}

# Function to fetch the current user info and store in global variables
function Fetch-CurrentUserInfo {
    $global:currentUserInfo = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $global:currentUsername = $global:currentUserInfo.Split('\')[-1]
}

# Function to fetch installed programs and store in global variable
function Fetch-And-Display-InstalledPrograms {
    Write-Info "Fetching list of installed programs..."
    $registryPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $global:installedPrograms = $registryPaths | ForEach-Object {
        Get-ItemProperty $_
    } | Select-Object DisplayName | Where-Object { $_.DisplayName -ne $null }

    Write-Info "Displaying installed programs:"
    $global:installedPrograms | ForEach-Object {
        Write-Host $_.DisplayName -ForegroundColor Green
    }
}

# Function to check if a program is installed
function Is-Installed {
    param ([string]$appName)
    return $global:installedPrograms | Where-Object { $_.DisplayName -like "*$appName*" } | Select-Object -First 1
}

# Display Header Information
Write-Host -ForegroundColor Blue "---------------------Developed by Amanda Hernow - Thorlabs Sweden AB---------------------"
Write-Confirm "Use: PowerShell script to be executed remotely on production PC using PSexec, scheduled task, or run from autofire HID device."
Write-Confirm "Program Description: Automates clean disk, clearing cache and cookies on all user accounts on the targeted PC, performs optimization and defragmentations on hard drive"
Write-Confirm "Developer: Amanda Hernow, Thorlabs Sweden AB"
Write-Confirm "Version: 2.2 Updated: 24-05-2024"
Write-Host -ForegroundColor Blue "-------------------------------PowerShell Script - PC Clean Up---------------------------"

# Change Log and Coming Soon Section
Write-Confirm "CHANGE_LOG:
V.0.1: Pre Alpha - Made Script Windows 11 Compatible and added DNS cache clean-up.
V.0.2: Pre Alpha - Listed installed programs to facilitate checks for installed applications.
V.0.3: Alpha - Enhanced operational stability for local PC executions.
V.0.4: Alpha - Implemented OS-Image and filesystem checks and repair methods.
V.0.5: Alpha - Integrated user session management, logging off users safely before operations.
V.1.0: Beta - Added hard drive type check and implemented defragmentation for HDDs.
V.1.1: Beta - Improved user interface feedback and scripting verbosity for better clarity during operations.
V.1.2: Beta - Enhanced error handling mechanisms and added dynamic execution paths based on system state.
v.1.3: Beta - Implemented automated disk cleanup task
v.2.0: Developed switch menu for dynamic script interactions.
v.2.1: Added function to remove user profile from windows device.
v.2.2: Improved structure, added global functions for fetching user and program data, updated error handling."
Write-Info "COMING_SOON:
1. Development of a switch menu for Program picker to clean common program files only
2. Deciding on execution methods: scheduled tasks, autofire HID devices, or through PSexec remotely.
3. Explore the possibility of dynamically finding cache paths from program installation paths for targeted cleaning.
4. Implement robust error handling to manage and log exceptions and errors effectively."

# Functions for specific tasks
function LogOffAllUsersExceptCurrent {
    Clear-Host
    Write-Section "SECTION 2: Logging Off All Users Except Current Session..."

    function GetCurrentUserInfo {
        Fetch-CurrentUserInfo
    }

    function DisplayCurrentUserInfo {
        Write-Console "Current user info: $global:currentUserInfo"
        Write-Console "Query current user session: $global:queryCurrentUserSession"
    }

    function GetLoggedOnUsers {
        try {
            $global:quserOutput = quser | Select-Object -Skip 1  # Skip the header
            $global:sessions = $global:quserOutput | ForEach-Object {
                if ($_ -match "(?i)(\w+)\s+(\d+)\s+") {
                    @{
                        UserName = $Matches[1].Trim()
                        SessionID = $Matches[2]
                    }
                }
            }
        } catch {
            Write-LogError "quser command not found. Falling back to Get-CimInstance."
            $global:sessions = Get-CimInstance -ClassName Win32_ComputerSystem | ForEach-Object {
                if ($_.UserName) {
                    $sessionInfo = @{
                        UserName = $_.UserName.Split('\')[-1]
                        SessionID = ($_.GetRelated('Win32_LogonSession') | ForEach-Object { $_.LogonId }) -join ','
                    }
                    [pscustomobject]$sessionInfo
                }
            }
        }
    }

    function LogOffOtherUsers {
        foreach ($session in $global:sessions) {
            if ($session.UserName -ne $global:currentUsername) {
                Write-Info "Logging off user $($session.UserName) with session ID $($session.SessionID)..."
                # Uncomment the next line to actually log off the users when you're ready to use this function in production
                # logoff $session.SessionID
                Start-Sleep -Seconds 2  # A short pause to ensure each logoff command has time to execute
            } else {
                Write-Console "Skipping logoff for current user session: $($session.UserName) with session ID $($session.SessionID)"
            }
        }
        Write-Confirm "User logoff process completed."
    }

    GetCurrentUserInfo
    DisplayCurrentUserInfo
    GetLoggedOnUsers
    LogOffOtherUsers

    Show-Menu
}

function DeleteUserProfile {
    Write-Info "Opening script to delete user profile from Windows device..."
    Write-Section "SECTION 3: Deleting User Profiles"

    function GetAllUserProfiles {
        $global:profiles = Get-WmiObject -Class Win32_UserProfile | Where-Object { 
            !$_.Special -and 
            $_.LocalPath -notmatch 'DefaultAppPool|ServiceProfiles|Public|defaultuser0' -and
            $_.LocalPath -notmatch 'C:\\Users\\Administrator' -and
            $_.LocalPath -notmatch 'C:\\Users\\Admin'
        }
        $global:i = 0
        $global:profileMap = @{}
    }

    function DisplayUserProfiles {
        $global:profiles | ForEach-Object {
            $global:i++
            $global:profileMap[$global:i] = $_
            Write-Confirm "$global:i. $($_.LocalPath)"
        }
    }

    function GetUserInputSelection {
        Write-Host "Enter the numbers of the profiles you want to remove (e.g., 1-3,5,7) or any key to return to main menu: " -ForegroundColor Yellow -NoNewline
        $global:userInput = Read-Host

        if ($global:userInput.Count -eq 0) {
            Show-Menu
            return
        }

        $global:selectedNumbers = $global:userInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+(-\d+)?$' }

        if ($global:selectedNumbers.Count -eq 0) {
            Write-LogError "Invalid input. Please enter valid numbers or ranges."
            Show-Menu
            return
        }

        $global:selectedProfiles = @()
        foreach ($number in $global:selectedNumbers) {
            if ($number -match '^(\d+)-(\d+)$') {
                $start = [int]$matches[1]
                $end = [int]$matches[2]
                if ($start -le $end) {
                    $global:selectedProfiles += $start..$end | ForEach-Object { $global:profileMap[$_] }
                } else {
                    Write-LogError "Invalid range: $number"
                }
            } elseif ($global:profileMap.ContainsKey([int]$number)) {
                $global:selectedProfiles += $global:profileMap[[int]$number]
            } else {
                Write-LogError "Profile number $number is not valid."
            }
        }

        if ($global:selectedProfiles.Count -eq 0) {
            Write-LogError "No valid profiles selected. Returning to main menu."
            Show-Menu
            return
        }
    }

    function ConfirmDeletion {
        Write-Info "You have selected the following profiles for deletion:"
        $global:selectedProfiles | ForEach-Object { Write-Info $_.LocalPath }
        Write-Host -NoNewline -ForegroundColor Yellow "Are you sure you want to remove these profiles? (Y/N): "
        $global:userInput = Read-Host

        if ($global:userInput.ToUpper() -eq 'Y') {
            $success = $true
            foreach ($profile in $global:selectedProfiles) {
                try {
                    $profile | Remove-WmiObject -Verbose
                    Write-Confirm "Profile at $($profile.LocalPath) removed successfully."
                } catch {
                    Write-LogError "Failed to remove profile at $($profile.LocalPath): $_"
                    $success = $false
                }
            }

            if ($success) {
                Write-Host -NoNewline -ForegroundColor Yellow "Would you like to (1) remove another profile, or (2) return to the main menu? "
                $userDecision = Get-ValidatedInput "Enter your choice (1 or 2):" @("1", "2")
                if ($userDecision -eq '1') {
                    DeleteUserProfile
                } else {
                    Show-Menu
                }
            } else {
                Write-Host -NoNewline -ForegroundColor Yellow "Do you want to try deleting profiles again? (Y/N): "
                $global:userInput = Read-Host
                if ($global:userInput.ToUpper() -eq 'Y') {
                    DeleteUserProfile
                } else {
                    Show-Menu
                }
            }
        } else {
            Write-Info "Profile removal canceled. Returning to main menu."
            Show-Menu
        }
    }

    do {
        GetAllUserProfiles
        DisplayUserProfiles
        GetUserInputSelection
        ConfirmDeletion
    } while ($true)
}

function DeepCacheClearing {
    function WelcomeClean {
        Write-Info "Opening Deep Cache Clearing..."
        Write-Section "SECTION 1: Deep Cache Clearing"
    }

    function WarningClean {
        Write-Host -NoNewline -ForegroundColor Red "WARNING"
        Write-Host -ForegroundColor Red ": Highly experimental script, run at your own risk."
        Write-Host ""
        Write-Host -NoNewline -ForegroundColor Yellow "This function aims to comprehensively clean cache files across the system and software directories."
        Write-Info "Press 'q' at any time to interrupt the script and choose an action."
        Write-Host -NoNewline -ForegroundColor Yellow "Do you want to (1) Proceed to run the script, (2) Restore cache backup files, or (3) Go back to the main menu? (1/2/3): "
        $global:userInput = Read-Host
        if ($global:userInput -eq '1') {
            return $true
        } elseif ($global:userInput -eq '2') {
            Write-Info "If the backup folder is compressed, please decompress it before proceeding."
            RestoreCacheBackupFiles
            return $false
        } else {
            Show-Menu
            return $false
        }
    }

    function RestoreCacheBackupFiles {
        Write-Info "Listing all non-compressed cache backup folders..."
        $backupFolders = Get-ChildItem -Path $global:backupRoot -Directory | Where-Object { -not ($_ | Get-ChildItem -Filter '*.zip') }
        $i = 0
        $backupMap = @{}

        foreach ($folder in $backupFolders) {
            $i++
            $backupMap[$i] = $folder
            Write-Confirm "$i. $($folder.Name)"
        }

        Write-Host -NoNewline -ForegroundColor Yellow "Enter the number of the backup folder to restore or 'q' to return to the main menu: "
        $global:userInput = Read-Host

        if ($global:userInput -eq 'Q') {
            Show-Menu
            return
        }

        if ($backupMap.ContainsKey([int]$global:userInput)) {
            $selectedBackup = $backupMap[[int]$global:userInput]
            $logFileName = "$($selectedBackup.Name.Split('_')[-1]).log"
            $logFilePath = Join-Path -Path $global:backupRoot -ChildPath $logFileName

            # Debugging output
            Write-Info "Selected Backup: $selectedBackup"
            Write-Info "Expected Log File Path: $logFilePath"

            if (Test-Path -Path $logFilePath) {
                Write-Info "Restoring files from $($selectedBackup.FullName)..."
                "Restoring files from $($selectedBackup.FullName)..." | Out-File -Append -FilePath $global:logPath

                # Check if there's an extra directory layer
                $backupSubFolders = Get-ChildItem -Path $selectedBackup.FullName -Directory
                if ($backupSubFolders.Count -eq 1 -and $backupSubFolders[0].Name -eq $selectedBackup.Name) {
                    $backupPath = $backupSubFolders[0].FullName
                } else {
                    $backupPath = $selectedBackup.FullName
                }

                $logEntries = Get-Content -Path $logFilePath -Encoding Unicode | Where-Object { $_ -match 'moved to' }
                foreach ($entry in $logEntries) {
                    $originalPath = $entry -replace ' moved to .*', ''
                    $fileBackupPath = Join-Path -Path $backupPath -ChildPath (Split-Path -Leaf $entry -replace '.* moved to ')

                    Write-Info "Attempting to restore $fileBackupPath to $originalPath"

                    if (-not (Test-Path -Path $fileBackupPath)) {
                        Write-LogError "Backup file not found: $fileBackupPath"
                        continue
                    }

                    if (-not (Test-Path -Path (Split-Path -Path $originalPath -Parent))) {
                        Write-LogError "Original directory not found: $(Split-Path -Path $originalPath -Parent)"
                        continue
                    }

                    try {
                        Robocopy $fileBackupPath (Split-Path -Path $originalPath -Parent) (Split-Path -Leaf $originalPath) /MOV /NFL /NDL /NJH /NJS
                        Write-Info "Restored $fileBackupPath to $originalPath"
                        "Restored $fileBackupPath to $originalPath" | Out-File -Append -FilePath $global:logPath
                    } catch {
                        Write-LogError "Error restoring ${fileBackupPath} to ${originalPath}: $_"
                    }
                }
                Remove-Item -Path $selectedBackup.FullName -Recurse -Force
                Write-Info "Files restored to their original locations. Backup folder $($selectedBackup.FullName) deleted."
            } else {
                Write-LogError "Log file not found for the selected backup. Cannot restore files."
            }
        } else {
            Write-LogError "Invalid selection. Returning to main menu."
        }
    }

    function SetupCleanDirNBack {
        $global:rootPath = "C:\"
        $global:backupRoot = "C:\cacheBackup"
        $global:filesMoved = @()
        Write-Info "Exporting the list of users to C:\users\$env:USERNAME\users.csv..."
    }

    function UserList {
        Get-ChildItem -Path C:\Users | Select-Object Name | Export-Csv -Path "C:\users\$env:USERNAME\users.csv" -NoTypeInformation
        $list = Test-Path "C:\users\$env:USERNAME\users.csv"
        Write-Info "User List Saved..."
    }

    function TestBackDir {
        if (-not (Test-Path -Path $global:backupRoot)) {
            New-Item -Path $global:backupRoot -ItemType Directory -Force | Out-Null
            Write-Info "Backup root directory created..."
        } else {
            Remove-Item -Path $global:backupRoot -Recurse -Force
            New-Item -Path $global:backupRoot -ItemType Directory -Force | Out-Null
            Write-Info "Backup root directory recreated..."
        }

        $global:date = Get-Date -Format "yyyyMMddHHmmss"
        $global:backupDir = Join-Path -Path $global:backupRoot -ChildPath "cacheBackup_$global:date"
        New-Item -Path $global:backupDir -ItemType Directory -Force | Out-Null
        $global:logPath = Join-Path -Path $global:backupRoot -ChildPath "$($global:date).log"
        New-Item -Path $global:logPath -ItemType File -Force | Out-Null
    }

    $global:excludedExtensions = @(
        ".7z", ".7Z", ".a", ".A", ".accdb", ".ACCDB", ".aep", ".AEP", ".ai", ".AI", ".ani", ".ANI", ".aspx", ".ASPX", 
        ".bak", ".BAK", ".bat", ".BAT", ".bin", ".BIN", ".BLOB", ".blob", ".blog", ".BLOG", ".bik", ".BIK", ".cdxml", 
        ".CDXML", ".cert", ".CERT", ".chk", ".CHK", ".class", ".CLASS", ".cmd", ".CMD", ".com", ".COM", ".conf", ".CONF", 
        ".config", ".CONFIG", ".cpp", ".CPP", ".cppproj", ".CPPPROJ", ".cpl", ".CPL", ".cs", ".CS", ".csproj", ".CSPROJ", 
        ".csv", ".CSV", ".cur", ".CUR", ".dat", ".DAT", ".dat64", ".DAT64", ".data", ".DATA", ".db", ".DB", ".dds", ".DDS", 
        ".deskthemepack", ".DESKTHEMEPACK", ".dll", ".DLL", ".doc", ".DOC", ".docx", ".DOCX", ".dtsx", ".DTSX", ".dtsConfig", 
        ".DTSCONFIG", ".dylib", ".DYLIB", ".epub", ".EPUB", ".etl", ".ETL", ".exe", ".EXE", ".f#", ".F#", ".fingerprint", 
        ".FINGERPRINT", ".fla", ".FLA", ".flp", ".FLP", ".gadget", ".GADGET", ".git", ".GIT", ".gitignore", ".GITIGNORE", 
        ".go", ".GO", ".groovy", ".GROOVY", ".gz", ".GZ", ".h", ".H", ".hg", ".HG", ".hdf", ".HDF", ".htaccess", ".HTACCESS", 
        ".hpp", ".HPP", ".ico", ".ICO", ".IMG", ".img", ".indd", ".INDD", ".ini", ".INI", ".inUse", ".INUSE", ".iso", ".ISO", ".idx", 
        ".IDX", ".java", ".JAVA", ".jar", ".JAR", ".jsp", ".JSP", ".js", ".JS", ".jsx", ".JSX", ".json", ".JSON", ".jrs", ".JRS", 
        ".key", ".KEY", ".kt", ".KT", ".ldf", ".LDF", ".license", ".LICENSE", ".lib", ".LIB", ".LINK", ".lnk", ".LNK", ".lock", ".LOCK", 
        ".log", ".LOG", ".LOG1", ".log1", ".LOG2", ".log2", ".mht", ".MHT", ".mhtml", ".MHTML", ".map", ".MAP", ".manifest", ".MANIFEST", 
        ".md", ".MD", ".markdown", ".MARKDOWN", ".mdb", ".MDB", ".mdf", ".MDF", ".ml", ".ML", ".msc", ".MSC", ".msi", ".MSI", ".msp", 
        ".MSP", ".mpp", ".MPP", ".ndf", ".NDF", ".npmrc", ".NPMRC", ".obj", ".OBJ", ".o", ".O", ".old", ".OLD", ".ost", ".OST", ".ova", ".OVA", 
        ".ovf", ".OVF", ".old", ".OLD", ".pfx", ".PFX", ".pak", ".PAK", ".php", ".PHP", ".phf", ".PHF", ".pma", ".PMA", ".pl", ".PL", 
        ".pm", ".PM", ".PMA", ".pma", ".png", ".PNG", ".pdf", ".PDF", ".ppt", ".PPT", ".pptx", ".PPTX", ".properties", ".PROPERTIES", 
        ".prproj", ".PRPROJ", ".ps1", ".PS1", ".psd", ".PSD", ".psd1", ".PSD1", ".ps1xml", ".PS1XML", ".psm1", ".PSM1", ".psp", ".PSP", 
        ".py", ".PY", ".pyc", ".PYC", ".r", ".R", ".rar", ".RAR", ".rdl", ".RDL", ".rdlc", ".RDLC", ".rel", ".REL", ".resx", ".RESX", 
        ".rb", ".RB", ".rds", ".RDS", ".sdf", ".SDF", ".scala", ".SCALA", ".sch", ".SCH", ".scr", ".SCR", ".ses", ".SES", ".sh", ".SH", 
        ".sln", ".SLN", ".so", ".SO", ".sql", ".SQL", ".sqlite", ".SQLITE", ".sql", ".SQL", ".ssh", ".SSH", ".swift", ".SWIFT", ".swiftproj", ".SWIFTPROJ", 
        ".svn", ".SVN", ".sys", ".SYS", ".tar", ".TAR", ".tbres", ".TBRES", ".theme", ".THEME", ".themepack", ".THEMEPACK", ".tiff", ".TIFF", 
        ".tif", ".TIF", ".ts", ".TS", ".tsx", ".TSX", ".v2", ".V2", ".val", ".VAL", ".vbproj", ".VBPROJ", ".vbs", ".VBS", 
        ".vdi", ".VDI", ".vmdk", ".VMDK", ".vmx", ".VMX", ".vpk", ".VPK", ".vhdx", ".VHDX", ".war", ".WAR", ".x3d", ".X3D", ".xcodeproj", ".XCODEPROJ", 
        ".xcf", ".XCF", ".xml", ".XML", ".yaml", ".YAML", ".yml", ".YML", ".zip", ".ZIP", ".z", ".Z", ".title", ".manifest", ".mum"
    )

    $global:excludedDirectories = @(
        "C:\Windows\System32\LogFiles",
        "C:\cacheBackup",
        "C:\Windows\System32\config",
        "C:\Program Files\Common Files\System",
        "C:\ProgramData\Microsoft\Diagnosis",
        "C:\Program Files (x86)\Common Files\Adobe\ARM",
        "C:\Program Files (x86)\Microsoft Office\Office16\XLSTART",
        "C:\Windows\SoftwareDistribution\DataStore",
        "C:\Users\$env:USERNAME\Thorlabs-Gothenburg-IT-Scripts",
        "C:\Users\$env:USERNAME\Thorlabs-Gothenburg-IT-Scripts - Copy"
    )

    function ScanNMove {
        Write-Info "Scanning for cache directories and files..."
        "Scanning for cache directories and files..." | Out-File -Append -FilePath $global:logPath
    
        $allDirectories = Get-ChildItem -Path $global:rootPath -Directory -Recurse -Force -ErrorAction SilentlyContinue -Verbose |
            Where-Object { $_.FullName -like "*cache*" -and $global:excludedDirectories -notcontains $_.FullName }

        foreach ($dir in $allDirectories) {
            Write-Info "Processing directory: $($dir.FullName)"
            "Processing directory: $($dir.FullName)" | Out-File -Append -FilePath $global:logPath

            $files = Get-ChildItem -Path $dir.FullName -File -Recurse -Force -ErrorAction SilentlyContinue -Verbose |
                Where-Object {
                    $extension = $_.Extension.ToLower()
                    $name = $_.Name.ToLower()
                    $excluded = $global:excludedExtensions -contains $extension -or ($global:excludedExtensions | ForEach-Object { $_.TrimStart('.') } | ForEach-Object { $_.ToUpper() }) -contains $name
                    -not $excluded -and
                    -not $_.Attributes.ToString().Split(',').Contains('System')
                }

            foreach ($file in $files) {
                if ([console]::KeyAvailable) {
                    [console]::ReadKey($true) | Out-Null
                    Write-Info "Process interrupted by user."
                    $global:userInput = Read-Host "Press 'C' to compress the folder or 'M' to move files back:"

                    if ($global:userInput.ToUpper() -eq 'C') {
                        Compress
                        return
                    } elseif ($global:userInput.ToUpper() -eq 'M') {
                        MoveFilesBack
                        return
                    }
                }

                $destinationFile = Join-Path -Path $global:backupDir -ChildPath $file.Name
                Robocopy $file.FullName $global:backupDir $file.Name /MOV /NFL /NDL /NJH /NJS
                $global:filesMoved += @{ "OriginalPath"=$file.FullName; "BackupPath"=$destinationFile; "OriginalName"=$file.Name }
                "$($file.FullName) moved to $destinationFile" | Out-File -Append -FilePath $global:logPath
                Write-Info "$($file.FullName) moved to $destinationFile"
            }
        }
    }

    function Compress {
        Write-Info "Compressing backup..."
        "Compressing backup..." | Out-File -Append -FilePath $global:logPath
        while ($true) {
            try {
                $compressedFile = "$global:backupDir.zip"
                Compress-Archive -Path $global:backupDir -DestinationPath $compressedFile -Force
                Remove-Item -Path $global:backupDir -Recurse -Force
                "Backup and compression complete. Files Moved: $($global:filesMoved.Count)." | Out-File -Append -FilePath $global:logPath
                Write-Info "Backup and compression complete. Files Moved: $($global:filesMoved.Count)."
                break
            } catch {
                Write-LogError "Error during compression: $_"
                "Error during compression: $_" | Out-File -Append -FilePath $global:logPath
                # Move all files back to their original locations and retry compression
                $filesInBackupDir = Get-ChildItem -Path $global:backupDir -Recurse -File
                foreach ($fileInBackupDir in $filesInBackupDir) {
                    # Try to move the file back to its original location
                    $originalFileDetails = $global:filesMoved | Where-Object { $_.BackupPath -eq $fileInBackupDir.FullName }
                    if ($originalFileDetails) {
                        Robocopy $fileInBackupDir.FullName (Split-Path -Path $originalFileDetails.OriginalPath -Parent) (Split-Path -Leaf $originalFileDetails.OriginalPath) /MOV /NFL /NDL /NJH /NJS
                        "Moved $($fileInBackupDir.FullName) back to $($originalFileDetails.OriginalPath) due to compression error" | Out-File -Append -FilePath $global:logPath
                        Write-Info "Moved $($fileInBackupDir.FullName) back to $($originalFileDetails.OriginalPath) due to compression error"
                        # Remove this file from the filesMoved list as it's no longer in the backup directory
                        $global:filesMoved = $global:filesMoved | Where-Object { $_.BackupPath -ne $fileInBackupDir.FullName }
                    }
                }
                if (-not (Get-ChildItem -Path $global:backupDir -File)) {
                    Write-Info "No files left to compress. Exiting compression loop."
                    "No files left to compress. Exiting compression loop." | Out-File -Append -FilePath $global:logPath
                    break
                }
            }
        }
    }

    function MoveFilesBack {
        Write-Info "Moving files back to their original locations..."
        "Moving files back to their original locations..." | Out-File -Append -FilePath $global:logPath

        foreach ($file in $global:filesMoved) {
            try {
                if (Test-Path -Path $file.BackupPath) {
                    Robocopy $file.BackupPath (Split-Path -Path $file.OriginalPath -Parent) (Split-Path -Leaf $file.OriginalPath) /MOV /NFL /NDL /NJH /NJS
                    "Moved $($file.BackupPath) back to $($file.OriginalPath)" | Out-File -Append -FilePath $global:logPath
                    Write-Info "Moved $($file.BackupPath) back to $($file.OriginalPath)"
                } else {
                    Write-LogError "Backup file not found: $($file.BackupPath)"
                }
            } catch {
                Write-LogError "Error moving ${file.BackupPath} back to ${file.OriginalPath}: $_"
            }
        }
    
        if (Test-Path -Path $global:backupDir) {
            Remove-Item -Path $global:backupDir -Recurse -Force
        }
    }

    function ReturnToMenu {
        do {
            Write-Host -NoNewline -ForegroundColor Yellow "Press 'Y' to return to the main menu or any other key to retry the script: "
            $global:userInput = Read-Host
            if ($global:userInput.ToUpper() -eq 'Y') {
                Show-Menu
                break
            } else {
                Write-Confirm "Retrying the script..."
                DeepCacheClearing
                break
            }
        } while ($true)
    }

    WelcomeClean
    if (WarningClean) {
        SetupCleanDirNBack
        UserList
        TestBackDir
        ScanNMove
        Write-Host -NoNewline -ForegroundColor Yellow "Do you want to (1) Compress the backup or (2) Move files back? (1/2): "
        $global:userInput = Read-Host
        if ($global:userInput -eq '1') {
            Compress
        } elseif ($global:userInput -eq '2') {
            MoveFilesBack
        }
    }
    ReturnToMenu
}

# Function to clear common program caches
function ClearCommonProgramCache {
    Write-Section "SECTION 4: Clear Cache From Common Windows Programs"

    # Define smaller functions within the main function
    function FetchInstalledPrograms {
        Fetch-And-Display-InstalledPrograms
    }

    function RemoveCacheItems {
        param (
            [string]$ProfilePath,
            [string]$CachePath
        )
        $fullPath = Join-Path -Path $ProfilePath -ChildPath $CachePath
        Write-Info "Removing cache at $fullPath"
        Remove-Item -Path $fullPath -Recurse -Force -ErrorAction SilentlyContinue -Verbose
        Write-Info "Cache removed at $fullPath"
    }

    function ClearFirefoxCache {
        if (Is-Installed "Mozilla Firefox") {
            Write-Info "Clearing Mozilla Firefox Caches"
            Import-Csv -Path C:\users\$env:USERNAME\users.csv | ForEach-Object {
                $ProfilePath = "C:\Users\$($_.Name)\AppData\Local\Mozilla\Firefox\Profiles\*.default"
                RemoveCacheItems -ProfilePath $ProfilePath -CachePath "cache\*"
                RemoveCacheItems -ProfilePath $ProfilePath -CachePath "cache2\entries\*.*"
                RemoveCacheItems -ProfilePath $ProfilePath -CachePath "thumbnails\*"
                RemoveCacheItems -ProfilePath $ProfilePath -CachePath "cookies.sqlite"
                RemoveCacheItems -ProfilePath $ProfilePath -CachePath "webappsstore.sqlite"
                RemoveCacheItems -ProfilePath $ProfilePath -CachePath "chromeappsstore.sqlite"
            }
            Write-Confirm "Clearing Mozilla Firefox caches completed."
        } else {
            Write-Info "Mozilla Firefox is not installed, skipping task..."
        }
    }

    function ClearAdobeCache {
        if (Is-Installed "Adobe Reader") {
            Write-Info "Clearing Adobe Acrobat Caches"
            Import-Csv -Path C:\users\$env:USERNAME\users.csv | ForEach-Object {
                $ProfilePath = "C:\Users\$($_.Name)\AppData\Local\Adobe\Acrobat\DC"
                RemoveCacheItems -ProfilePath $ProfilePath -CachePath "Cache\*"
                RemoveCacheItems -ProfilePath $ProfilePath -CachePath "Acrobat\Cookie\*"
                RemoveCacheItems -ProfilePath $ProfilePath -CachePath "*.log"
                RemoveCacheItems -ProfilePath $ProfilePath -CachePath "*.tmp"
            }
            Write-Confirm "Adobe cache and specific files cleanup completed."
        } else {
            Write-Info "Adobe Acrobat is not installed, skipping task..."
        }
    }

    function ClearChromeCache {
        if (Is-Installed "Google Chrome") {
            Write-Info "Clearing Google Chrome Caches"
            Import-Csv -Path C:\users\$env:USERNAME\users.csv | ForEach-Object {
                $ChromePath = "C:\Users\$($_.Name)\AppData\Local\Google\Chrome\User Data\Default"
                RemoveCacheItems -ProfilePath $ChromePath -CachePath "Cache\*"
                RemoveCacheItems -ProfilePath $ChromePath -CachePath "Cache2\entries\*"
                RemoveCacheItems -ProfilePath $ChromePath -CachePath "Cookies\*"
                RemoveCacheItems -ProfilePath $ChromePath -CachePath "Media Cache\*"
                RemoveCacheItems -ProfilePath $ChromePath -CachePath "Cookies-Journal\*"
                RemoveCacheItems -ProfilePath $ChromePath -CachePath "ChromeDWriteFontCache\*"
            }
            Write-Confirm "Clearing Google Chrome caches completed."
        } else {
            Write-Info "Google Chrome is not installed, skipping task..."
        }
    }

    function ClearWindowsCache {
        Write-Info "Cleaning up local Windows system caches"
        Import-Csv -Path C:\users\$env:USERNAME\users.csv | ForEach-Object {
            RemoveCacheItems -ProfilePath "C:\Windows" -CachePath "Temp\*"
            RemoveCacheItems -ProfilePath "C:\Windows" -CachePath "prefetch\*"
            RemoveCacheItems -ProfilePath "C:\Users\$($_.Name)\AppData\Local\Microsoft\Windows" -CachePath "Temporary Internet Files\*"
            RemoveCacheItems -ProfilePath "C:\Users\$($_.Name)\AppData\Local\Microsoft\Windows" -CachePath "Caches\*"
            RemoveCacheItems -ProfilePath "C:\Users\$($_.Name)\AppData\Local\Microsoft\Windows" -CachePath "ActionCenterCache\*"
            RemoveCacheItems -ProfilePath "C:\Users\$($_.Name)\AppData\Local\Microsoft\Windows\WER" -CachePath "*"
            RemoveCacheItems -ProfilePath "C:\Users\$($_.Name)\AppData\Local\Temp" -CachePath "*"
            RemoveCacheItems -ProfilePath "C:\Users\$($_.Name)\AppData\Local\Microsoft\Edge\User Data\Default\Code Cache" -CachePath "*"
            RemoveCacheItems -ProfilePath "C:\Users\$($_.Name)\AppData\Local\Microsoft\Edge\User Data\ShaderCache" -CachePath "*"
            RemoveCacheItems -ProfilePath "C:\Users\$($_.Name)\Microsoft\Edge\User Data\Default\Cache" -CachePath "*"
            RemoveCacheItems -ProfilePath "C:\`$recycle.bin" -CachePath "*"
        }
        Write-Confirm "Local Windows system cache cleanup completed."
    }

    # Execute the functions in order
    FetchInstalledPrograms
    ClearFirefoxCache
    ClearAdobeCache
    ClearChromeCache
    ClearWindowsCache

    Write-Host "Press 'Y' to return to the main menu, or any other key to exit."
    $returnToMenu = Read-Host
    if ($returnToMenu -eq 'Y' -or $returnToMenu -eq 'y') {
        Show-Menu
    } else {
        Write-Confirm "Exiting..."
    }
}

function PerformDiskCleanup {
    Write-Section "SECTION 5: Disk Cleanup"

    function ClearPreviousSettings {
        Write-Info "Clearing previous automation settings..."
        try {
            Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\*' -Name StateFlags0001 -ErrorAction SilentlyContinue -Verbose |
            Remove-ItemProperty -Name StateFlags0001 -ErrorAction SilentlyContinue -Verbose
        } catch {
            Write-LogError "Error clearing automation settings: $_"
        }
    }

    function EnableUpdateCleanup {
        Write-Info "Enabling Update Cleanup. Automatically managed in Windows 10 and set manually for assurance in Windows 11..."
        try {
            New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Update Cleanup' -Name StateFlags0001 -Value 2 -PropertyType DWord -ErrorAction Stop -Verbose
        } catch {
            Write-LogError "Error setting Update Cleanup: $_"
        }
    }

    function EnableTempFilesCleanup {
        Write-Info "Enabling Temporary Files Cleanup..."
        try {
            New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Files' -Name StateFlags0001 -Value 2 -PropertyType DWord -ErrorAction Stop -Verbose
        } catch {
            Write-LogError "Error setting Temporary Files Cleanup: $_"
        }
    }

    function StartDiskCleanup {
        Write-Info "Starting Disk Cleanup to perform cleanup tasks..."
        try {
            Start-Process -FilePath CleanMgr.exe -ArgumentList '/sagerun:1' -WindowStyle Hidden -Wait
            Write-Info "Waiting for Disk Cleanup process to complete..."
            Get-Process -Name cleanmgr -ErrorAction SilentlyContinue -Verbose | Wait-Process
            Write-Confirm "Disk Cleanup process completed."
        } catch {
            Write-LogError "Error starting or waiting for CleanMgr.exe: $_"
        }
    }

    function ClearAutomationFlags {
        Write-Info "Clearing automation settings post-cleanup..."
        try {
            Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\*' -Name StateFlags0001 -ErrorAction SilentlyContinue -Verbose |
            Remove-ItemProperty -Name StateFlags0001 -ErrorAction SilentlyContinue -Verbose
            Write-Confirm "Disk Cleanup automation settings have been cleared."
        } catch {
            Write-LogError "Error clearing automation settings post-cleanup: $_"
        }
    }

    ClearPreviousSettings
    EnableUpdateCleanup
    EnableTempFilesCleanup
    StartDiskCleanup
    ClearAutomationFlags

    $returnToMenu = Read-Host "Press 'Y' to return to the main menu, or any other key to exit."
    if ($returnToMenu -eq 'Y' -or $returnToMenu -eq 'y') {
        Show-Menu
    } else {
        Write-Confirm "Exiting..."
    }
}

function RepairOSImage {
    Clear-Host
    Write-Section "SECTION 6: Repair OS-Image"

    function StartOSRepair {
        Write-Info "Starting OS-Image repair task..."
        try {
            $dismResult = DISM /Online /Cleanup-Image /Restore-health
            if ($LASTEXITCODE -ne 0) {
                throw "DISM failed with exit code $LASTEXITCODE"
            }
            Write-Confirm "OS-Image repair task completed successfully."
        } catch {
            Write-LogError "An error occurred during DISM operation: $_"
        }
    }

    StartOSRepair

    $returnToMenu = Read-Host "Press 'Y' to return to the main menu, or any other key to exit."
    if ($returnToMenu -eq 'Y' -or $returnToMenu -eq 'y') {
        Show-Menu
    } else {
        Write-Confirm "Exiting..."
    }
}

function OptimizeDisks {
    Clear-Host
    Write-Section "SECTION 7: Disk Defragmentation, Optimization, and TRIM for SSDs"

    function CollectDiskInfo {
        Write-Info "Collecting Disk type Information..."
        $global:disks = Get-PhysicalDisk | Select-Object DeviceID, MediaType
    }

    function AnalyzeAndDefrag {
        foreach ($disk in $global:disks) {
            Write-Info "Checking if disk is HDD or SSD..."

            if ($disk.MediaType -eq 'HDD') {
                Write-Info "Disk $($disk.DeviceID) is an HDD. Initiating defragmentation process..."
                $volumes = Get-WmiObject -Class Win32_Volume | Where-Object { $_.DriveType -eq 3 }

                foreach ($volume in $volumes) {
                    if ($volume.DriveLetter -ne $null) {
                        Write-Info "Analyzing and defragmenting volume: $($volume.Caption)..."
                        $analysis = $volume.DefragAnalysis()
                        if ($analysis.DefragAnalysis) {
                            Write-Console "Fragmentation Level: $($analysis.DefragAnalysis.TotalPercentFragmentation)%"
                        }

                        $defragResult = $volume.Defrag($true)
                        if ($defragResult.ReturnValue -eq 0) {
                            Write-Confirm "Defragmentation successful on volume: $($volume.Caption)"
                        } else {
                            Write-LogError "Defragmentation failed with code: $($defragResult.ReturnValue) on volume: $($volume.Caption)"
                        }
                    }
                }
            } elseif ($disk.MediaType -eq 'SSD') {
                Write-Info "Disk $($disk.DeviceID) is an SSD. Initiating TRIM command..."
                $volumes = Get-WmiObject -Class Win32_Volume | Where-Object { $_.DriveType -eq 3 }

                foreach ($volume in $volumes) {
                    if ($volume.DriveLetter -ne $null) {
                        Write-Info "Performing TRIM on volume: $($volume.Caption)..."
                        Optimize-Volume -DriveLetter $volume.DriveLetter -ReTrim -Verbose
                    }
                }
            } else {
                Write-Info "Disk $($disk.DeviceID) is neither HDD nor SSD or type is unknown. No specific action taken."
            }
        }
    }

    CollectDiskInfo
    AnalyzeAndDefrag

    $returnToMenu = Read-Host "Press 'Y' to return to the main menu, or any other key to exit."
    if ($returnToMenu -eq 'Y' -or $returnToMenu -eq 'y') {
        Show-Menu
    } else {
        Write-Confirm "Exiting..."
    }
}

function FlushDNSCache {
    Write-Section "SECTION 8: Clearing DNS Client Cache"

    function StartDNSFlush {
        Write-Info "Starting DNS Client cache clean up task..."
        Write-Info "Flushing DNS..."
        try {
            Clear-DnsClientCache
            Write-Confirm "DNS Flush task completed."
        } catch {
            Write-LogError "Error occurred while flushing DNS: $_"
        }
    }

    StartDNSFlush

    $returnToMenu = Read-Host "Press 'Y' to return to the main menu, or any other key to exit."
    if ($returnToMenu -eq 'Y' -or $returnToMenu -eq 'y') {
        Show-Menu
    } else {
        Write-Confirm "Exiting..."
    }
}

function Run-ChkdskAndRestart {
    Write-Section "SECTION 9: Disk Check and Restart"

    function ScheduleChkdsk {
        Write-Info "Scheduling disk check and preparing to restart..."
        try {
            echo Y | chkdsk C: /v /f /r
            Start-Sleep -Seconds 5
            Write-Info "Restarting the computer now..."
            shutdown /r /t 0
        } catch {
            Write-LogError "Error occurred while scheduling chkdsk or restarting: $_"
        }
    }

    ScheduleChkdsk
}

# Main Menu and option selection functionality
function Show-Menu {
    param ([string]$Title = 'Computer Clean Up Menu')
    Write-Section $Title
    
    # Menu options
    Write-Confirm "1: User Session Management - Logs off all users except the current. (Recommended)"
    Write-Confirm "2: Delete user profile from windows device"
    Write-Confirm "3: Deep Cache Clearing - Clears system and application caches."
    Write-Confirm "4: Common Program Cache Cleaning - Clears cache from browsers and more."
    Write-Confirm "5: Disk Cleanup - Cleans temporary files and updates."
    Write-Confirm "6: OS Image Repair - Runs DISM and SFC to repair system files."
    Write-Confirm "7: Disk Optimization - Optimizes HDDs and SSDs."
    Write-Confirm "8: DNS Cache Flush - Clears DNS cache to resolve network issues."
    Write-Confirm "9: Disk Check and Restart - Intensive scan and repair. WARNING: Restarts immediately!"
    Write-Confirm "Q: Quit - Exit the menu and end the session."

    # Get validated user input
    $selection = Get-ValidatedInput "Please select an option" @("1","2","3","4","5","6","7","8","9","Q")
    switch ($selection) {
        '1' { LogOffAllUsersExceptCurrent }
        '2' { DeleteUserProfile }
        '3' { DeepCacheClearing }
        '4' { ClearCommonProgramCache }
        '5' { PerformDiskCleanup }
        '6' { RepairOSImage }
        '7' { OptimizeDisks }
        '8' { FlushDNSCache }
        '9' { Run-ChkdskAndRestart }
        'Q' { exit }
        default { Write-LogError "Invalid selection, please try again."; Show-Menu }
    }
}

# Call the menu function to start the script
Show-Menu
