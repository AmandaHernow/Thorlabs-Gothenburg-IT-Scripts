# Color-coded message functions setup
$section = {
    param($text)
    Write-Host -ForegroundColor Blue "-------------------"
    Write-Host -ForegroundColor Green $text
    Write-Host -ForegroundColor Blue "-------------------"
}
$confirm = { param([string]$text) Write-Host -ForegroundColor Green $text }
$info = { param([string]$text) Write-Host -ForegroundColor Yellow $text }
$logError = { param([string]$text) Write-Host -ForegroundColor Red $text }
$console = { param([string]$text) Write-Host -ForegroundColor Cyan $text }

# Display Header Information
Write-Host -ForegroundColor Blue "---------------------Developed by Amanda Hernow - Thorlabs Sweden AB---------------------"
&$confirm "Use: PowerShell script to be executed remotely on production PC using PSexec, scheduled task, or run from autofire HID device."
&$confirm "Program Description: Automates clean disk, clearing cache and cookies on all user accounts on the targeted PC, performs optimization and defragmentations on hard drive"
&$confirm "Developer: Amanda Hernow, Thorlabs Sweden AB"
&$confirm "Version: 2.1 Updated: 08-05-2024"
Write-Host -ForegroundColor Blue "-------------------------------PowerShell Script - PC Clean Up---------------------------"

# Change Log and Coming Soon Section
&$confirm "CHANGE_LOG:
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
v.2.1: Added function to remove userprofile from windows device."
&$info "COMING_SOON:
1. Development of a switch menu for Program picker to clean common program files only
2. Deciding on execution methods: scheduled tasks, autofire HID devices, or through PSexec remotely.
3. Explore the possibility of dynamically finding cache paths from program installation paths for targeted cleaning.
4. Implement robust error handling to manage and log exceptions and errors effectively."

# Main Menu and option selection functionality
function Show-Menu {
    param ([string]$Title = 'Computer Clean Up Menu')
    &$section $Title
    &$confirm "1: Deep Cache Clearing - Clears system and application caches."
    &$confirm "2: User Session Management - Logs off all users except the current. (Recommended)"
    &$confirm "3: Delete user profile from windows device"
    &$confirm "4: Common Program Cache Cleaning - Clears cache from browsers and more."
    &$confirm "5: Disk Cleanup - Cleans temporary files and updates."
    &$confirm "6: OS Image Repair - Runs DISM and SFC to repair system files."
    &$confirm "7: Disk Optimization - Optimizes HDDs and SSDs."
    &$confirm "8: DNS Cache Flush - Clears DNS cache to resolve network issues."
    &$confirm "9: Disk Check and Restart - Intensive scan and repair. WARNING: Restarts immediately!"
    &$confirm "Q: Quit - Exit the menu and end the session."
}

function Select-Option {
    Show-Menu
    $userChoice = Read-Host "Select an option by number (or 'Q' to Quit)"
    switch ($userChoice) {
        '1' { DeepCacheClearing }
        '2' { LogOffAllUsersExceptCurrent }
        '3' { DeleteUserProfile }
        '4' { ClearCommonProgramCache }
        '5' { PerformDiskCleanup }
        '6' { RepairOSImage }
        '7' { OptimizeDisks }
        '8' { FlushDNSCache }
        '9' { Run-ChkdskAndRestart }
        'Q' {
            &$confirm "Exiting..."
            exit
        }
        default {
            &$logError "Invalid option, please try again."
            Start-Sleep -Seconds 2
            Select-Option  # Recursively call Select-Option to handle retries
        }
    }
}

function DeepCacheClearing {
    &$info "Opening Deep Cache Clearing..."
    &$section "SECTION 1: Deep Cache Clearing"

    # Warning and confirmation
    &$info "WARNING: This function aims to comprehensively clean cache files across the system and software directories."
    &$info "Press 'Y' to proceed or any other key to return to the main menu. Proceed with caution."
    &$confirm "Do you want to proceed? (Y/N): "
    $userInput = Read-Host
    if ($userInput.ToUpper() -ne 'Y') {
        &$info "Operation cancelled by user. Returning to main menu..."
        Select-Option
        return
    }

    # Initial setup and backup directory check
    $rootPath = "C:\"
    $backupRoot = "C:\cacheBackup"
    $filesMoved = @()
    &$info "Exporting the list of users to c:\users\$env:USERNAME\users.csv..."
    # List the users in c:\users and export to the local profile for calling later
    dir C:\Users | select Name | Export-Csv -Path C:\users\$env:USERNAME\users.csv -NoTypeInformation
    $list=Test-Path C:\users\$env:USERNAME\users.csv
    &$info "User List Saved..."

    # Ensure the backup root directory exists
    if (-not (Test-Path -Path $backupRoot)) {
        New-Item -Path $backupRoot -ItemType Directory -Force | Out-Null
        &$info "Backup root directory created..."
    } else {
        &$info "Backup root directory already exists..."
    }

    $date = Get-Date -Format "yyyyMMddHHmmss"
    $backupDir = Join-Path -Path $backupRoot -ChildPath "cacheBackup_$date"
    New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
    $logPath = Join-Path -Path $backupRoot -ChildPath "$($date).log"
    New-Item -Path $logPath -ItemType File -Force | Out-Null

    # Define excluded extensions and directories to skip
    $excludedExtensions = @(
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
    ".xcf", ".XCF", ".xml", ".XML", ".yaml", ".YAML", ".yml", ".YML", ".zip", ".ZIP", ".z", ".Z"
    )
    $excludedDirectories = @(
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

    &$info "Scanning for cache directories and files..." | Out-File -Append -FilePath $logPath
    $allDirectories = Get-ChildItem -Path $rootPath -Directory -Recurse -Force -ErrorAction SilentlyContinue -Verbose |
        Where-Object { $_.FullName -like "*cache*" -and $excludedDirectories -notcontains $_.FullName }

    foreach ($dir in $allDirectories) {
        $files = Get-ChildItem -Path $dir.FullName -File -Recurse -Force -ErrorAction SilentlyContinue -Verbose |
            Where-Object {
                $_.Extension -notin $excludedExtensions -and
                -not $_.Attributes.ToString().Split(',').Contains('System')
            }

        foreach ($file in $files) {
            $destinationFile = Join-Path -Path $backupDir -ChildPath $file.Name
            Robocopy $dir.FullName $backupDir $file.Name /MOV /NFL /NDL /NJH /NJS
            $filesMoved += @{ "OriginalPath"=$file.FullName; "BackupPath"=$destinationFile; "OriginalName"=$file.Name }
            "$($file.FullName) moved to $destinationFile" | Out-File -Append -FilePath $logPath
        }
    }

    &$info "Compressing backup..." | Out-File -Append -FilePath $logPath
    while ($true) {
        try {
            $compressedFile = "$backupDir.zip"
            Compress-Archive -Path $backupDir -DestinationPath $compressedFile -Force
            Remove-Item -Path $backupDir -Recurse -Force
            "Backup and compression complete. Files Moved: $($filesMoved.Count)." | Out-File -Append -FilePath $logPath
            break
        } catch {
            &$logError "Error during compression: $_"  # Log the specific compression error
            "Compression attempt failed: $_" | Out-File -Append -FilePath $logPath
            # Move all files back to their original locations and retry compression
            $filesInBackupDir = Get-ChildItem -Path $backupDir -Recurse -File
            foreach ($fileInBackupDir in $filesInBackupDir) {
                # Try to move the file back to its original location
                $originalFileDetails = $filesMoved | Where-Object { $_.BackupPath -eq $fileInBackupDir.FullName }
                if ($originalFileDetails) {
                    Move-Item -Path $fileInBackupDir.FullName -Destination $originalFileDetails.OriginalPath -Force
                    "Moved $($fileInBackupDir.FullName) back to $($originalFileDetails.OriginalPath) due to compression error" | Out-File -Append -FilePath $logPath
                    # Remove this file from the filesMoved list as it's no longer in the backup directory
                    $filesMoved = $filesMoved | Where-Object { $_.BackupPath -ne $fileInBackupDir.FullName }
                }
            }
            if (-not (Get-ChildItem -Path $backupDir -File)) {
                &$info "No files left to compress. Exiting compression loop." | Out-File -Append -FilePath $logPath
                break
            }
        }
    }

    $returnToMenu = Read-Host "Press 'Y' to return to the main menu, or any other key to exit."
    if ($returnToMenu -eq 'Y' -or $returnToMenu -eq 'y') {
        Select-Option
    } else {
        &$confirm "Exiting..."
    }
}

function LogOffAllUsersExceptCurrent {
    Clear-Host
    &$section "SECTION 2: Logging Off All Users Except Current Session..."

    # Retrieve current username and session ID for more accurate identification
    $currentUserInfo = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $currentUsername = $currentUserInfo.Split('\')[-1]
    $queryCurrentUserSession = quser $currentUsername | Select-Object -Skip 1

    # Display current user information for debugging
    &$console "Current user info: $currentUserInfo"
    &$console "Query current user session: $queryCurrentUserSession"

    # Get a list of all logged on users using 'quser'
    $quserOutput = quser | Select-Object -Skip 1  # Skip the header

    # Parse the output to get session IDs and usernames
    $sessions = $quserOutput | ForEach-Object {
        if ($_ -match "(?i)(\w+)\s+(\d+)\s+") {
            @{
                UserName = $Matches[1].Trim()
                SessionID = $Matches[2]
            }
        }
    }

    # Log off each session except the current user's session
    foreach ($session in $sessions) {
        if ($session.UserName -ne $currentUsername) {
            &$info "Logging off user $($session.UserName) with session ID $($session.SessionID)..."
            # Uncomment the next line to actually log off the users when you're ready to use this function in production
            # logoff $session.SessionID
            Start-Sleep -Seconds 2  # A short pause to ensure each logoff command has time to execute
        } else {
            &$console "Skipping logoff for current user session: $($session.UserName) with session ID $($session.SessionID)"
        }
    }
    &$confirm "User logoff process completed."

    # Ask user if they want to return to the main menu
    $returnToMenu = Read-Host "Press 'Y' to return to the main menu, or any other key to exit."
    if ($returnToMenu -eq 'Y' -or $returnToMenu -eq 'y') {
        Select-Option
    } else {
        &$confirm "Exiting..."
    }
}

function DeleteUserProfile {
    &$info "Opening script to delete user profile from Windows device..."
    &$section "SECTION 3: Deleting User Profiles"

    do {
        $profiles = Get-WmiObject -Class Win32_UserProfile | Where-Object { !$_.Special }
        $i = 0
        $profiles | ForEach-Object {
            $i++
            &$confirm "$i. $($_.LocalPath)"
        }

        &$info "Enter the number of the profile you want to remove or or any key to return to main menu:"
        $selectedNumber = Read-Host

        if ($selectedNumber.ToUpper() -eq 'Q') {
            return
        }

        if ($selectedNumber -match '^\d+$' -and [int]$selectedNumber -gt 0 -and [int]$selectedNumber -le $i) {
            $selectedProfile = $profiles[[int]$selectedNumber - 1]
            &$info "Are you sure you want to remove the profile at $($selectedProfile.LocalPath)? (Y/N): "
            $confirm = (Read-Host).ToUpper()
            if ($confirm -eq 'Y') {
                try {
                    $verboseOutput = $selectedProfile | Remove-WmiObject -Verbose 4>&1
                    &$console $verboseOutput
                    &$confirm "Profile removed successfully."
                    break
                } catch {
                    &$logError "Failed to remove profile: $_"
                }
            } else {
                &$info "Profile removal canceled."
                Select-Option
            }
        } else {
            &$logError "Invalid input. Please enter a valid number corresponding to a user profile."
        }

        &$info "Do you want to try again? (Y/N):"
        $tryAgain = (Read-Host).ToUpper()
    } while ($tryAgain -eq 'Y')

    &$info "Would you like to (1) remove another profile, (2) return to the main menu, or (3) quit?"
    $userDecision = Read-Host "Enter your choice (1, 2, or 3):"
    switch ($userDecision) {
        '1' { DeleteUserProfile }
        '2' { Select-Option }
        '3' { &$confirm "Exiting..." ; exit }
        default { &$logError "Invalid selection, returning to main menu." ; Select-Option }
    }
}

function ClearCommonProgramCache {
    &$section "SECTION 4: Clear Cache From Common Windows Programs"

    &$info "Listing Device Users"
    # Write Information to the screen
    &$info "Exporting the list of users to c:\users\$env:USERNAME\users.csv..."
    # List the users in c:\users and export to the local profile for calling later
    dir C:\Users | select Name | Export-Csv -Path C:\users\$env:USERNAME\users.csv -NoTypeInformation
    $list=Test-Path C:\users\$env:USERNAME\users.csv
    &$info "User List Saved..."

    &$info "Listing Installed Programs"
    # Begin process of retrieving installed programs from the registry
    &$info "Exporting the list of Installed Programs to C:\users\$env:USERNAME\installed_programs.csv..."

    # Get list of installed programs from registry and store in CSV
    $registryPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    # Retrieve the display names of installed applications from the registry
    $installedPrograms = $registryPaths | ForEach-Object {
        Get-ItemProperty $_
    } | Select-Object DisplayName | Where-Object { $_.DisplayName -ne $null }

    # Export the list of installed programs to CSV
    $installedPrograms | Export-Csv -Path C:\users\$env:USERNAME\installed_programs.csv -NoTypeInformation -Force

    &$confirm "List of Installed Programs saved"
    ""

    &$info  "Running Script..."
    &$info "Starting up cache clearing process..."

    if ($list) {
        ""
        # Function to check if a program is installed
        function Is-Installed($appName) {
            $installedPrograms | Where-Object { $_.DisplayName -like "*$appName*" } | Select-Object -First 1
        }

        &$info "Scanning for Mozilla Firefox"
        ""
        # Clear Mozilla Firefox Cache if installed
        if (Is-Installed "Mozilla Firefox") {

            &$info "Clearing Mozilla Firefox Caches"
            &$info "Starting clearing Mozilla caches task..."
            &$console
            Import-CSV -Path C:\users\$env:USERNAME\users.csv -Header Name | foreach {
                $ProfilePath = "C:\Users\$($_.Name)\AppData\Local\Mozilla\Firefox\Profiles\*.default"

                Remove-Item -Path (Join-Path -Path $ProfilePath -ChildPath "cache\*") -Recurse -Force -EA SilentlyContinue -Verbose
                Remove-Item -Path (Join-Path -Path $ProfilePath -ChildPath "cache\*.*") -Recurse -Force -EA SilentlyContinue -Verbose
                Remove-Item -Path (Join-Path -Path $ProfilePath -ChildPath "cache2\entries\*.*") -Recurse -Force -EA SilentlyContinue -Verbose
                Remove-Item -Path (Join-Path -Path $ProfilePath -ChildPath "thumbnails\*") -Recurse -Force -EA SilentlyContinue -Verbose
                Remove-Item -Path (Join-Path -Path $ProfilePath -ChildPath "cookies.sqlite") -Recurse -Force -EA SilentlyContinue -Verbose
                Remove-Item -Path (Join-Path -Path $ProfilePath -ChildPath "webappsstore.sqlite") -Recurse -Force -EA SilentlyContinue -Verbose
                Remove-Item -Path (Join-Path -Path $ProfilePath -ChildPath "chromeappsstore.sqlite") -Recurse -Force -EA SilentlyContinue -Verbose
            }
            &$confirm "Clearing Mozilla Firefox caches completed."
            &$confirm "Done..."
        } else {
            &$info "Mozilla Firefox is not installed"
            &$info "skipping task..."
            &$info "Starting next process..."
            &$info "Scanning for Adobe Acrobat..."
            ""
        }

        &$info "Starting next process..."
        &$info "Scanning for Adobe Acrobat..."
        ""

        if (Is-Installed "Adobe Reader") {
            # Clear Adobe Acrobat Cache

            &$info "Clearing Adobe Acrobat Caches"
            &$info "Starting clearing of Adobe caches task..."

            Import-CSV -Path C:\users\$env:USERNAME\users.csv -Header Name | foreach {
                $ProfilePath = "C:\Users\$env:USERNAME\AppData\Local\Adobe\Acrobat\DC"

                # Clearing general cache
                &$info "Clearing general Acrobat cache..."
                &$console
                Remove-Item -Path (Join-Path -Path $ProfilePath -ChildPath "Cache\*") -Recurse -Force -EA SilentlyContinue -Verbose

                # Clearing cookie files
                &$info "Clearing Acrobat cookie files..."
                &$console
                Remove-Item -Path (Join-Path -Path $ProfilePath -ChildPath "Acrobat\Cookie\*") -Recurse -Force -EA SilentlyContinue -Verbose

                # Handling AcroCef Cache
                $AcroCefPath = "C:\Users\$env:USERNAME\AppData\Local\Adobe\AcroCef\DC\Acrobat\Cache"
                &$info "Clearing AcroCef cache and filtering specific files..."
                &$console
                Remove-Item -Path (Join-Path -Path $AcroCefPath -ChildPath "*.log") -Force -Verbose -EA SilentlyContinue -Verbose
                Remove-Item -Path (Join-Path -Path $AcroCefPath -ChildPath "*.tmp") -Recurse -Force -EA SilentlyContinue -Verbose

                # Handling ARM Cache (assuming clearing empty directories)
                $ARMPath = "C:\Users\$env:USERNAME\AppData\Local\Adobe\ARM"
                &$info "Cleaning up empty directories in Adobe ARM..."
                &$console
                Get-ChildItem -Path $ARMPath -Directory | Where-Object { $_.GetFileSystemInfos().Count -eq 0 } | Remove-Item -Recurse -Force -Verbose -EA SilentlyContinue

                # Managing specific Acrobat DC files
                &$info "Handling specific Acrobat DC files..."
                &$console
                $specificFiles = @("UserCache64.bin", "DCAPIDiscoveryCacheAcrobat", "IconCacheAcro65536.dat", "IconCacheAcro98304.dat")
                foreach ($file in $specificFiles) {
                    Remove-Item -Path (Join-Path -Path $ProfilePath -ChildPath $file) -Force -Verbose -EA SilentlyContinue
                }

                &$confirm "Adobe cache and specific files cleanup completed."
                &$confirm "Done..."
                &$info "Starting Scan for Google Chrome..."
                ""
            }
        } else {
            &$info "Adobe Acrobat is not installed..."
            &$info "skipping task..."
            &$confirm "Starting next process..."
            &$info "Starting Scan for Google Chrome..."
            ""
        }

        # Clear Google Chrome Cache if installed
        if (Is-Installed "Google Chrome") {
            &$info "Clearing Google Chrome Caches"
            &$info "Starting clearing Google Chrome caches task..."
            &$console

            Import-CSV -Path C:\users\$env:USERNAME\users.csv -Header Name | foreach {
                $ChromePath = "C:\Users\$($_.Name)\AppData\Local\Google\Chrome\User Data\Default"

                Remove-Item -Path (Join-Path -Path $ChromePath -ChildPath "Cache\*") -Recurse -Force -EA SilentlyContinue -Verbose
                Remove-Item -Path (Join-Path -Path $ChromePath -ChildPath "Cache2\entries\*") -Recurse -Force -EA SilentlyContinue -Verbose
                Remove-Item -Path (Join-Path -Path $ChromePath -ChildPath "Cookies\*") -Recurse -Force -EA SilentlyContinue -Verbose
                Remove-Item -Path (Join-Path -Path $ChromePath -ChildPath "Media Cache\*") -Recurse -Force -EA SilentlyContinue -Verbose
                Remove-Item -Path (Join-Path -Path $ChromePath -ChildPath "Cookies-Journal\*") -Recurse -Force -EA SilentlyContinue -Verbose
                Remove-Item -Path (Join-Path -Path $ChromePath -ChildPath "ChromeDWriteFontCache\*") -Recurse -Force -EA SilentlyContinue -Verbose
            }

            &$info "Clearing Google Chrome caches completed."
            &$confirm "Done..."
            &$info "Starting Scan for Windows Cache..."
            &$break
        } else {
            &$info "Google Chrome is not installed."
            &$info "skipping task..."
            &$confirm "Starting next process..."
            &$confirm "Starting Scan for Windows System Cache..."
        }

        # Clear temporary Files

        &$info "Cleaning up in local Windows"
        &$info "Running local system Cache Cleanup Task..."
        &$console
        Import-CSV -Path C:\users\$env:USERNAME\users.csv | foreach {
            Remove-Item -path "C:\Windows\Temp\*" -Recurse -Force -EA SilentlyContinue -Verbose
            Remove-Item -path "C:\Windows\prefetch\*" -Recurse -Force -EA SilentlyContinue -Verbose
            Remove-Item -path "C:\Users\$($_.Name)\AppData\Local\Microsoft\Windows\Temporary Internet Files\*" -Recurse -Force -EA SilentlyContinue -Verbose
            Remove-Item -path "C:\Users\$($_.Name)\AppData\Local\Microsoft\Windows\Caches\*" -Recurse -Force -EA SilentlyContinue -Verbose
            Remove-Item -path "C:\Users\$($_.Name)\AppData\Local\Microsoft\Windows\ActionCenterCache\*" -Recurse -Force -EA SilentlyContinue -Verbose
            Remove-Item -path "C:\Users\$($_.Name)\AppData\Local\Microsoft\Windows\Caches\*" -Recurse -Force -EA SilentlyContinue -Verbose
            Remove-Item -path "C:\Users\$($_.Name)\AppData\Local\Microsoft\Windows\Caches\*" -Recurse -Force -EA SilentlyContinue -Verbose
            Remove-Item -path "C:\Users\$($_.Name)\AppData\Local\Microsoft\Windows\WER\*" -Recurse -Force -EA SilentlyContinue -Verbose
            Remove-Item -path "C:\Users\$($_.Name)\AppData\Local\Temp\*" -Recurse -Force -EA SilentlyContinue -Verbose
            Remove-Item -path "C:\Users\$($_.Name)\AppData\Local\Microsoft\Edge\User Data\Default\Code Cache\*" -Recurse -Force -EA SilentlyContinue -Verbose
            Remove-Item -path "C:\Users\$($_.Name)\AppData\Local\Microsoft\Edge\User Data\ShaderCache\*" -Recurse -Force -EA SilentlyContinue -Verbose
            Remove-Item -path "C:\Users\$($_.Name)\Microsoft\Edge\User Data\Default\Cache\*" -Recurse -Force -EA SilentlyContinue -Verbose

            Remove-Item -path "C:\`$recycle.bin\*" -Recurse -Force -EA SilentlyContinue -Verbose
            &$confirm "Done..."
            &$info "Starting next process..."
            ""
        }
    }

    $returnToMenu = Read-Host "Press 'Y' to return to the main menu, or any other key to exit."
    if ($returnToMenu -eq 'Y' -or $returnToMenu -eq 'y') {
        Select-Option
    } else {
        &$confirm "Exiting..."
    }
}

function PerformDiskCleanup {
    &$confirm "Opening disk cleanup..."
    &$section "SECTION 5: Disk Cleanup"

    # Clearing any previous CleanMgr.exe automation settings to ensure a clean state
    &$info "Clearing previous automation settings..."
    &$console
    try {
        Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\*' -Name StateFlags0001 -ErrorAction SilentlyContinue -Verbose |
        Remove-ItemProperty -Name StateFlags0001 -ErrorAction SilentlyContinue -Verbose
    } catch {
        &$logError "Error clearing automation settings: $_"
    }

    # Enabling Update Cleanup, traditionally automated in Windows 10 and beyond, ensures updates are cleaned on Windows 11
    &$info "Enabling Update Cleanup. Automatically managed in Windows 10 and set manually for assurance in Windows 11..."
    &$console
    try {
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Update Cleanup' -Name StateFlags0001 -Value 2 -PropertyType DWord -ErrorAction Stop -Verbose
    } catch {
        &$logError "Error setting Update Cleanup: $_"
    }

    # Enabling Temporary Files Cleanup to ensure temporary files are managed correctly
    &$info "Enabling Temporary Files Cleanup..."
    &$console
    try {
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Files' -Name StateFlags0001 -Value 2 -PropertyType DWord -ErrorAction Stop -Verbose
    } catch {
        &$logError "Error setting Temporary Files Cleanup: $_"
    }

    # Starting the CleanMgr.exe process to run cleanup tasks
    &$info "Starting Disk Cleanup to perform cleanup tasks..."
    &$console
    try {
        Start-Process -FilePath CleanMgr.exe -ArgumentList '/sagerun:1' -WindowStyle Hidden -Wait
        # Wait for all associated CleanMgr processes to complete
        &$info "Waiting for Disk Cleanup process to complete..."
        Get-Process -Name cleanmgr -ErrorAction SilentlyContinue -Verbose | Wait-Process
        &$confirm "Disk Cleanup process Done..."
    } catch {
        &$logError "Error starting or waiting for CleanMgr.exe: $_"
    }

    # Remove automation flags after completion
    try {
        &$console
        Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\*' -Name StateFlags0001 -ErrorAction SilentlyContinue -Verbose |
        Remove-ItemProperty -Name StateFlags0001 -ErrorAction SilentlyContinue -Verbose
        &$confirm "Disk Cleanup automation settings have been cleared..."
    } catch {
        &$logError "Error clearing automation settings post-cleanup: $_"
    }

    &$confirm "Disk Cleanup task completed."

    $returnToMenu = Read-Host "Press 'Y' to return to the main menu, or any other key to exit."
    if ($returnToMenu -eq 'Y' -or $returnToMenu -eq 'y') {
        Select-Option
    } else {
        &$confirm "Exiting..."
    }
}

function RepairOSImage {
    Clear-Host
    &$section "SECTION 6: Repair OS-Image"

    &$info "Starting OS-Image repair task..."
    Write-Host -ForegroundColor Yellow "Checking and Repairing OS-Image..."
    # Run DISM to check and restore system health
    try {
        $dismResult = DISM /Online /Cleanup-Image /Restore-health
        if ($LASTEXITCODE -ne 0) {
            throw "DISM failed with exit code $LASTEXITCODE"
        }
        &$confirm "OS-Image repair task completed successfully."
    } catch {
        &$logError "An error occurred during DISM operation: $_"
    }

    $returnToMenu = Read-Host "Press 'Y' to return to the main menu, or any other key to exit."
    if ($returnToMenu -eq 'Y' -or $returnToMenu -eq 'y') {
        Select-Option
    } else {
        &$confirm "Exiting..."
    }
}

function OptimizeDisks {
    Clear-Host
    &$section "SECTION 7: Disk Defragmentation, Optimization, and TRIM for SSDs"

    &$info "Collecting Disk type Information..."
    $disks = Get-PhysicalDisk | Select-Object DeviceID, MediaType

    foreach ($disk in $disks) {
        &$info "Checking if disk is HDD or SSD..."

        if ($disk.MediaType -eq 'HDD') {
            &$info "Disk $($disk.DeviceID) is an HDD. Initiating defragmentation process..."
            $volumes = Get-WmiObject -Class Win32_Volume | Where-Object { $_.DriveType -eq 3 }

            foreach ($volume in $volumes) {
                if ($volume.DriveLetter -ne $null) {
                    &$info "Analyzing and defragmenting volume: $($volume.Caption)..."
                    $analysis = $volume.DefragAnalysis()
                    if ($analysis.DefragAnalysis) {
                        &$console "Fragmentation Level: $($analysis.DefragAnalysis.TotalPercentFragmentation)%"
                    }

                    $defragResult = $volume.Defrag($true)
                    if ($defragResult.ReturnValue -eq 0) {
                        &$confirm "Defragmentation successful on volume: $($volume.Caption)"
                    } else {
                        &$logError "Defragmentation failed with code: $($defragResult.ReturnValue) on volume: $($volume.Caption)"
                    }
                }
            }
        } elseif ($disk.MediaType -eq 'SSD') {
            &$info "Disk $($disk.DeviceID) is an SSD. Initiating TRIM command..."
            $volumes = Get-WmiObject -Class Win32_Volume | Where-Object { $_.DriveType -eq 3 }

            foreach ($volume in $volumes) {
                if ($volume.DriveLetter -ne $null) {
                    &$info "Performing TRIM on volume: $($volume.Caption)..."
                    Optimize-Volume -DriveLetter $volume.DriveLetter -ReTrim -Verbose
                }
            }
        } else {
            &$info "Disk $($disk.DeviceID) is neither HDD nor SSD or type is unknown. No specific action taken."
        }
    }

    $returnToMenu = Read-Host "Press 'Y' to return to the main menu, or any other key to exit."
    if ($returnToMenu -eq 'Y' -or $returnToMenu -eq 'y') {
        Select-Option
    } else {
        &$confirm "Exiting..."
    }
}

function FlushDNSCache {
    &$section "SECTION 8: Clearing DNS Client Cache"

    &$info "Starting DNS Client cache clean up task..."
    &$info "Flushing DNS..."
    # Flushing DNS
    Clear-DnsClientCache 
    &$confirm "DNS Flush task Done..."

    $returnToMenu = Read-Host "Press 'Y' to return to the main menu, or any other key to exit."
    if ($returnToMenu -eq 'Y' -or $returnToMenu -eq 'y') {
        Select-Option
    } else {
        &$confirm "Exiting..."
    }
}

function Run-ChkdskAndRestart {
    &$section "SECTION 9: Disk Check and Restart"
    # Function to run chkdsk and handle the prompt automatically, then restart
    &$info "Scheduling disk check and preparing to restart..."

    # Schedule chkdsk to run with confirmation 'Y' automatically piped into it
    echo Y | chkdsk C: /v /f /r

    # Wait for a moment before initiating a restart to ensure command processes
    Start-Sleep -Seconds 5

    # Using PowerShell to shutdown and restart the computer immediately
    &$info "Restarting the computer now..."
    shutdown /r /t 0
}

# Call the menu function to start the script
Select-Option
