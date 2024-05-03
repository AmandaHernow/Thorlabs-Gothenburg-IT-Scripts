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
&$confirm "Developer: Amanda Hernow, Thorlabs Sweden AB - 22-042024"
&$confirm "Version: 2.0"
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
v.2.0: Developed switch menu for dynamic script interactions."
&$info "COMING_SOON:
1. Development of a switch menu for Program picker to clean common program files only
2. Deciding on execution methods: scheduled tasks, autofire HID devices, or through PSexec remotely.
3. Explore the possibility of dynamically finding cache paths from program installation paths for targeted cleaning.
4. Implement robust error handling to manage and log exceptions and errors effectively."

# Menu and option selection functionality
function Show-Menu {
    param ([string]$Title = 'Computer Clean Up Menu')
    Clear-Host
    & $section $Title
    & $confirm "1: Deep Cache Clearing - Clears system and application caches."
    & $confirm "2: User Session Management - Logs off all users except the current. (Recommended)"
    & $confirm "3: Common Program Cache Cleaning - Clears cache from browsers and more."
    & $confirm "4: Disk Cleanup - Cleans temporary files and updates."
    & $confirm "5: OS Image Repair - Runs DISM and SFC to repair system files."
    & $confirm "6: Disk Optimization - Optimizes HDDs and SSDs."
    & $confirm "7: DNS Cache Flush - Clears DNS cache to resolve network issues."
    & $confirm "8: Disk Check and Restart - Intensive scan and repair. WARNING: Restarts immediately!"
    & $confirm "Q: Quit - Exit the menu and end the session."
}

function Select-Option {
    Show-Menu
    $userChoice = Read-Host "Select an option by number (or 'Q' to Quit)"
    switch ($userChoice) {
        '1' { DeepCacheClearing }
        '2' { LogOffAllUsersExceptCurrent }
        '3' { ClearCommonProgramCache }
        '4' { PerformDiskCleanup }
        '5' { RepairOSImage }
        '6' { OptimizeDisks }
        '7' { FlushDNSCache }
        '8' { Run-ChkdskAndRestart }
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

# Function placeholders for each option
function DeepCacheClearing {
    &$confirm "Opening Deep Cache Clearing..."
    Clear-Host
    &$section "SECTION 1: Deep Cache Clearing"

    # Initial setup and backup directory check
    $rootPath = "C:\"
    $backupRoot = "C:\cacheBackup"

    # Ensure the backup root directory exists
    try {
        if (-not (Test-Path -Path $backupRoot)) {
            &$info "Creating Backup Folder..."
            New-Item -Path $backupRoot -ItemType Directory -Force -Verbose | Out-Null
            &$confirm "Backup root directory created..."
        } else {
            &$info "Backup root directory already exists..."
        }
    } catch {
        &$logError "Error creating backup root directory: $_"
    }

    $date = Get-Date -Format "yyyyMMddHHmmss"
    $backupDir = Join-Path -Path $backupRoot -ChildPath "cacheBackup_$date"
    $logPath = Join-Path -Path $backupRoot -ChildPath "$($date).log"

    try {
        &$info "Creating Session Backup Log and Folder"
        New-Item -Path $backupDir -ItemType Directory -Force -Verbose | Out-Null
        New-Item -Path $logPath -ItemType File -Force -Verbose | Out-Null
        &$confirm "Backup folder and log file prepared..."
    } catch {
        &$logError "Error preparing folders and log file: $_"
    }

    # Exclusion list for files not to be moved
    $excludedExtensions = @(".config", ".ini", ".db", ".sqlite", ".exe", ".dll", ".dat", ".bin", ".lock", ".log", ".xml", ".json", ".bak", ".tmp", ".old", ".backup", ".ps1", ".sh", ".bat", ".cmd", ".cert", ".pfx", ".key", ".rb", ".py", ".ldf", ".data base")

    # Variables to track number of files moved and their total size
    $filesMoved = 0
    $totalSizeMoved = 0

    # Recursive file processing
    &$info "Scanning for cache directories..."
    $cacheDirs = Get-ChildItem -Path $rootPath -Directory -Recurse -Force -ErrorAction SilentlyContinue -Verbose |
        Where-Object { $_.Name -like "*cache*" -and $_.FullName -notlike "*$backupRoot*" }

    foreach ($dir in $cacheDirs) {
        $files = Get-ChildItem -Path $dir.FullName -File -Recurse -Force -ErrorAction SilentlyContinue -Verbose |
            Where-Object { $ext = [System.IO.Path]::GetExtension($_.Name); $ext -ne "" -and $ext -notin $excludedExtensions }

        foreach ($file in $files) {
            try {
                $relativePath = $file.FullName.Substring($rootPath.Length)
                $destinationFile = Join-Path -Path $backupDir -ChildPath $relativePath
                $destinationDir = Split-Path -Path $destinationFile -Parent
                if (-not (Test-Path -Path $destinationDir)) {
                    New-Item -Path $destinationDir -ItemType Directory -Force -Verbose | Out-Null
                }
                Move-Item -Path $file.FullName -Destination $destinationFile -Force -Verbose
                $fileSize = $file.Length / 1MB
                $totalSizeMoved += $fileSize
                $filesMoved++
                "$($file.FullName) ($("{0:N2}" -f $fileSize) MB) moved to $destinationFile" | Out-File -Append -FilePath $logPath
                "`r`n" | Out-File -Append -FilePath $logPath
            } catch {
                "$file.FullName failed to move: $_" | Out-File -Append -FilePath $logPath
                "`r`n" | Out-File -Append -FilePath $logPath
            }
        }
    }

    # Compress and finalize
    &$info "Compressing backup..."
    try {
        $compressedFile = "$backupDir.zip"
        Compress-Archive -Path $backupDir -DestinationPath $compressedFile -Force -Verbose
        Remove-Item -Path $backupDir -Recurse -Force -Verbose

        # Log final stats
        "Total backup size: $("{0:N2}" -f $totalSizeMoved) MB" | Out-File -Append -FilePath $logPath
        "Total number of cache files moved: $filesMoved" | Out-File -Append -FilePath $logPath
        "`r`n" | Out-File -Append -FilePath $logPath

        &$confirm "Backup and compression complete. Total backup size: $("{0:N2}" -f $totalSizeMoved) MB, Files Moved: $filesMoved."
    } catch {
        &$logError "Error compressing backup or calculating size: $_"
    }

    # Ask user if they want to return to the main menu
    $returnToMenu = Read-Host "Press 'Y' to return to the main menu, or any other key to exit."
    if ($returnToMenu -eq 'Y' -or $returnToMenu -eq 'y') {
        Select-Option
    } else {
        &$confirm "Exiting..."
    }
    ""
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
    ""
}

function ClearCommonProgramCache {

    &$section "SECTION 3: Clear Cache From Common Windows Programs"

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

        if(Is-Installed Adobe Reader){
        # Clear Adobe Acrobat 

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

        # Clear emporary Files

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
    }
}

function PerformDiskCleanup {
    &$confirm "Opening disk cleanup..."
    &$section "SECTION 4: Disk Cleanup"

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
    ""
}

function RepairOSImage {
    Clear-Host
    &$section "SECTION 5: Repair OS-Image"

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
}

function OptimizeDisks {
    Clear-Host
    &$section "SECTION 6: Disk Defragmentation, Optimization, and TRIM for SSDs"

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
}


function FlushDNSCache {
    &$section "SECTION 7: Clearing DNS Client Cache"

    &$info "Starting DNS Client cache clean up task..."
    &$info "Flushing DNS..."
    # Flushing DNS
    Clear-DnsClientCache 
    &$confirm "DNS Flush task Done..."
}


function Run-ChkdskAndRestart {
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
