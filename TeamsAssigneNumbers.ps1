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
Write-Host -ForegroundColor Blue "-------------------------------Developed by Amanda Hernow - Thorlabs Sweden AB-------------------------------"
&$confirm "Use: PowerShell script for querying Microsoft Teams to collect and assign phone numbers."
&$confirm "Program Description: Queries Microsoft Teams for assigned numbers and allows number assignment to user accounts. Includes error handling and verbose output."
&$confirm "Developer: Amanda Hernow, Thorlabs Sweden AB"
&$confirm "Version: 2.4 - Updated 2024-05-12"
Write-Host -ForegroundColor Blue "-------------------------------PowerShell Script - Get & Assign Teams Numbers-------------------------------"
&$confirm "CHANGE_LOG:
V. 2.0: Script based on initial concepts by Andrew Morpeth, UC Geek.
V. 2.1: Added automatic check and installation of Microsoft Teams PowerShell module.
V. 2.2: Introduced user choice for output formats (CSV, Excel, or both).
V. 2.3: Added functionality to assign phone numbers to users and enhanced error handling.
V. 2.4: Added functionality to remove phone numbers from teams users."

# Script functionality here
&$section "RUN INSTRUCTIONS"
&$info "The script checks and installs the necessary PowerShell modules. Execute with .\\TeamsAssignNumbers.ps1"
&$info "Disclaimer: This script is provided 'as-is' without warranty. No responsibility is assumed by the author for any damage or data loss that may occur from its use. Always test before deploying in a production environment."

# Display Output Options Menu
&$section "Main Menu"
&$confirm "Select an output option by number or press 'Q' to Quit:"
&$confirm "1: Export assigned numbers to CSV"
&$confirm "2: Export assigned numbers to Excel"
&$confirm "3: Export to both CSV and Excel"
&$confirm "4: Assign a phone number to a Teams user account"
&$confirm "5: Remove a phone number from a Teams user account"
Write-Host -ForegroundColor Green "Enter your choice: " -NoNewline
$OutputChoice = Read-Host

# Immediate exit if 'Q' or 'q' is selected
if ($OutputChoice -eq 'Q' -or $OutputChoice -eq 'q') {
    &$confirm "Operation cancelled. Exiting script."
    exit
}

# Check and install Microsoft Teams PowerShell module if necessary
function TeamsPowerMode {
    try {
        $module = Get-Module -Name "MicrosoftTeams" -ListAvailable
        if (-not $module) {
            &$info "Microsoft Teams PowerShell module is not installed. Attempting to install..."
            Install-Module -Name MicrosoftTeams -RequiredVersion 2.3.1 -Force -AllowClobber -Verbose | ForEach-Object { &$console $_ }
            Import-Module -Name MicrosoftTeams
            &$confirm "Microsoft Teams PowerShell module installed successfully."
        } else {
            &$confirm "Microsoft Teams PowerShell module is already installed."
        }
        Connect-MicrosoftTeams -Verbose | ForEach-Object { &$console $_ }
    } catch {
        &$logError "Failed to install or connect to the Microsoft Teams PowerShell module. Please check your permissions, internet connection, and credentials."
        exit
    }
}

# Check and install ImportExcel module if necessary
function ExcelPowerMode {
    try {
        $excelModule = Get-Module -Name "ImportExcel" -ListAvailable
        if (-not $excelModule) {
            &$info "ImportExcel module is not installed. Attempting to install..."
            Install-Module -Name ImportExcel -Force -Verbose | ForEach-Object { &$console $_ }
            &$confirm "ImportExcel module installed successfully."
        } else {
            &$confirm "ImportExcel module is already installed."
        }
    } catch {
        &$logError "Failed to install the ImportExcel module. Please check your permissions and internet connection."
        exit
    }
}

function TeamsNumberTable {
    $FileName = "TeamsAssignedNumbers_" + (Get-Date -Format s).replace(":", "-")
    $FilePath = "C:\\Temp\\$FileName"

    $Array1 = @()
    $Regex1 = '^(?:tel:)?(?:\+)?(\d+)(?:;ext=(\d+))?(?:;([\w-]+))?$'

    $UsersLineURI = Get-CsOnlineUser -Filter {LineURI -ne $Null}
    if ($UsersLineURI -ne $null) {
        foreach ($item in $UsersLineURI) {
            if ($item.LineURI -match $Regex1) {
                $myObject1 = New-Object PSObject -Property @{
                    LineURI = $item.LineURI
                    DDI = $Matches[1]
                    Ext = $Matches[2]
                    DisplayName = $item.DisplayName
                    FirstName = $item.FirstName
                    LastName = $item.LastName
                    Type = "User"
                }
                $Array1 += $myObject1
            }
        }
    }

    $OnlineApplicationInstanceLineURI = Get-CsOnlineApplicationInstance | where {$_.PhoneNumber -ne $Null}
    if ($OnlineApplicationInstanceLineURI -ne $null) {
        foreach ($item in $OnlineApplicationInstanceLineURI) {
            if ($item.PhoneNumber -match $Regex1) {
                $type = switch ($item.ApplicationId) {
                    "ce933385-9390-45d1-9512-c8d228074e07" { "Auto Attendant Resource Account" }
                    "11cd3e2e-fccb-42ad-ad00-878b93575e07" { "Call Queue Resource Account" }
                    default { "Unknown Resource Account" }
                }
                $myObject1 = New-Object PSObject -Property @{
                    LineURI = $item.PhoneNumber
                    DDI = $Matches[1]
                    Ext = $Matches[2]
                    DisplayName = $item.DisplayName
                    Type = $type
                }
                $Array1 += $myObject1
            }
        }
    }

    return $Array1  # Ensure this data is returned
}


function CheckAdmin {
&$confirm "Please ensure you are assigned as a Teams admin in Azure."
$adminConfirm = Read-Host "Press 'Y' to continue if you have confirmed your admin roles in Azure is activated (press any other key to exit)"
    if ($adminConfirm -ne 'Y') {
        &$logError "Admin confirmation failed, exiting..."
        exit
    }
}

# Function to assign phone number
function Assign-PhoneNumber {
    &$section "Assign Phone Number to Teams User"
    try {
        CheckAdmin
        TeamsPowerMode
        &$console "Connected to Microsoft Teams."

        # User input for assignment details
        $identity = Read-Host "Enter the user's email (e.g., user@domain.com): "
        $phoneNumber = Read-Host "Enter the phone number to assign to the Teams user account: "
        $policyName = Read-Host "Enter the voice routing policy name (e.g., Masergy_EU): "

        # Assign the phone number and policy
        Set-CsPhoneNumberAssignment -Identity $identity -PhoneNumber $phoneNumber -PhoneNumberType DirectRouting
        Set-CsPhoneNumberAssignment -Identity $identity -EnterpriseVoiceEnabled $true
        Grant-CsOnlineVoiceRoutingPolicy -Identity $identity -PolicyName $policyName

        &$confirm "Phone number $phoneNumber has been successfully assigned to $identity."
    } catch {
        &$logError "An error occurred: $_"
    }
}

function Remove-PhoneNumber {
    &$section "Remove Phone Number from Teams User"
    CheckAdmin  # This ensures only admins are executing the function
    TeamsPowerMode  # Ensure Microsoft Teams PowerShell is loaded and connected

    try {
        $identity = Read-Host "Enter the user's email from which to remove the phone number (e.g., user@domain.com): "
        Remove-CsPhoneNumberAssignment -Identity $identity -RemoveAll -Verbose | ForEach-Object { &$console $_ }
        &$confirm "All phone numbers have been successfully removed from $identity."
    } catch {
        &$logError "Failed to remove phone number: $_"
    }
}

# Settings for output handling based on user choice
switch ($OutputChoice) {
    '1' {
        TeamsPowerMode
        $Array1 = TeamsNumberTable
        $CSVPath = $FilePath + ".csv"
        $Array1 | Export-Csv -Path $CSVPath -NoTypeInformation
        &$confirm "CSV file has been saved to $CSVPath."
    }
    '2' {
        TeamsPowerMode
        ExcelPowerMode
        $Array1 = TeamsNumberTable
        $ExcelPath = $FilePath + ".xlsx"
        $Array1 | Export-Excel -Path $ExcelPath -AutoSize -TableName "TeamsNumbers" -Show
        &$confirm "Excel file has been saved to $ExcelPath."
    }
    '3' {
        TeamsPowerMode
        ExcelPowerMode
        $Array1 = TeamsNumberTable
        $CSVPath = $FilePath + ".csv"
        $ExcelPath = $FilePath + ".xlsx"
        $Array1 | Export-Csv -Path $CSVPath -NoTypeInformation
        $Array1 | Export-Excel -Path $ExcelPath -AutoSize -TableName "TeamsNumbers" -Show
        &$confirm "Both CSV and Excel files have been saved to $FilePath."
    }
    '4' {
        Assign-PhoneNumber
    }
    '5' {
        Remove-PhoneNumber
    }
    default {
        &$logError "Invalid choice. Please restart the script and select a valid option."
        exit
    }
}
