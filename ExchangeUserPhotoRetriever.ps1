# Display Header Information
Write-Host -ForegroundColor Blue "-------------------------------Developed by Amanda Hernow - Thorlabs Sweden AB-------------------------------"
Write-Host -ForegroundColor Green "Use: PowerShell script for querying and saving Exchange Online user photos."
Write-Host -ForegroundColor Green "Program Description: Queries Exchange Online to retrieve user photos and save them locally. Includes error handling and prompts for necessary permissions."
Write-Host -ForegroundColor Green "Developer: Amanda Hernow, Thorlabs Sweden AB"
Write-Host -ForegroundColor Green "Version: 1.0 - Updated 2024-05-14"
Write-Host -ForegroundColor Blue "-------------------------------PowerShell Script - Retrieve & Save User Photos-------------------------------"

# Function to check and create a specific folder
function Ensure-FolderExists {
    $folderPath = "C:\userPhotos"
    if (-not (Test-Path -Path $folderPath)) {
        New-Item -ItemType Directory -Path $folderPath | Out-Null
    }
    return $folderPath
}

# Function to install and import Exchange Online Management Module
function InstallAndImport-ExchangeOnlineManagement {
    [CmdletBinding()]
    param()

    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        Install-Module -Name ExchangeOnlineManagement -Force -AllowClobber
    }
    Import-Module ExchangeOnlineManagement -DisableNameChecking
}

# Connect to Exchange Online with necessary credentials
function Connect-ExchangeOnline {
    [CmdletBinding()]
    param()
    $UserCredential = Get-Credential
    Connect-ExchangeOnline -Credential $UserCredential -ShowProgress $true
}

# Retrieve and save the user photo
function Get-AndSaveUserPhoto {
    param (
        [string]$UserEmail,
        [string]$FolderPath
    )
    try {
        $photo = Get-UserPhoto -Identity $UserEmail -ErrorAction Stop
        if ($photo.PictureData) {
            $filePath = Join-Path -Path $FolderPath -ChildPath "$UserEmail.jpg"
            $photo.PictureData | Set-Content -Path $filePath -Encoding Byte
            Write-Host -ForegroundColor Green "Photo successfully downloaded to $filePath"
        } else {
            Write-Host -ForegroundColor Yellow "No photo available for user $UserEmail"
        }
    } catch {
        Write-Host -ForegroundColor Red "An error occurred: $_"
    }
}

# Main script execution
InstallAndImport-ExchangeOnlineManagement
Connect-ExchangeOnline
$folderPath = Ensure-FolderExists

do {
    $userEmails = Read-Host "Enter the email addresses of the users whose photos you want to download, separated by commas, or type 'Q' to quit: "
    if ($userEmails.ToUpper() -eq 'Q') {
        Write-Host -ForegroundColor Green "Exiting script..."
        break
    }

    $emailArray = $userEmails -split ','
    foreach ($email in $emailArray) {
        Get-AndSaveUserPhoto -UserEmail $email.Trim() -FolderPath $folderPath
    }
}
while ($true)
