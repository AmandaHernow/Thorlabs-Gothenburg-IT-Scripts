# Display Header Information
Write-Host -ForegroundColor Blue "-------------------------------Developed by Amanda Hernow - Thorlabs Sweden AB-------------------------------"
Write-Host -ForegroundColor Green "Use: PowerShell script for querying and saving Exchange Online user photos."
Write-Host -ForegroundColor Green "Program Description: Queries Exchange Online to retrieve user photos and save them locally. Includes error handling and prompts for necessary permissions."
Write-Host -ForegroundColor Green "Developer: Amanda Hernow, Thorlabs Sweden AB"
Write-Host -ForegroundColor Green "Version: 1.2 - Updated 2024-05-14"
Write-Host -ForegroundColor Blue "-------------------------------PowerShell Script - Retrieve & Save User Photos-------------------------------"

Write-Host -ForegroundColor Green "CHANGE_LOG:
V. 1.1: Added functionality to save the photo files with the username part of the email address.
V. 1.2: Added prompt to make sure user have activated Exchange Admin rights."

# Prompt user to confirm they have activated the necessary role
Write-Host -ForegroundColor Yellow "Have you activated your Exchange Administrator role in Azure PIM? (Y/N)"
$userConfirmation = Read-Host
if ($userConfirmation.ToUpper() -ne 'Y') {
    Write-Host -ForegroundColor Red "Script execution stopped. Please activate your Exchange Administrator role and try again."
    return
}

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
        $usernamePart = $UserEmail.Split('@')[0] # Extract the part before '@'
        $photo = Get-UserPhoto -Identity $UserEmail -ErrorAction Stop
        if ($photo.PictureData) {
            $fileExtension = switch ($photo.ContentType) {
                "image/jpeg" { "jpg" }
                "image/png"  { "png" }
                Default { "jpg" } # Default to jpg if another format is not handled
            }
            $filePath = Join-Path -Path $FolderPath -ChildPath "$usernamePart.$fileExtension"
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
