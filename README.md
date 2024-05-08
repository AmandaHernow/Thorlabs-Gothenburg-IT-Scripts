Thorlabs-Gothenburg-IT-Scripts

Welcome to the Thorlabs Gothenburg IT Scripts repository. This repository houses a collection of PowerShell scripts designed to facilitate IT management tasks related to software and system maintenance.

###This repository contains two PowerShell scripts:

1. **TeamsAssignNumbers.ps1** - Retrieves and allows assignment of phone numbers from Microsoft Teams. It offers options for exporting these numbers to CSV or Excel formats and assigning numbers to user accounts or removing them. The script includes robust error handling and verbose output for effective monitoring.

2. **Cache_CookieClearer.ps1** - Automates the cleaning of disk space, cache, and cookies on all user accounts on the targeted PC. This script is designed for execution on production PCs via PSExec, scheduled tasks, or autofire HID devices.

## Usage Instructions and Precautions

Both scripts are experimental and should be used with caution. They are intended for IT professionals familiar with automated system modifications.

## Prerequisites

Before running these scripts, ensure that the Microsoft Teams PowerShell module is installed. The scripts check for the module and attempt to install it if it is not present. However, for smooth execution:

- **Run PowerShell as an administrator** to avoid permission issues.
- **Set the execution policy appropriately** if you encounter any policy-related errors. This can be done by running:
  ```powershell
  Set-ExecutionPolicy Bypass -Scope Process -Force
```

###Installation
Clone this repository to your local machine using Git:
```powershell
  git clone https://github.com/yourgithubprofile/Thorlabs-Gothenburg-IT-Scripts.git
```

###Usage
Running TeamsAssignNumbers.ps1
Navigate to the directory containing the script and run:
  ```powershell
  .\TeamsAssignNumbers.ps1
```

Choose the desired output format or the option to assign phone numbers via the interactive menu.
##OBS! You must PIM: Teams Administrator in Azure before assigning number to teams account.

Running Cache_CookieClearer.ps1
Ensure you have administrative rights. Navigate to the script's directory and execute:
  ```powershell
  .\Cache_CookieClearer.ps1
```

Follow the on-screen prompts to select specific cleaning tasks.

##Contributing
Contributions are welcome. Please fork the repository and submit pull requests with any enhancements, bug fixes, or improvements.

##Contact
For further information or feedback, please contact amanda.hernow@thorlabs.com at Thorlabs Sweden AB.