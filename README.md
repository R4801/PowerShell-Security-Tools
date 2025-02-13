# **IOCAnalyzer** 🚀

IOCAnalyzer is a PowerShell-based tool that checks various Indicators of Compromise (IOCs) such as IP addresses, domains, and file hashes against VirusTotal's threat intelligence database. It helps security analysts and incident responders automate IOC lookups efficiently.

## **Features**

- 🔍 Scan hashes and IP addresses using VirusTotal API.
- 🔄 Automatic API key rotation to handle rate limits.
- 📝 Ability to manually define artifacts for batch analysis.

## **Installation** 
Clone the repository to your local machine:
```powershell
 git clone https://github.com/R4801/PowerShell-Security-Tools.git
```
## **Usage** 💡📜⚙️

1. 📂 Open PowerShell and navigate to the script directory:
```powershell
cd PowerShell-Security-Tools
```
2. 🏃 Run the script interactively:
```powershell
.\IOCAnalyzer.ps1 -artifacts "<IOC1>", "<IOC2>" -api "<Your_VirusTotal_API_Key>"
```
3. ⚙️ To use this script in automatic mode:
- 📝 Open IOCAnalyzer.ps1. 
- ✏️ Manually add artifacts in the $artifacts variable.
- 🔑 Add API keys in the $VT_api variable.
- 💾 Save and execute the script.
```powershell
# Define the artifacts (IOCs) to be scanned and the VirusTotal API key for lookup
param (
    [string[]]$artifacts = @(),  #<<<---- Enter your IOCs seperated by commas here. Example @("hash","hash","IPAddress""IPAddress")
    [string]$api = ""  # Default API key; Add your API here or in the $VT_api list for multiple API
)

# List of VirusTotal API keys (used in rotation when rate limits are reached)
# Add your API keys here if they are not provided as a runtime parameter.
[string[]]$VT_api = @()    #<<<---- Enter your APIs seperated by commas here. Example: @("api1")
```
## **Requirements** 📌🖥️

- 🖥️ PowerShell 5.1 or later.
- 🔐 A valid VirusTotal API key.

## **Roadmap** 📅🔄

- ✅ Support for Hash and IP address scanning.

- ⏳ Domain scanning support (coming soon).


