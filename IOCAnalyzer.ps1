# Define the artifacts (IOCs) to be scanned and the VirusTotal API key for lookup
param (
    [string[]]$artifacts = @(),  # Default artifacts
    [string]$api = ""  # Default API key
)

# List of VirusTotal API keys (used in rotation when rate limits are reached)
# Add your API keys here if they are not provided as a runtime parameter.
[string[]]$VT_api = @() 

if ($api) {
    $VT_api+=$api
}

# Lists of artifacts (IOCs) to be analyzed.
# Add values below to run the script without passing parameters at runtime.
$ip_addresses = @()
$hashes = @()
$domains = @()
$unknownArtifacts = @()

# Process artifacts provided as script parameters and categorize them into relevant lists
if ($artifacts){
    
    foreach ($artifact in $artifacts) {
        
        if ($artifact -match "^(?:\d{1,3}\.){3}\d{1,3}$") {
            $ip_addresses += $artifact
        }
        elseif ($artifact -match "^(?=.{1,253}$)([a-zA-Z0-9][-a-zA-Z0-9]{0,62}\.)+[a-zA-Z]{2,63}$") {
            $domains += $artifact
        }
        elseif ($artifact -match "^[a-fA-F0-9]{32}$" -or $artifact -match "^[a-fA-F0-9]{40}$" -or $artifact -match "^[a-fA-F0-9]{64}$") {
            $hashes += $artifact
        }
        else {
            $unknownArtifacts += $artifact
        }
    }
}


# Initialize API index to start with the first API key
$api_index = 0


#------------------------
#Initiating Functions
#------------------------

# Function to check IP address using VirusTotal API
function CheckAddress {
    param (
        $ip_address,  # IP to check
        $header      # API headers
    )

    # Construct VirusTotal API endpoint
    $VT_path = "https://www.virustotal.com/api/v3/ip_addresses/$ip_address"

    # Send request to VirusTotal API and parse response
    $VT_response = Invoke-WebRequest -Method Get -Uri $VT_path -Headers $header | ConvertFrom-Json

    # Extract total malicious detections
    $total_flags = $VT_response.data.attributes.last_analysis_stats.malicious

    # If malicious detections are found, list the detecting vendors
    if ($total_flags) {
        $AVs = @()
        foreach ($property in $VT_response.data.attributes.last_analysis_results.PSobject.Properties) {
            if ($property.Value.category -eq "malicious") {
                $AVs += $property.Name
            }
        }

        # Display results
        Write-Host "`n$ip_address is flagged Malicious by $total_flags scanners: $($AVs -join ', ') `n`n"
    }else{Write-Host "$ip_address was not flagged by any Security Vendor`n`n"}

    
}

# Function to check File Hash using VirusTotal API
function CheckHashes {
    param (
        $hash,  # IP to check
        $header      # API headers
    )
    # Construct VirusTotal API endpoint
    $VT_path = "https://www.virustotal.com/api/v3/files/$hash"

    # Send request to VirusTotal API and parse response
    $VT_response = Invoke-WebRequest -Method Get -Uri $VT_path -Headers $header | ConvertFrom-Json    

    # Extract total malicious detections
    $total_flags = $VT_response.data.attributes.last_analysis_stats.malicious

    # If malicious detections are found, list the detecting vendors
    if ($total_flags) {
        $magic_description = $VT_response.data.attributes.magic
        $extension= $VT_response.data.attributes.type_extension
        $extension_description= $VT_response.data.attributes.type_description

        Write-Host "-------------------------------------------`n**$hash**`n-------------------------------------------"

        Write-Host "Flagged malicious by $total_flags Security Vendors"
        if ($extension) {
            Write-Host "File extension: $extension ($extension_description)"
        }
        if ($magic_description) {
            Write-Host "Magic Number details: $magic_description`n`n"
        }
    }else{Write-Host "$hash was not flagged by any Security Vendor`n`n"}
}

#------------------------
#Functions END
#------------------------

#++++++++++++++++++++++++++++++++

#------------------------
#Analyzing IP Addresses
#------------------------

if ($ip_addresses) {
    # Loop through each IP address
foreach ($ip_address in $ip_addresses) {
    try {
        # Set API headers for the current API key
        $VT_headers = @{"accept"="Application/JSON"; "x-apikey"="$($VT_api[$api_index])"}
        # Check the IP address
        CheckAddress $ip_address $VT_headers

    } catch {
        Write-Host "API Key $($VT_api[$api_index]) exhausted. Switching to next API key..."
        
        # Move to the next API key
        $api_index++

        # If all API keys are exhausted, stop execution
        if ($api_index -ge $VT_api.Count) {
            Write-Host "All API keys have been exhausted. Stopping script."
            break
        }

        # Set new API headers with the next API key
        $VT_headers = @{"accept"="Application/JSON"; "x-apikey"="$($VT_api[$api_index])"}

        # Retry checking the current IP with the new API key
        CheckAddress $ip_address $VT_headers
    }
}
}


#------------------------
#Analyzing Hashes
#------------------------

if ($hashes) {
    # Loop through each hash
foreach ($hash in $hashes) {

    try {
        # Set API headers for the current API key
        $VT_headers = @{"accept"="Application/JSON"; "x-apikey"="$($VT_api[$api_index])"}
        # Check the Hash
        CheckHashes $hash $VT_headers
    } catch {
        Write-Host "`nAPI Key $($VT_api[$api_index]) exhausted. Switching to next API key...`n"
        
        # Move to the next API key
        $api_index++

        # If all API keys are exhausted, stop execution
        if ($api_index -ge $VT_api.Count) {
            Write-Host "`nAll API keys have been exhausted. Stopping script.`n"
            break
        }

        # Set new API headers with the next API key
        $VT_headers = @{"accept"="Application/JSON"; "x-apikey"="$($VT_api[$api_index])"}

        # Retry checking the current IP with the new API key
        CheckHashes $hash $VT_headers
    }
} 
}







