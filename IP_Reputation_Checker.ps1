# List of IP addresses to be checked
$ip_addresses = @("", "", "")

# List of API keys (rotate when one is depleted)
$VT_api = @("",
            "") 

# Initialize API index to start with the first API key
$api_index = 0

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
        Write-Host "$ip_address is flagged Malicious by $total_flags scanners: $($AVs -join ', ')"
    }

    
}

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
