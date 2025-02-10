#$ip_add = Read-Host "Enter the IP addresses separated by commas : "
$ip_add = @("78.109.200.147","59.173.135.46","98.51.132.203") 


$VT_api = "" #insert your api here
$VT_headers = @{"accept"="Application/JSON"; "x-apikey"="$VT_api"}



foreach ($address in $ip_add) {

    $VT_path = "https://www.virustotal.com/api/v3/ip_addresses/$address"
    $VT_response = Invoke-WebRequest -Method Get -Uri $VT_path -Headers $VT_headers |ConvertFrom-Json
    $AVs = @()
    $total_flags = $VT_response.data.attributes.last_analysis_stats.malicious
    if ($total_flags) {
        
        foreach ($property in $VT_response.data.attributes.last_analysis_results.PSobject.Properties) {
            
            if ($property.Value.category -eq "malicious") {
                $AVs += $property.Name
            }
        }

        Write-Host "$address is flagged Malicious by $total_flags scanners: $($AVs -join ", ")"

    }
}