# ====================================================
# doh-multi-test.ps1
# ====================================================
#
# Test DoH (DNS-over-HTTPS) GET and POST methods against
# Google, Cloudflare, AdGuard, and Disobey. This version:
#  - Uses a random 16-bit Transaction ID per resolver
#  - Allows specifying any domain (default "example.com")
#  - Prints which domain is being queried, and the exact GET URL
#  - Uses color coding for clarity
#
# Usage:
#   1. Save as doh-multi-test.ps1
#   2. Open PowerShell (no Admin needed)
#   3. If needed, allow local scripts:
#        Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
#   4. cd to the folder containing doh-multi-test.ps1
#   5. Run: .\doh-multi-test.ps1
# ====================================================

# 0) Change this to test a different domain if you like:
$domain = "example.com"

# 1) Build the DNS wire-format question section for $domain:
$qnameList = New-Object System.Collections.Generic.List[Byte]
$labels = $domain.Split(".")
foreach ($label in $labels) {
    $lengthByte = [byte]$label.Length
    $qnameList.Add($lengthByte)
    $bytesLabel = [Text.Encoding]::ASCII.GetBytes($label)
    $qnameList.AddRange($bytesLabel)
}
# null-terminate QNAME
$qnameList.Add(0)

# Append QTYPE = A (0x0001) and QCLASS = IN (0x0001)
$qnameList.Add(0x00)
$qnameList.Add(0x01)
$qnameList.Add(0x00)
$qnameList.Add(0x01)
$qnameBytes = $qnameList.ToArray()

# The “rest” BEFORE QNAME is:
#   Flags = 0x0100, QDCOUNT = 1, ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0
$prefixBytes = [byte[]] (
    0x01, 0x00,   # Flags: standard recursive query
    0x00, 0x01,   # QDCOUNT = 1
    0x00, 0x00,   # ANCOUNT = 0
    0x00, 0x00,   # NSCOUNT = 0
    0x00, 0x00    # ARCOUNT = 0
)

# 2) Providers to test
$providers = @(
    "https://dns.google/dns-query",
    "https://cloudflare-dns.com/dns-query",
    "https://dns.adguard.com/dns-query",
    "https://dns.disobey.net/dns-query"
)

foreach ($provider in $providers) {
    # Generate a fresh random TXID for each resolver
    $rand = Get-Random -Minimum 1 -Maximum 65536
    $txidBytes = [BitConverter]::GetBytes([UInt16] $rand)
    if ([BitConverter]::IsLittleEndian) {
        [Array]::Reverse($txidBytes)
    }

    # Combine TXID + prefix + QNAME into full DNS query bytes
    $queryBytes = New-Object byte[] ($txidBytes.Length + $prefixBytes.Length + $qnameBytes.Length)
    [Array]::Copy($txidBytes,    0, $queryBytes, 0,                            $txidBytes.Length)
    [Array]::Copy($prefixBytes,  0, $queryBytes, $txidBytes.Length,              $prefixBytes.Length)
    [Array]::Copy($qnameBytes,   0, $queryBytes, $txidBytes.Length + $prefixBytes.Length, $qnameBytes.Length)

    # Base64-URL encode for GET
    $normalB64 = [Convert]::ToBase64String($queryBytes)
    $b64url    = $normalB64.Replace("+", "-").Replace("/", "_").TrimEnd("=")

    # Print which domain and which provider
    Write-Host ""
    Write-Host "Querying domain '$domain' against $provider" -ForegroundColor Cyan

    # -------------------------
    # Test GET
    # -------------------------
    Write-Host "GET method" -ForegroundColor Yellow
    # Build GET URL via concatenation
    $getUrl = $provider + "?dns=" + $b64url
    Write-Host "GET URL: $getUrl" -ForegroundColor DarkGray

    try {
        $uriObj = [Uri] $getUrl
        $response = Invoke-WebRequest -Uri $uriObj `
            -Headers @{ "Accept" = "application/dns-message" } `
            -UseBasicParsing

        if ($response -ne $null -and $response.RawContentStream -ne $null) {
            $ms        = New-Object System.IO.MemoryStream
            $response.RawContentStream.CopyTo($ms)
            $respBytes = $ms.ToArray()

            Write-Host "SUCCESS: Received $($respBytes.Length) bytes" -ForegroundColor Green
            $respB64 = [Convert]::ToBase64String($respBytes)
            Write-Host "  DNS response (Base64): $respB64" -ForegroundColor Gray
        }
        else {
            Write-Host "WARNING: No response body (empty content)." -ForegroundColor Yellow
        }
    }
    catch [System.UriFormatException] {
        Write-Host "ERROR: Invalid GET URL" -ForegroundColor Red
        Write-Host "  $getUrl" -ForegroundColor DarkGray
    }
    catch [System.Net.WebException] {
        $we = $_.Exception
        Write-Host "ERROR or BLOCKED: Status = $($we.Status)" -ForegroundColor Red

        if ($we.Response -ne $null) {
            $httpResp = $we.Response
            try {
                $statusCode        = $httpResp.StatusCode
                $statusDescription = $httpResp.StatusDescription
            }
            catch {
                $statusCode        = "<unknown>"
                $statusDescription = "<unknown>"
            }
            Write-Host "  --- RESPONSE METADATA ---" -ForegroundColor DarkYellow
            Write-Host "  Status Code       : $statusCode" -ForegroundColor DarkYellow
            Write-Host "  Status Description: $statusDescription" -ForegroundColor DarkYellow
            Write-Host "  ------------------------" -ForegroundColor DarkYellow
            Write-Host "  Headers:" -ForegroundColor DarkYellow
            foreach ($headerKey in $httpResp.Headers.Keys) {
                $value = $httpResp.Headers[$headerKey]
                Write-Host ("    {0}: {1}" -f $headerKey, $value) -ForegroundColor DarkGray
            }

            try {
                $ms2       = New-Object System.IO.MemoryStream
                $httpResp.GetResponseStream().CopyTo($ms2)
                $bodyBytes = $ms2.ToArray()

                Write-Host "  Body length: $($bodyBytes.Length) bytes" -ForegroundColor DarkYellow
                if ($bodyBytes.Length -gt 0) {
                    $bodyB64 = [Convert]::ToBase64String($bodyBytes)
                    Write-Host "  Body (Base64): $bodyB64" -ForegroundColor DarkGray
                }
                else {
                    Write-Host "  (No body content - length zero.)" -ForegroundColor DarkYellow
                }
            }
            catch {
                Write-Host "  Failed to read body: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        else {
            Write-Host "  No HTTP response; message: $($we.Message)" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "UNEXPECTED ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }

    # -------------------------
    # Test POST
    # -------------------------
    Write-Host "POST method" -ForegroundColor Yellow
    $postUrl = $provider
    Write-Host "POST URL: $postUrl" -ForegroundColor DarkGray

    try {
        $response = Invoke-WebRequest -Uri $postUrl `
            -Method      "POST" `
            -Headers     @{ 
                "Accept"       = "application/dns-message"
                "Content-Type" = "application/dns-message"
            } `
            -Body        $queryBytes `
            -UseBasicParsing

        if ($response -ne $null -and $response.RawContentStream -ne $null) {
            $ms        = New-Object System.IO.MemoryStream
            $response.RawContentStream.CopyTo($ms)
            $respBytes = $ms.ToArray()

            Write-Host "SUCCESS: Received $($respBytes.Length) bytes" -ForegroundColor Green
            $respB64 = [Convert]::ToBase64String($respBytes)
            Write-Host "  DNS response (Base64): $respB64" -ForegroundColor Gray
        }
        else {
            Write-Host "WARNING: No response body (empty content)." -ForegroundColor Yellow
        }
    }
    catch [System.Net.WebException] {
        $we = $_.Exception
        Write-Host "ERROR or BLOCKED: Status = $($we.Status)" -ForegroundColor Red

        if ($we.Response -ne $null) {
            $httpResp = $we.Response
            try {
                $statusCode        = $httpResp.StatusCode
                $statusDescription = $httpResp.StatusDescription
            }
            catch {
                $statusCode        = "<unknown>"
                $statusDescription = "<unknown>"
            }
            Write-Host "  --- RESPONSE METADATA ---" -ForegroundColor DarkYellow
            Write-Host "  Status Code       : $statusCode" -ForegroundColor DarkYellow
            Write-Host "  Status Description: $statusDescription" -ForegroundColor DarkYellow
            Write-Host "  ------------------------" -ForegroundColor DarkYellow
            Write-Host "  Headers:" -ForegroundColor DarkYellow
            foreach ($headerKey in $httpResp.Headers.Keys) {
                $value = $httpResp.Headers[$headerKey]
                Write-Host ("    {0}: {1}" -f $headerKey, $value) -ForegroundColor DarkGray
            }

            try {
                $ms2       = New-Object System.IO.MemoryStream
                $httpResp.GetResponseStream().CopyTo($ms2)
                $bodyBytes = $ms2.ToArray()

                Write-Host "  Body length: $($bodyBytes.Length) bytes" -ForegroundColor DarkYellow
                if ($bodyBytes.Length -gt 0) {
                    $bodyB64 = [Convert]::ToBase64String($bodyBytes)
                    Write-Host "  Body (Base64): $bodyB64" -ForegroundColor DarkGray
                }
                else {
                    Write-Host "  (No body content - length zero.)" -ForegroundColor DarkYellow
                }
            }
            catch {
                Write-Host "  Failed to read body: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        else {
            Write-Host "  No HTTP response; message: $($we.Message)" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "UNEXPECTED ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
} # End foreach provider
