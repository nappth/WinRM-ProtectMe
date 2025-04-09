Start-Transcript -Path "C:\Windows\Temp\winrm_config.log" -Append

try {
    # Configure network profile
    Write-Output "Configuring network profile..."
    Set-NetConnectionProfile -NetworkCategory Private -ErrorAction Stop

    # Enable PSRemoting
    Write-Output "Enabling PSRemoting..."
    Enable-PSRemoting -Force -ErrorAction Stop

    # Configure WinRM HTTP
    Write-Output "Configuring WinRM HTTP..."
    winrm set winrm/config/service '@{AllowUnencrypted="true"}' -ErrorAction Stop
    winrm set winrm/config/service/auth '@{Basic="true"}' -ErrorAction Stop
    netsh advfirewall firewall add rule name="WinRM-HTTP" dir=in action=allow protocol=TCP localport=5985 -ErrorAction Stop

    # Create self-signed certificate
    Write-Output "Creating certificate..."
    $cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My -ErrorAction Stop
    $thumbprint = $cert.Thumbprint
    Write-Output "Certificate thumbprint: $thumbprint"

    # Configure WinRM HTTPS
    Write-Output "Configuring WinRM HTTPS..."
    winrm create winrm/config/Listener?Address=*+Transport=HTTPS "@{Hostname=`"$env:COMPUTERNAME`"; CertificateThumbprint=`"$thumbprint`"}" -ErrorAction Stop
    netsh advfirewall firewall add rule name="WinRM-HTTPS" dir=in action=allow protocol=TCP localport=5986 -ErrorAction Stop

    Write-Output "Configuration completed successfully"
    exit 0
}
catch {
    Write-Output "ERROR: $_"
    exit 1
}
finally {
    Stop-Transcript
}
