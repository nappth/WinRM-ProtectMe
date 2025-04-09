# configure_winrm.ps1
try {
    # Configure network profile
    Set-NetConnectionProfile -NetworkCategory Private -ErrorAction Stop

    # Enable PSRemoting
    Enable-PSRemoting -Force -ErrorAction Stop

    # Configure WinRM HTTP
    winrm set winrm/config/service '@{AllowUnencrypted="true"}' -ErrorAction Stop
    winrm set winrm/config/service/auth '@{Basic="true"}' -ErrorAction Stop
    netsh advfirewall firewall add rule name="WinRM-HTTP" dir=in action=allow protocol=TCP localport=5985 -ErrorAction Stop

    # Create self-signed certificate
    $cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My -ErrorAction Stop
    $thumbprint = $cert.Thumbprint

    # Configure WinRM HTTPS
    winrm create winrm/config/Listener?Address=*+Transport=HTTPS "@{Hostname=`"$env:COMPUTERNAME`"; CertificateThumbprint=`"$thumbprint`"}" -ErrorAction Stop
    netsh advfirewall firewall add rule name="WinRM-HTTPS" dir=in action=allow protocol=TCP localport=5986 -ErrorAction Stop

    exit 0
}
catch {
    Write-Error $_
    exit 1
}
