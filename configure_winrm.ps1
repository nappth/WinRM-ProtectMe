# Configure network profile
Set-NetConnectionProfile -NetworkCategory Private

# Enable PSRemoting
Enable-PSRemoting -Force

# Configure WinRM HTTP
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
winrm set winrm/config/service/auth '@{Basic="true"}'
netsh advfirewall firewall add rule name="WinRM-HTTP" dir=in action=allow protocol=TCP localport=5985

# Create self-signed certificate
$cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My
$thumbprint = $cert.Thumbprint

# Configure WinRM HTTPS
winrm create winrm/config/Listener?Address=*+Transport=HTTPS "@{Hostname=`"$env:COMPUTERNAME`"; CertificateThumbprint=`"$thumbprint`"}"
netsh advfirewall firewall add rule name="WinRM-HTTPS" dir=in action=allow protocol=TCP localport=5986

# Configure TCP settings
Set-NetTCPSetting -SettingName InternetCustom -CongestionProvider None