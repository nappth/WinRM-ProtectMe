Start-Transcript -Path "C:\Windows\Temp\winrm_config.log" -Append

try {
    # 1. Configurer le profil réseau en privé
    Write-Output "Configuring network profile..."
    Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private -ErrorAction Stop

    # 2. Activer PS Remoting
    Write-Output "Enabling PSRemoting..."
    Enable-PSRemoting -Force -ErrorAction Stop
    Set-Service -Name WinRM -StartupType Automatic -ErrorAction Stop

    # 3. Configurer WinRM
    Write-Output "Configuring WinRM service..."
    winrm quickconfig -quiet
    winrm set winrm/config/service '@{AllowUnencrypted="true"}'
    winrm set winrm/config/service/auth '@{Basic="true"}'
    winrm set winrm/config/client/auth '@{Basic="true"}'
    winrm set winrm/config/service/auth '@{CredSSP="true"}'

    # 4. Créer un certificat autosigné
    Write-Output "Creating self-signed certificate..."
    $hostname = $env:COMPUTERNAME
    $cert = New-SelfSignedCertificate -DnsName $hostname -CertStoreLocation "Cert:\LocalMachine\My" -ErrorAction Stop
    $thumbprint = $cert.Thumbprint
    Write-Output "Certificate thumbprint: $thumbprint"

    # 5. Supprimer les anciens listeners HTTPS s'ils existent
    Write-Output "Removing old HTTPS listeners..."
    Get-ChildItem WSMan:\localhost\Listener | Where-Object { $_.Keys -contains "Transport=HTTPS" } | Remove-Item -Recurse -Force

    # 6. Créer un listener HTTPS
    Write-Output "Configuring WinRM HTTPS listener..."
    New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbprint $thumbprint -Force

    # 7. Configurer le pare-feu
    Write-Output "Configuring firewall..."
    New-NetFirewallRule -DisplayName "WinRM-HTTP" -Direction Inbound -LocalPort 5985 -Protocol TCP -Action Allow -ErrorAction Stop
    New-NetFirewallRule -DisplayName "WinRM-HTTPS" -Direction Inbound -LocalPort 5986 -Protocol TCP -Action Allow -ErrorAction Stop

    # 8. Redémarrer le service
    Write-Output "Restarting WinRM service..."
    Restart-Service WinRM -Force -ErrorAction Stop

    # 9. Vérification que les listeners sont bien configurés
    Write-Output "Verifying WinRM configuration..."
    winrm enumerate winrm/config/listener

    Write-Output "✅ WinRM configuration completed successfully"
    exit 0
}
catch {
    Write-Output "❌ ERROR: $($_.Exception.Message)"
    Write-Output "DETAILS: $($_.ScriptStackTrace)"
    exit 1
}
finally {
    Stop-Transcript
}
