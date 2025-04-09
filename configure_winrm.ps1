Start-Transcript -Path "C:\Windows\Temp\winrm_config.log" -Append

try {
    # 1. Configurer le profil réseau en privé
    Write-Output "Configuring network profile..."
    Set-NetConnectionProfile -NetworkCategory Private -ErrorAction Stop

    # 2. Activer PS Remoting (nécessaire pour WinRM)
    Write-Output "Enabling PSRemoting..."
    Enable-PSRemoting -Force -ErrorAction Stop

    # 3. Configurer WinRM HTTP (optionnel, mais utile en debug local)
    Write-Output "Configuring WinRM HTTP..."
    winrm set winrm/config/service '@{AllowUnencrypted="false"}' -ErrorAction Stop
    winrm set winrm/config/service/auth '@{Basic="true"}' -ErrorAction Stop
    netsh advfirewall firewall add rule name="WinRM-HTTP" dir=in action=allow protocol=TCP localport=5985 -ErrorAction Stop

    # 4. Créer un certificat autosigné
    Write-Output "Creating self-signed certificate..."
    $cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My -ErrorAction Stop
    $thumbprint = $cert.Thumbprint
    Write-Output "Certificate thumbprint: $thumbprint"

    # 5. Supprimer les anciens listeners HTTPS (pour éviter les conflits)
    Write-Output "Removing old HTTPS listeners (if any)..."
    $listeners = winrm enumerate winrm/config/listener
    if ($listeners -match "Transport = HTTPS") {
        winrm delete winrm/config/Listener?Address=*+Transport=HTTPS
    }

    # 6. Créer un listener HTTPS avec le certificat
    Write-Output "Configuring WinRM HTTPS listener..."
    winrm create winrm/config/Listener?Address=*+Transport=HTTPS "@{Hostname=`"$env:COMPUTERNAME`"; CertificateThumbprint=`"$thumbprint`"}" -ErrorAction Stop

    # 7. Ouvrir le port 5986 dans le pare-feu
    Write-Output "Allowing port 5986 in firewall..."
    netsh advfirewall firewall add rule name="WinRM-HTTPS" dir=in action=allow protocol=TCP localport=5986 -ErrorAction Stop

    # 8. Redémarrer WinRM pour appliquer toutes les modifs
    Write-Output "Restarting WinRM service..."
    Restart-Service winrm

    Write-Output "✅ WinRM configuration completed successfully"
    exit 0
}
catch {
    Write-Output "❌ ERROR: $_"
    exit 1
}
finally {
    Stop-Transcript
}
