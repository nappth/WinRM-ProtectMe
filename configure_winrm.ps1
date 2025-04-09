Start-Transcript -Path "C:\Windows\Temp\winrm_ssh_config.log" -Append

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

    # 7. Configurer le pare-feu pour WinRM
    Write-Output "Configuring firewall for WinRM..."
    New-NetFirewallRule -DisplayName "WinRM-HTTP" -Direction Inbound -LocalPort 5985 -Protocol TCP -Action Allow -ErrorAction Stop
    New-NetFirewallRule -DisplayName "WinRM-HTTPS" -Direction Inbound -LocalPort 5986 -Protocol TCP -Action Allow -ErrorAction Stop

    # 8. Installation et configuration d'OpenSSH
    Write-Output "Installing OpenSSH Server..."
    # Vérifier si Windows 10 1809 ou plus récent (où Add-WindowsCapability fonctionne)
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    $osVersion = [Version]($osInfo.Version)
    
    if ($osVersion -ge [Version]"10.0.17763") {
        # Windows 10 1809 ou plus récent - utiliser Add-WindowsCapability
        Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -ErrorAction SilentlyContinue
    } else {
        # Pour les versions plus anciennes, utiliser la méthode d'installation via PowerShell
        $sshPath = "$env:TEMP\OpenSSH-Win64.zip"
        $sshExtractPath = "$env:ProgramFiles\OpenSSH"
        
        # Télécharger OpenSSH
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri "https://github.com/PowerShell/Win32-OpenSSH/releases/download/v8.9.1.0p1-Beta/OpenSSH-Win64.zip" -OutFile $sshPath -ErrorAction SilentlyContinue
        
        # Extraire l'archive
        if (Test-Path $sshPath) {
            Expand-Archive -Path $sshPath -DestinationPath $env:ProgramFiles -Force
            Rename-Item "$env:ProgramFiles\OpenSSH-Win64" -NewName "OpenSSH" -ErrorAction SilentlyContinue
            
            # Installer SSH
            & "$sshExtractPath\install-sshd.ps1" -ErrorAction SilentlyContinue
        }
    }

    # 9. Configurer et démarrer le service SSH
    Write-Output "Configuring SSH service..."
    if (Get-Service sshd -ErrorAction SilentlyContinue) {
        Start-Service sshd
        Set-Service -Name sshd -StartupType 'Automatic'
        
        # Autoriser l'authentification par mot de passe (pour l'accès initial)
        $sshdConfigPath = "$env:ProgramData\ssh\sshd_config"
        if (Test-Path $sshdConfigPath) {
            $config = Get-Content $sshdConfigPath
            $config = $config -replace "#PasswordAuthentication yes", "PasswordAuthentication yes"
            $config | Set-Content $sshdConfigPath
            Restart-Service sshd
        }
    }

    # 10. Configurer le pare-feu pour SSH
    Write-Output "Configuring firewall for SSH..."
    New-NetFirewallRule -DisplayName "SSH" -Direction Inbound -LocalPort 22 -Protocol TCP -Action Allow -ErrorAction Stop

    # 11. Redémarrer les services
    Write-Output "Restarting services..."
    Restart-Service WinRM -Force -ErrorAction Stop
    if (Get-Service sshd -ErrorAction SilentlyContinue) {
        Restart-Service sshd -ErrorAction SilentlyContinue
    }

    # 12. Vérification finale
    Write-Output "Verifying configurations..."
    Write-Output "WinRM Listeners:"
    winrm enumerate winrm/config/listener
    
    Write-Output "SSH Status:"
    if (Get-Service sshd -ErrorAction SilentlyContinue) {
        Get-Service sshd | Format-List Name, Status, StartType
    } else {
        Write-Output "SSH service not found."
    }

    Write-Output "✅ Configuration completed successfully"
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
