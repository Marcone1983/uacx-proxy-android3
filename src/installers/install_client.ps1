# SmartCache Client Installation Script
# Executes on each target computer via WMI

$ErrorActionPreference = "Stop"

# Configuration
$pluginPath = "C:\Program Files\SmartCache"
$serviceName = "SmartCache"
$supabaseKey = $env:SUPABASE_ANON_KEY  # Read from environment or replaced during deployment

# Function to write log
function Write-Log {
    param($Message)
    $logFile = "$env:TEMP\SmartCache_Install.log"
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $logFile -Append
}

Write-Log "Starting SmartCache installation on $env:COMPUTERNAME"

try {
    # Create installation directory
    if (!(Test-Path $pluginPath)) {
        New-Item -Path $pluginPath -ItemType Directory -Force | Out-Null
        Write-Log "Created directory: $pluginPath"
    }

    # Download SmartCache from network share or internal server
    $sourceFiles = "\\$env:USERDNSDOMAIN\SmartCache$\*"
    
    # Try network share first
    if (Test-Path $sourceFiles) {
        Copy-Item -Path $sourceFiles -Destination $pluginPath -Recurse -Force
        Write-Log "Copied files from network share"
    } else {
        # Fallback to web download
        $downloadUrl = "https://internal-server.company.local/smartcache/SmartCacheClient.zip"
        $zipPath = "$pluginPath\SmartCacheClient.zip"
        
        Write-Log "Downloading from $downloadUrl"
        Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing
        
        # Extract archive
        Expand-Archive -Path $zipPath -DestinationPath $pluginPath -Force
        Remove-Item $zipPath -Force
        Write-Log "Extracted SmartCache files"
    }

    # Update configuration with Supabase key
    $configPath = "$pluginPath\.env"
    if (Test-Path $configPath) {
        $config = Get-Content $configPath
        $config = $config -replace 'YOUR_SUPABASE_ANON_KEY', $supabaseKey
        $config | Set-Content $configPath
        Write-Log "Updated configuration"
    }

    # Install Node.js if not present
    $nodePath = Get-Command node -ErrorAction SilentlyContinue
    if (!$nodePath) {
        Write-Log "Installing Node.js..."
        $nodeInstaller = "$env:TEMP\node-installer.msi"
        Invoke-WebRequest -Uri "https://nodejs.org/dist/v20.10.0/node-v20.10.0-x64.msi" `
            -OutFile $nodeInstaller -UseBasicParsing
        
        Start-Process msiexec.exe -ArgumentList "/i", $nodeInstaller, "/quiet", "/norestart" -Wait
        Write-Log "Node.js installed"
    }

    # Install dependencies
    Set-Location $pluginPath
    & npm install --production --silent 2>&1 | Out-Null
    Write-Log "Dependencies installed"

    # Create Windows service
    $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($existingService) {
        Stop-Service -Name $serviceName -Force
        sc.exe delete $serviceName
        Start-Sleep -Seconds 2
    }

    # Create new service
    $serviceParams = @{
        Name = $serviceName
        BinaryPathName = "`"C:\Program Files\nodejs\node.exe`" `"$pluginPath\src\smartcache.js`""
        DisplayName = "SmartCache AI Interceptor"
        Description = "Enterprise AI response caching and optimization"
        StartupType = "Automatic"
    }
    
    New-Service @serviceParams
    Write-Log "Service created: $serviceName"

    # Configure service recovery
    sc.exe failure $serviceName reset=86400 actions=restart/5000/restart/10000/restart/30000
    
    # Set service to run as SYSTEM
    sc.exe config $serviceName obj=LocalSystem
    
    # Start the service
    Start-Service -Name $serviceName
    Write-Log "Service started successfully"

    # Configure Windows Firewall
    New-NetFirewallRule -DisplayName "SmartCache Dashboard" `
        -Direction Inbound `
        -Protocol TCP `
        -LocalPort 3000 `
        -Action Allow `
        -ErrorAction SilentlyContinue
    
    New-NetFirewallRule -DisplayName "SmartCache WebSocket" `
        -Direction Inbound `
        -Protocol TCP `
        -LocalPort 8080 `
        -Action Allow `
        -ErrorAction SilentlyContinue
    
    Write-Log "Firewall rules configured"

    # Install browser extension for all users
    $chromeExtPath = "$env:ProgramData\Google\Chrome\Extensions\smartcache"
    if (!(Test-Path $chromeExtPath)) {
        New-Item -Path $chromeExtPath -ItemType Directory -Force | Out-Null
    }
    
    Copy-Item -Path "$pluginPath\browser-extension\*" -Destination $chromeExtPath -Recurse -Force
    
    # Add Chrome policy for auto-install
    $chromePolicyPath = "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist"
    if (!(Test-Path $chromePolicyPath)) {
        New-Item -Path $chromePolicyPath -Force | Out-Null
    }
    
    Set-ItemProperty -Path $chromePolicyPath -Name "1" -Value "smartcache;file:///$chromeExtPath"
    Write-Log "Browser extension configured"

    # Configure system proxy
    netsh winhttp set proxy proxy-server="127.0.0.1:8888" bypass-list="localhost;127.0.0.1;*.local"
    Write-Log "System proxy configured"

    # Add to startup for all users
    $startupPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    Set-ItemProperty -Path $startupPath -Name "SmartCache" -Value "$pluginPath\smartcache.exe"
    
    # Create scheduled task for redundancy
    $taskAction = New-ScheduledTaskAction -Execute "node.exe" -Argument "$pluginPath\src\smartcache.js"
    $taskTrigger = New-ScheduledTaskTrigger -AtStartup
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
    $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    
    Register-ScheduledTask -TaskName "SmartCache-Backup" `
        -Action $taskAction `
        -Trigger $taskTrigger `
        -Principal $taskPrincipal `
        -Settings $taskSettings `
        -Force
    
    Write-Log "Scheduled task created"

    # Send installation success notification to central server
    $installData = @{
        hostname = $env:COMPUTERNAME
        username = $env:USERNAME
        domain = $env:USERDNSDOMAIN
        ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike "*Loopback*"}).IPAddress[0]
        timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        status = "installed"
    }
    
    try {
        Invoke-RestMethod -Uri "https://grjhpkndqrkewluxazvl.functions.supabase.co/uacx-cache/install" `
            -Method POST `
            -Body ($installData | ConvertTo-Json) `
            -ContentType "application/json" `
            -Headers @{ "apikey" = $supabaseKey }
    } catch {
        Write-Log "Failed to notify central server: $_"
    }

    Write-Log "SmartCache installation completed successfully!"
    
    # Open dashboard for verification (if interactive)
    if ([Environment]::UserInteractive) {
        Start-Process "http://localhost:3000"
    }

} catch {
    Write-Log "ERROR: $_"
    
    # Send failure notification
    try {
        $errorData = @{
            hostname = $env:COMPUTERNAME
            error = $_.Exception.Message
            timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            status = "failed"
        }
        
        Invoke-RestMethod -Uri "https://grjhpkndqrkewluxazvl.functions.supabase.co/uacx-cache/install" `
            -Method POST `
            -Body ($errorData | ConvertTo-Json) `
            -ContentType "application/json" `
            -Headers @{ "apikey" = $supabaseKey }
    } catch {
        # Silent fail
    }
    
    exit 1
}

exit 0