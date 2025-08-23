# SmartCache Enterprise - Master AD Deployment Script
# Executes from Domain Controller to deploy across all computers

$ErrorActionPreference = "Stop"
$ProgressPreference = 'SilentlyContinue'

Write-Host "================================" -ForegroundColor Cyan
Write-Host "SmartCache Enterprise Deployment" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan

# Configuration
$SourcePath = Split-Path -Parent $PSScriptRoot
$SharePath = "\\$env:COMPUTERNAME\SmartCache$"
$InstallScript = "install_client.ps1"

# Create network share if doesn't exist
if (!(Test-Path $SharePath)) {
    New-Item -Path $SharePath -ItemType Directory -Force | Out-Null
    New-SmbShare -Name "SmartCache$" -Path $SharePath -FullAccess "Domain Admins" -ReadAccess "Domain Computers"
    Write-Host "✅ Created network share: $SharePath" -ForegroundColor Green
}

# Copy installation files to share
Write-Host "📦 Copying installation files to network share..." -ForegroundColor Yellow
Copy-Item -Path "$SourcePath\*" -Destination $SharePath -Recurse -Force

# Get all computers in domain
Write-Host "🔍 Discovering computers in Active Directory..." -ForegroundColor Yellow
$computers = Get-ADComputer -Filter * -Properties OperatingSystem | 
    Where-Object { $_.OperatingSystem -like "*Windows*" } |
    Select-Object -ExpandProperty Name

Write-Host "📊 Found $($computers.Count) Windows computers" -ForegroundColor Cyan

# Deploy to each computer
$successCount = 0
$failureCount = 0
$results = @()

foreach ($computer in $computers) {
    Write-Host "`n🖥️  Processing: $computer" -ForegroundColor White
    
    try {
        # Test connectivity
        if (!(Test-Connection -ComputerName $computer -Count 1 -Quiet)) {
            throw "Computer offline or unreachable"
        }
        
        # Deploy SmartCache
        $result = Invoke-WmiMethod -ComputerName $computer `
            -Class Win32_Process `
            -Name Create `
            -ArgumentList "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File $SharePath\$InstallScript"
        
        if ($result.ReturnValue -eq 0) {
            Write-Host "    ✅ Successfully deployed to $computer" -ForegroundColor Green
            $successCount++
            
            # Track deployment
            $results += [PSCustomObject]@{
                Computer = $computer
                Status = "Success"
                ProcessId = $result.ProcessId
                Timestamp = Get-Date
            }
        } else {
            throw "WMI execution failed with code: $($result.ReturnValue)"
        }
        
    } catch {
        Write-Host "    ❌ Failed on $computer: $_" -ForegroundColor Red
        $failureCount++
        
        $results += [PSCustomObject]@{
            Computer = $computer
            Status = "Failed"
            Error = $_.Exception.Message
            Timestamp = Get-Date
        }
    }
}

# Generate deployment report
Write-Host "`n================================" -ForegroundColor Cyan
Write-Host "Deployment Summary" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host "✅ Successful: $successCount" -ForegroundColor Green
Write-Host "❌ Failed: $failureCount" -ForegroundColor Red
Write-Host "📊 Total: $($computers.Count)" -ForegroundColor White

# Save deployment log
$logPath = "$env:TEMP\SmartCache_Deployment_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$results | Export-Csv -Path $logPath -NoTypeInformation
Write-Host "`n📝 Deployment log saved to: $logPath" -ForegroundColor Yellow

# Optional: Create Group Policy for persistence
Write-Host "`n🔧 Creating Group Policy for SmartCache..." -ForegroundColor Yellow
$gpoName = "SmartCache-AutoStart"

try {
    New-GPO -Name $gpoName -ErrorAction SilentlyContinue
    
    # Configure startup script
    Set-GPRegistryValue -Name $gpoName `
        -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" `
        -ValueName "SmartCache" `
        -Type String `
        -Value "C:\Program Files\SmartCache\smartcache.exe"
    
    # Link to domain
    New-GPLink -Name $gpoName -Target (Get-ADDomain).DistinguishedName
    
    Write-Host "✅ Group Policy created and linked" -ForegroundColor Green
} catch {
    Write-Host "⚠️  Group Policy creation skipped (may already exist)" -ForegroundColor Yellow
}

# Monitor deployment status
Write-Host "`n📊 Monitoring deployment status..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

# Check if services are running
$runningServices = 0
foreach ($computer in $computers) {
    try {
        $service = Get-Service -ComputerName $computer -Name "SmartCache" -ErrorAction SilentlyContinue
        if ($service.Status -eq "Running") {
            $runningServices++
        }
    } catch {
        # Service not found or computer unreachable
    }
}

Write-Host "🚀 SmartCache running on $runningServices computers" -ForegroundColor Green

# Open central dashboard
Write-Host "`n🌐 Opening SmartCache Central Dashboard..." -ForegroundColor Cyan
Start-Process "http://localhost:3000"

Write-Host "`n✨ Deployment complete!" -ForegroundColor Green
Write-Host "Check the dashboard for real-time statistics from all clients" -ForegroundColor Cyan