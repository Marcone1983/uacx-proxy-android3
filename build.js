#!/usr/bin/env node

const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

console.log('🔨 Building SmartCache Enterprise executables...');

// Ensure dependencies are installed
exec('npm install', (err) => {
  if (err) {
    console.error('Failed to install dependencies:', err);
    process.exit(1);
  }

  // Build executables for all platforms
  const targets = [
    { platform: 'win', arch: 'x64', ext: '.exe' },
    { platform: 'macos', arch: 'x64', ext: '' },
    { platform: 'linux', arch: 'x64', ext: '' }
  ];

  targets.forEach(target => {
    const outputName = `smartcache-${target.platform}-${target.arch}${target.ext}`;
    const pkgTarget = `node20-${target.platform}-${target.arch}`;
    
    console.log(`Building for ${target.platform}-${target.arch}...`);
    
    exec(`npx pkg . --target ${pkgTarget} --output dist/${outputName}`, (err, stdout, stderr) => {
      if (err) {
        console.error(`Failed to build for ${target.platform}:`, stderr);
      } else {
        console.log(`✅ Built: dist/${outputName}`);
      }
    });
  });
});

// Create auto-installer batch file for Windows
const winInstaller = `@echo off
echo Installing SmartCache Enterprise...
set INSTALL_DIR=%ProgramFiles%\\SmartCache

if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
copy /Y smartcache-win-x64.exe "%INSTALL_DIR%\\smartcache.exe"

echo Creating Windows service...
sc create SmartCache binPath= "%INSTALL_DIR%\\smartcache.exe" start= auto DisplayName= "SmartCache AI Enterprise"
sc start SmartCache

echo Installation complete!
echo Dashboard will open in your browser...
timeout /t 3
start http://localhost:3000
pause
`;

fs.writeFileSync('dist/install-windows.bat', winInstaller);
console.log('✅ Created Windows auto-installer');

// Create PowerShell installer with network propagation
const psInstaller = `
# SmartCache Enterprise Network Installer
$ErrorActionPreference = "Stop"

function Install-SmartCache {
    param($ComputerName = "localhost")
    
    $sourcePath = $PSScriptRoot
    $targetPath = "\\\\$ComputerName\\c$\\ProgramFiles\\SmartCache"
    
    Write-Host "Installing on $ComputerName..."
    
    # Copy files
    New-Item -Path $targetPath -ItemType Directory -Force | Out-Null
    Copy-Item "$sourcePath\\smartcache-win-x64.exe" -Destination "$targetPath\\smartcache.exe" -Force
    
    # Create and start service
    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        $exe = "C:\\Program Files\\SmartCache\\smartcache.exe"
        New-Service -Name "SmartCache" -BinaryPathName $exe -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service "SmartCache"
    }
    
    Write-Host "✅ Installed on $ComputerName"
}

# Install locally first
Install-SmartCache

# Network propagation
Write-Host "Scanning network for deployment..."
$subnet = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.PrefixOrigin -ne "WellKnown"})[0].IPAddress -replace '\\.[^.]+$', ''

1..254 | ForEach-Object -Parallel {
    $ip = "$using:subnet.$_"
    if (Test-Connection -ComputerName $ip -Count 1 -Quiet) {
        try {
            Install-SmartCache -ComputerName $ip
        } catch {
            # Silent fail for unreachable hosts
        }
    }
} -ThrottleLimit 10

Write-Host "Network deployment complete!"
Start-Process "http://localhost:3000"
`;

fs.writeFileSync('dist/network-install.ps1', psInstaller);
console.log('✅ Created PowerShell network installer');