$ErrorActionPreference = "Stop"

$installPath = "$env:ProgramFiles\SmartCache"
New-Item -Path $installPath -ItemType Directory -Force | Out-Null
Invoke-WebRequest -Uri "https://github.com/Marcone1983/uacx-proxy-android3/releases/latest/download/smartcache.zip" -OutFile "$installPath\smartcache.zip"
Expand-Archive "$installPath\smartcache.zip" -DestinationPath $installPath -Force

New-Service -Name "SmartCache" -BinaryPathName "node $installPath\src\smartcache.js" -StartupType Automatic
Start-Service "SmartCache"

Start-Process "http://localhost:3000"