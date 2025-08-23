Import-Module ActiveDirectory
$computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

foreach ($pc in $computers) {
  try {
    Invoke-WmiMethod -ComputerName $pc -Class Win32_Process -Name Create `
      -ArgumentList "powershell -ExecutionPolicy Bypass -File \\SERVER\share\install_windows.ps1"
    Write-Host "✅ Deployed to $pc"
  } catch {
    Write-Host "❌ Failed on $pc: $_"
  }
}