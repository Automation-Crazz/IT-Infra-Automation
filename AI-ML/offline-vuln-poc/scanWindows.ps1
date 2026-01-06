# scanWindows.ps1

# Windows System Security Scanner

# Run in PowerShell as administrator
 
$data = @{}
 
# System Information

$data.ComputerInfo = Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OSArchitecture
 
# Installed Software

$data.InstalledSoftware = Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor
 
# Windows Features

$data.WindowsFeatures = Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq "Enabled"} | Select-Object FeatureName
 
# Services

$data.Services = Get-Service | Select-Object Name, Status, StartType
 
# Network Connections

$data.NetworkConnections = Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"} | Select-Object LocalAddress, LocalPort, OwningProcess
 
# Processes

$data.Processes = Get-Process | Select-Object Name, Id, Company, Path
 
$data | ConvertTo-Json -Depth 3 | Out-File -Encoding utf8 "windows_system_scan.json"
 
Write-Host "Scan complete. Output saved to windows_system_scan.json"

Write-Host "Please upload this JSON file to the vulnerability analyzer."
 