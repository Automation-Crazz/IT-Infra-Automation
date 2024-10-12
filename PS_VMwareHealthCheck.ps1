# The following code checks the VMware resources health including -- Cluster Details, VM Host Details, DataStore Details and VM details
# Save your VCenter credentials in "Windows Credential Manager" under "Generic" tab
# The script needs to be called with Config File path(C:\path\to\config.json) and Output Folder path (C:\path\to\output-Folder\)


<########################## Config File Content ###############################################

Config.json
-------------
{
    "outputFileName" : "vmWare_Status_Report.txt",
    "vmServerName" : "VM-srv-1,VM-srv-2,VM-srv-3",
    "vmServerCredential" : "ABC"
}

###############################################################################################>

param(
  [string]$configFile,
  [string]$outputFolderPath
)


# getting the vm_credential
try {
    $vmUserName = (Get-StoredCredential -Target ($configFile.vmServerCredential)).UserName
    $vmPassword = (Get-StoredCredential -Target ($configFile.vmServerCredential)).GetNetworkCredential().Password
}
catch {
    write-host "ERROR - While Fetching UserName and Password From Cred-Manager : $_"
}

# loop through all the server details
$vCenterDetails = $configFile.vmServerName -split ','
foreach ($vmServerName in $vCenterDetails) {
    # define output file path
    $date = Get-Date -Format "MM-dd-yyyy"
    $outputFilePath = Join-Path -Path $outputFolderPath -ChildPath ("$date" + "_" + "$vmServerName" + "_" + $configFile.outputFileName)
    
    # Add Header Content
    $date = Get-Date -Format "MM-dd-yyyy"
    # Add-Content -Path $outputFilePath -Value "Date: $date `nServer Name: $vmServerName`n=======================================================================`n`n"
    "Date: $date`r`nServer Name: $vmServerName`r`n================================================================================================================================================`r`n" | Out-File -FilePath $outputFilePath -Append
    # get the cluster details
    try {
        Connect-VIServer -Server $vmServerName -User $vmUserName -Password $vmPassword | Out-Null
        & $LogEntry -LogMessage "SUCCESS - Successfully Connected With $vmServerName - Cluster"
        try {
            Get-Cluster | Select-Object Name, HAEnabled, HAFailoverLevel, DrsEnabled, DrsMode | Format-Table -AutoSize | Out-String -Width 4096 | Out-File -FilePath $outputFilePath -Append
            Clear-Host
            Write-Host "SUCCESS - $vmServerName Cluster Details Fetched"
        }
        catch {
            Write-Host "ERROR - $vmServerName Cluster Details Not Fetched"
        }
        Disconnect-VIServer -Server $vmServerName -Confirm:$false -Force
    }
    catch {
        Write-Host "ERROR - Connection Failed With The $vmServerName"
    }

    # get the vmHost details
    try {
        Connect-VIServer -Server $vmServerName -User $vmUserName -Password $vmPassword | Out-Null
        Write-Host "SUCCESS - Successfully Connected With $vmServerName - vmHost"

        try {
            Get-VMHost | Select-Object Name, ConnectionState, PowerState, @{N = 'Cluster'; E = { Get-Cluster -VMHost $_ } }, @{N = 'CPU(%)'; E = { $_.CpuUsageMhz } }, @{N = 'Memory(%)'; E = { $_.MemoryUsageGB.ToString("F2") } }, @{N = "Uptime(Days)"; E = { New-Timespan -Start $_.ExtensionData.Summary.Runtime.BootTime -End (Get-Date) | Select-Object -ExpandProperty Days } } | Format-Table -AutoSize | Out-String -Width 4096 | Out-File -FilePath $outputFilePath -Append
            Clear-Host
            Write-Host "SUCCESS - $vmServerName - vmHost Details Fetched"
        }
        catch {
            Write-Host "ERROR - $vmServerName - vmHost Details Not Fetched"
        }
        Disconnect-VIServer -Server $vmServerName -Confirm:$false -Force
    }
    catch {
        Write-Host "ERROR - Connection Failed With The $vmServerName"
    }

    # get the DataStore details
    try {
        Connect-VIServer -Server $vmServerName -User $vmUserName -Password $vmPassword | Out-Null
        Write-Host "SUCCESS - Successfully Connected With $vmServerName - DataStore"

        try {
            Get-Datastore | Select-Object Name, State, Type, @{N = 'Capacity(GB)'; E = { $_.CapacityGB.ToString("F2") } }, @{N = 'FreeSpace(GB)'; E = { $_.FreeSpaceGB.ToString("F2") } } | Format-Table -AutoSize | Out-String -Width 4096 | Out-File -FilePath $outputFilePath -Append
            Clear-Host
            Write-Host "SUCCESS - $vmServername -  Datastore Detials Fetched"
        }
        catch {
            Write-Host "ERROR - $vmServerName - DataStore Details Not Fetched"
        }
        Disconnect-VIServer -Server $vmServerName -Confirm:$false -Force
    }
    catch {
        Write-Host "ERROR - Connection Failed With The $vmServerName"
    }

    # get the vm details
    try {
        Connect-VIServer -Server $vmServerName -User $vmUserName -Password $vmPassword | Out-Null
        Write-Host "SUCCESS - Successfully Connected With $vmServerName - VM"

        try {
            Get-VM | Select-Object Name, @{N = 'Status'; E = { $_.PowerState }}, @{N = 'ProvisionedSpace(GB)'; E = { $_.ProvisionedSpaceGB.ToString("F2") } }, @{N = 'UsedSpace(GB)'; E = { $_.UsedSpaceGB.ToString("F2") } }, @{N = 'CPU(n)'; E = { $_.NumCpu } }, @{N = 'Memory(GB)'; E = { $_.MemoryGB.ToString("F2") } } | Format-Table -AutoSize | Out-String -Width 4096 | Out-File -FilePath $outputFilePath -Append
            Clear-Host
            Write-Host "SUCCESS - $vmServerName VM Detials Fetched"
        }
        catch {
            Write-Host "ERROR - $vmServerName - VM Details Not Fetched"
        }
        Disconnect-VIServer -Server $vmServerName -Confirm:$false -Force
    }
    catch {
        Write-Host "ERROR - Connection Failed With The $vmServerName"
    }
    ##############################################################################################
}

