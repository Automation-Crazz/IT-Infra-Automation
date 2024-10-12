# The script is designed to extract the USER information from AD and save it in a CSV file.
# The script needs to be called with AD server name/IP and CSV file path.



param (

[CmdletBinding()]

    [Parameter(Mandatory=$true)]
    [ValidateNotNUllorEmpty()]
    [string]$serverInstance,

    [Parameter(Mandatory=$true)]
    [string]$outputPath
)


$adminCred = Get-Credential -Message "Enter credentials for the jump server"

try {

    $session = New-PSSession -ComputerName $serverInstance -Credential $adminCred
    if ($session) {
        Write-Host "Login to server $serverInstance successfully" -ForegroundColor Green

        $command = {
            param($adminCred)
            Import-Module ActiveDirectory

            try {
                $users = Get-ADUser -Filter * -Credential $adminCred -Properties Created, EmailAddress, Description, GivenName, Modified, Name, LockedOut, Enabled, AccountExpirationDate, PasswordLastSet, SamAccountName, UserPrincipalName, LastLogonDate, DistinguishedName -ErrorAction Stop

                $selectedUsers = $users | Select-Object @{Name="Name";Expression={$_.Name}},
                                                      @{Name="First Name";Expression={$_.GivenName}},
                                                      @{Name="Creation Date";Expression={$_.Created}}, 
                                                      @{Name="Email Address";Expression={$_.EmailAddress}}, 
                                                      @{Name="Description";Expression={$_.Description}}, 
                                                      @{Name="Modification Date";Expression={$_.Modified}}, 
                                                      @{Name="Account is Locked Out";Expression={$_.LockedOut}}, 
                                                      @{Name="Disabled";Expression={!$_.Enabled}}, 
                                                      @{Name="Expiration Date";Expression={$_.AccountExpirationDate}}, 
                                                      @{Name="Password Age(Days)";Expression={($_.PasswordLastSet - (Get-Date)).Days}}, 
                                                      @{Name="Password Last Changed";Expression={$_.PasswordLastSet}}, 
                                                      @{Name="Username";Expression={$_.SamAccountName}}, 
                                                      @{Name="Username(pre 2000)";Expression={$_.UserPrincipalName}}, 
                                                      @{Name="Last LogonDate";Expression={$_.LastLogonDate}}, 
                                                      @{Name="Distinguished Name";Expression={$_.DistinguishedName}}

                return $selectedUsers
            } catch {
                Write-Host "Error querying AD: $_" -ForegroundColor Red
            }
        }

        $selectedUsers = Invoke-Command -Session $session -ScriptBlock $command -ArgumentList $adminCred 

        if ($selectedUsers) {

            $selectedUsers | Export-Csv -Path $outputPath -NoTypeInformation -Force
            Write-Host "Query executed and CSV file exported to $outputPath on the local machine" -ForegroundColor Green
        } else {
            Write-Host "No data retrieved from the server" -ForegroundColor Red
        }

    } else {
        Write-Host "Failed to login to the server $serverInstance" -ForegroundColor Red
    }
} catch {
    Write-Host "Error occurred: $_" -ForegroundColor Red
} finally {
    # Clean the session
    if ($session) {
        Remove-PSSession -Session $session
    }
}
