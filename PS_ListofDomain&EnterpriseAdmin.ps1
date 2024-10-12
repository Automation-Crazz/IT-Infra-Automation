# Below code is capable of listing down all the Enterprise and Domain Admin members. (Nested Groups)
# The below code needs to be called with "Target Server name" and 2 files - groupName.txt and outputFile.xlsx.

<################################# FIle COntent ######################################################
GroupFile.txt                      
---------------                           
Domain Admin
Enterprise Admin
Global Admin

#####################################################################################################>


param (
    [string]$serverInstance,
    [string]$groupFilePath,
    [string]$xlsFilePath,
)

# Variable declaration

$obj = New-Object PSObject
	$obj | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $null
	$obj | Add-Member -MemberType NoteProperty -Name "1st Level Group" -Value $null
    $obj | Add-Member -MemberType NoteProperty -Name "2nd Level Group" -Value $null
    $obj | Add-Member -MemberType NoteProperty -Name "3rd Level Group" -Value $null
    $obj | Add-Member -MemberType NoteProperty -Name "Owner Description" -Value $null
    $obj | Add-Member -MemberType NoteProperty -Name "Last Modified Date" -Value $null


$list = ""
#"Server Name`t`t`t`t1st Level Group`t`t`t`t2nd Level Group`t`t`t`t3rd Level Group" | Out-File $result
foreach($server in $endPointName){
    Write-Host "Fetching Group information for $server" 
    $list =(Get-ADGroupMember -Identity $server).Name
    $descp = Get-ADGroup -identity $server -Properties * 
    $groupDescp = $descp.Description
    $groupModified = $descp.Modified
    #1st Level nested Group Identification
    foreach($firstnestedgorup in $list){
    try{
        $firstnestedlist = (Get-ADGroupMember -Identity $firstnestedgorup).Name
        if($firstnestedlist.count -le 0){
             $obj.GroupName  = [String]$server
                         $obj.'1st Level Group'  = [String]$firstnestedgorup + "(" + $sameName + ")"
                         $obj.'2nd Level Group'  = "-"
                         $obj.'3rd Level Group'  = "-"
                         $obj.'Owner Description' = [String]$groupDescp
                         $obj.'Last Modified Date' = [String]$groupModified
                         $intRow = $intRow + 1
        }
        $first1 = 0
        #2nd Level nested Group Identification
        foreach($secondnestedgorup in $firstnestedlist){
          try{
             $secondnestedlist = (Get-ADGroupMember -Identity $secondnestedgorup).Name
             $second1 = 0
             foreach($thirdnestedgroup in $secondnestedlist){
              try{
                    $sameName = (Get-ADUser -Filter {Name -eq $thirdnestedgroup}).samaccountname
                    }catch{
                    $sameName = "Group"
                    }
                if($second1 -eq 0){
                    if($first1 -eq 0){
                        #"$server`t`t`t`t`t$firstnestedgorup`t`t`t`t$secondnestedgorup`t`t`t`t$thirdnestedgroup" | Out-File $result -Append
                         $obj.GroupName  = [String]$server
                         $obj.'1st Level Group'  = [String]$firstnestedgorup
                         $obj.'2nd Level Group'  = [String]$secondnestedgorup
                         $obj.'3rd Level Group'  = [String]$thirdnestedgroup + "(" + $sameName + ")"
                         $obj.'Owner Description' = "-"
                         $obj.'Last Modified Date' = "-"
                         $intRow = $intRow + 1
                        $first1 = 1
                    }
                    else{
                        #"-`t`t`t-`t`t`t$secondnestedgorup`t`t`t`t$thirdnestedgroup" | Out-File $result -Append
                         $obj.GroupName  = "-"
                         $obj.'1st Level Group'  = "-"
                         $obj.'2nd Level Group'  = [String]$secondnestedgorup
                         $obj.'3rd Level Group'  = [String]$thirdnestedgroup + "(" + $sameName + ")"
                         $obj.'Owner Description' = "-"
                         $obj.'Last Modified Date' = "-"
                         $intRow = $intRow + 1
                        $first1 = 1
                    }
                    $second1 = 1
                }
                else{
                    #"-`t`t`t`t`t`t-`t`t`t`t`t$thirdnestedgroup" | Out-File $result -Append
                     $obj.GroupName  = "-"
                     $obj.'1st Level Group'  = "-"
                     $obj.'2nd Level Group'  = "-"
                     $obj.'3rd Level Group'  = [String]$thirdnestedgroup + "(" + $sameName + ")"
                     $obj.'Owner Description' = "-"
                     $obj.'Last Modified Date' = "-"
                     $intRow = $intRow + 1
                }
                $obj | Export-Csv -Path $xlsFilePath -Append -NoTypeInformation

            }
        }catch{
         $sameName = (Get-ADUser -Filter {Name -eq $secondnestedgorup}).samaccountname
            if($first1 -eq 0){
                #"$server`t`t`t`t`t$firstnestedgorup`t`t`t`t$secondnestedgorup`t`t`t`t -" | Out-File $result -Append
                         $obj.GroupName   = [String]$server
                         $obj.'1st Level Group'  = [String]$firstnestedgorup
                         $obj.'2nd Level Group'  = [String]$secondnestedgorup + "(" + $sameName + ")"
                         $obj.'3rd Level Group'  = "-"
                         $obj.'Owner Description' = "-"
                         $obj.'Last Modified Date' = "-"
                         $intRow = $intRow + 1
                $first1 = 1
            }
            else{
                #"-`t`t`t`t`t`t-`t`t`t`t`t$secondnestedgorup`t`t -" | Out-File $result -Append
                         $obj.GroupName  = "-"
                         $obj.'1st Level Group'  = "-"
                         $obj.'2nd Level Group'  = [String]$secondnestedgorup + "(" + $sameName + ")"
                         $obj.'3rd Level Group'  = "-"
                         $obj.'Owner Description' = "-"
                         $obj.'Last Modified Date' = "-"
                         $intRow = $intRow + 1
            }
        }
        $obj | Export-Csv -Path $xlsFilePath -Append -NoTypeInformation
        }
    }catch{ 
     $sameName = (Get-ADUser -Filter {Name -eq $firstnestedgorup}).samaccountname
        #"$server`t`t`t`t`t$firstnestedgorup`t`t`t`t -`t`t`t`t -" | Out-File $result -Append
                         $obj.GroupName  = [String]$server
                         $obj.'1st Level Group'  = [String]$firstnestedgorup + "(" + $sameName + ")"
                         $obj.'2nd Level Group'  = "-"
                         $obj.'3rd Level Group'  = "-"
                         $obj.'Owner Description' = [String]$groupDescp
                         $obj.'Last Modified Date' = [String]$groupModified
                         $intRow = $intRow + 1
    }
    $obj | Export-Csv -Path $xlsFilePath -Append -NoTypeInformation
    }
}
