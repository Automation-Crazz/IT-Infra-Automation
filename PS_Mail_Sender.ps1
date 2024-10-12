# The below code could be utilized when the "Send-MailMessage" is not working in PowerShell.
# The following code uses the .Net smtp modules to send the email.


<######################## Content of config File ############################################
Config.json (File Name) 

{
    "smtpServer" : "",
     "smtpPort": 587,
    "servers" : [""],
    "fromMail" : "",
    "toMail" : "",
    "username" : "",
    "password" : ""
}
############################################################################################>

param(
    [string]$configFilePath,
    [string]$attachmentFilePath
)

$configFile = Get-Content -Raw -Path $configFilePath | ConvertFrom-Json
$smtpServer = $configFile.smtpServer
$smtpPort = $configFile.smtpPort
$fromMail = $configFile.fromMail
$toMail = $configFile.toMail
$subject = $configFile.subject
$body = $configFile.body

$username = $configFile.username
$password = $configFile.password | ConvertTo-SecureString -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ($username, $password)


$smtpClient = New-Object System.Net.Mail.SmtpClient($smtpServer, $smtpPort)
$smtpClient.EnableSsl = $true  # Enable SSL/TLS

$smtpClient.Credentials = $cred

$mailMessage = New-Object System.Net.Mail.MailMessage($fromMail, $toMail, $subject, $body)
$mailMessage.IsBodyHtml = $false  # Set to HTML body

$attachment = New-Object System.Net.Mail.Attachment($attachmentFilePath)
$mailMessage.Attachments.Add($attachment)

# Send the email
try {
    $smtpClient.Send($mailMessage)
    Write-Host "SUCCESS - MAIL SENT SUCCESSFULLY TO: $toMail"
} catch {
    Write-Host "FAILED TO SEND MAIL-- Error: $_"
}
