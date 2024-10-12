# Function to capture logs in a File

function Write-Log
{
    [CmdletBinding()]
    Param
    (  
      [Parameter(Mandatory=$true)]
      [ValidateNotNUllorEmpty()]
      [Alias("LogContent")]
      [string]$message,
      
      [Parameter(Mandatory=$false)]
      [Alias("LogPath")]
      [string]$path,

      [Parameter(Mandatory=$false)]
      [ValidateSet("Error", "Warn", "Info")]
      [string]$Level       
    )

    try
    {
      # If attempting to write a log in a folder/path that doesn't exist, create the file including the path
      if (!(Test-Path $Path))
      {
          New-Item $Path -Force -ItemType File | Out-Null
      }

      #Format Date for Log FIle independent of system langauge
      $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
      $englishCulture = [System.Globallization.CultureInfo]::GetCultureInfo("en-US")
      $systemDateinEnglish = $FormattedDate.ToString($englishCulture)

      # Write message to error, warning or verbose pipeline and specify $LevelText
      switch($level)
      {
            'Error'
            {  
              $LevelText = 'ERROR'
            }

            'Warn'
            {
              $LevelText = 'WARNING'
            }

            'Info'
            {
              $LevelText = 'INFO'
            }

            Default
            {
              $LevelText = 'INFO'
            }
            
      }

      # Write the LOG to file
      "[$systemDateinEnglish] [$LevelText] : $Message" | Out-file -FilePath $Path -Append
      
    }
    catch
    {
        throw "$($_.ExceptionMessage)"
    }

}
