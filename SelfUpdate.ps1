$scriptDir = Split-Path $script:MyInvocation.MyCommand.Path
Write-Host "Checking for updates to Posh-SentinelOne"
$RepositoryManifest = "https://raw.githubusercontent.com/zeroonesec/posh-sentinelone/master/Posh-SentinelOne.psd1"
$RepositoryDownload = "https://github.com/zeroonesec/posh-sentinelone/archive/master.zip"
$ModuleVersion = (Import-LocalizedData -BaseDirectory $scriptDir -FileName Posh-SentinelOne.psd1).ModuleVersion

$Result = Invoke-WebRequest -URI $RepositoryManifest -ContentType 'application/text' -OutFile "$scriptDir\RepositoryManifest.psd1"
$RepositoryVersion = (Import-LocalizedData -BaseDirectory $scriptDir -FileName RepositoryManifest.psd1).ModuleVersion
Remove-Item $scriptDir\RepositoryManifest.psd1

if($ModuleVersion -eq $RepositoryVersion) {
    Write-Host "Module is up-to-date."
} else {
    Write-Host "A new version of Posh-SentinelOne is available, performing update"
    Write-Host "Downloading $RepositoryDownload"
    $Result = Invoke-WebRequest -URI $RepositoryDownload -OutFile "$scriptDir\archive.zip"

    Write-Host "Extracting..."
    Expand-Archive $scriptDir\archive.zip $scriptDir\update
    Copy-item "$scriptDir\update\*\*" $scriptDir -Force -Recurse
    Remove-Item $scriptDir\update -Recurse -Force
    Remove-Item $scriptDir\archive.zip

}