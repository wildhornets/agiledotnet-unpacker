param(
 [Parameter(Mandatory=$true)][string]$InputDirectory,
 [Parameter(Mandatory=$true)][string]$OutputDirectory,
 [string]$DnlibPath='')
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath $OutputDirectory){throw 'Choose a NEW output directory; confirmed files are never overwritten'}
New-Item -ItemType Directory -Path $OutputDirectory|Out-Null
& (Join-Path $PSScriptRoot 'cleanup-tools\remove_c5vm_static.ps1') -InputDirectory $InputDirectory -OutputDirectory (Join-Path $OutputDirectory 'helper-free') -DnlibPath $DnlibPath
& (Join-Path $PSScriptRoot 'cleanup-tools\rename_readable.ps1') -InputFile (Join-Path $OutputDirectory 'helper-free\helperfree.bin') -OutputDirectory (Join-Path $OutputDirectory 'result') -DnlibPath $DnlibPath -ReferenceDirectory $InputDirectory
Write-Output ('ANALYSIS_OUTPUT '+(Join-Path $OutputDirectory 'result\SeroXen.cleaned.bin'))
Write-Output 'No sample execution. No C# compilation. Renamed identifiers are partly inferred/generated, not guaranteed original names.'
