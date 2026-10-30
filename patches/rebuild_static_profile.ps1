param([Parameter(Mandatory=$true)][string]$OutputDirectory, [string]$DnlibPath='')
$ErrorActionPreference='Stop'
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
if(Test-Path -LiteralPath $OutputDirectory){throw 'Choose a NEW patch output directory'}
$vendor=Join-Path $PSScriptRoot '..\vendor\AgileDevirtualizer-v1.0.1'
$expected='a09ddedd44014a7fb9bb0be0f837d4015436a32701f07532df5157239733a9a8'
if((Get-FileHash -LiteralPath (Join-Path $vendor 'AgileDevirtualizer.dll')).Hash.ToLower() -ne $expected){throw 'Upstream DLL hash mismatch'}
New-Item -ItemType Directory -Path $OutputDirectory|Out-Null
& (Join-Path $PSScriptRoot 'patch_vm_tool.ps1') -Destination (Join-Path $OutputDirectory 'phase1') -VendorDirectory $vendor -DnlibPath $DnlibPath
& (Join-Path $PSScriptRoot 'patch_vm_tool_phase2.ps1') -SourceDirectory (Join-Path $OutputDirectory 'phase1') -Destination (Join-Path $OutputDirectory 'phase2') -DnlibPath $DnlibPath
& (Join-Path $PSScriptRoot 'patch_vm_tool_phase3.ps1') -SourceDirectory (Join-Path $OutputDirectory 'phase2') -Destination (Join-Path $OutputDirectory 'phase3') -DnlibPath $DnlibPath
& (Join-Path $PSScriptRoot 'scope_pointer_reads.ps1') -SourceDirectory (Join-Path $OutputDirectory 'phase3') -Destination (Join-Path $OutputDirectory 'phase4') -DnlibPath $DnlibPath
$final=Join-Path $OutputDirectory 'phase4\AgileDevirtualizer.dll'
$actual=(Get-FileHash -LiteralPath $final).Hash.ToLower()
$expected='9177b61b640d937b675648440b13df841d8970d3426df72fcee32df642a66302'
if($actual -ne $expected){throw "Rebuilt tool differs from tested profile: $actual"}
Write-Output "VERIFIED_STATIC_PROFILE $actual"
