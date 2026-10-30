param([string]$DnlibPath='')
$ErrorActionPreference='Stop'
if(-not $DnlibPath){$DnlibPath=$env:DNLIB_PATH}
if(-not $DnlibPath -and $env:DNSPY_HOME){
 foreach($candidate in @((Join-Path $env:DNSPY_HOME 'bin\dnlib.dll'),(Join-Path $env:DNSPY_HOME 'dnlib.dll'))){
  if(Test-Path -LiteralPath $candidate -PathType Leaf){$DnlibPath=$candidate;break}
 }
}
if(-not $DnlibPath){throw 'Supply -DnlibPath to a trusted dnlib.dll, or set DNLIB_PATH / DNSPY_HOME. Tested with dnlib3.5.0. No download or compilation is performed.'}
$resolved=(Resolve-Path -LiteralPath $DnlibPath -ErrorAction Stop).Path
$identity=[Reflection.AssemblyName]::GetAssemblyName($resolved)
if($identity.Name -ne 'dnlib'){throw 'The supplied library is not dnlib'}
[Reflection.Assembly]::LoadFrom($resolved)|Out-Null
