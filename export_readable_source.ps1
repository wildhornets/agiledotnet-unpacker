param(
 [Parameter(Mandatory=$true)][string]$InputFile,
 [Parameter(Mandatory=$true)][string]$OutputDirectory,
 [string]$TypeFilter='', [int]$TimeoutSeconds=120,
 [string]$DnSpyDirectory=$env:DNSPY_HOME, [string]$ReferenceDirectory='')
$ErrorActionPreference='Stop'
if(-not $DnSpyDirectory){throw 'Supply -DnSpyDirectory or set DNSPY_HOME to a trusted dnSpy installation'}
$bin=(Resolve-Path -LiteralPath $DnSpyDirectory).Path
if(Test-Path -LiteralPath (Join-Path $bin 'bin\ICSharpCode.Decompiler.dll')){$bin=Join-Path $bin 'bin'}
if(-not(Test-Path -LiteralPath (Join-Path $bin 'ICSharpCode.Decompiler.dll'))){throw 'dnSpy decompiler DLL not found'}
$InputFile=(Resolve-Path -LiteralPath $InputFile).Path
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
if(Test-Path -LiteralPath $OutputDirectory){throw 'Choose a NEW source output directory'}
[Reflection.Assembly]::LoadFrom((Join-Path $bin 'dnlib.dll'))|Out-Null
[Reflection.Assembly]::LoadFrom((Join-Path $bin 'ICSharpCode.Decompiler.dll'))|Out-Null
$contracts=[Reflection.Assembly]::LoadFrom((Join-Path $bin 'dnSpy.Contracts.Logic.dll'))
$moduleContext=[dnlib.DotNet.ModuleDef]::CreateModuleContext()
$moduleContext.AssemblyResolver.PreSearchPaths.Add((Split-Path -Parent $InputFile))
if($ReferenceDirectory){$moduleContext.AssemblyResolver.PreSearchPaths.Add((Resolve-Path -LiteralPath $ReferenceDirectory).Path)}
$moduleContext.AssemblyResolver.PreSearchPaths.Add($bin)
$module=[dnlib.DotNet.ModuleDefMD]::Load($InputFile,$moduleContext)
$provider=[dnSpy.Contracts.Decompiler.CSharpMetadataTextColorProvider]::Instance
New-Item -ItemType Directory -Path $OutputDirectory -ErrorAction Stop|Out-Null
$records=[Collections.Generic.List[object]]::new()
$index=0
foreach($type in $module.Types){
 if($type.IsGlobalModuleType){continue}
 if($TypeFilter -and $type.FullName -ne $TypeFilter){continue}
 $index++
 $started=[DateTime]::UtcNow
 $safeName=([regex]::Replace($type.FullName,'[^A-Za-z0-9_.-]','_'))
 if($safeName.Length -gt 90){$safeName=$safeName.Substring(0,90)}
 $file=Join-Path $OutputDirectory ('T'+$type.MDToken.Rid.ToString('0000')+'_'+$safeName+'.cs')
 $status='';$errorText='';$text=''
 $cts=[Threading.CancellationTokenSource]::new();$cts.CancelAfter([TimeSpan]::FromSeconds($TimeoutSeconds))
 try {
   $context=[ICSharpCode.Decompiler.DecompilerContext]::new(0,$module,$provider)
   $context.Settings=[ICSharpCode.Decompiler.DecompilerSettings]::new()
   $context.CancellationToken=$cts.Token
   $context.CurrentType=$type
   $builder=[ICSharpCode.Decompiler.Ast.AstBuilder]::new($context)
   $builder.AddType($type)
   $builder.RunTransformations()
   $output=[dnSpy.Contracts.Decompiler.StringBuilderDecompilerOutput]::new()
   $builder.GenerateCode($output)
   $text=$output.ToString()
   [IO.File]::WriteAllText($file,$text,[Text.UTF8Encoding]::new($false))
   $status='CSharpExported'
 } catch {
   $status='Error';$errorText=$_.Exception.ToString()
   [IO.File]::WriteAllText($file+'.error.txt',$errorText,[Text.UTF8Encoding]::new($false))
 } finally {$cts.Dispose()}
 $entry=[ordered]@{type=$type.FullName;token=$type.MDToken.ToString();file=$file;status=$status;characters=$text.Length;elapsed_seconds=[math]::Round(([DateTime]::UtcNow-$started).TotalSeconds,3);error=$errorText}
 $records.Add($entry)
 @($records.ToArray())|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $OutputDirectory 'index.json') -Encoding utf8
 Write-Output ('EXPORTED '+$index+' '+$type.FullName+' '+$status+' '+$text.Length)
}
$summary=[ordered]@{event='static_dnspy_source_export';input=$InputFile;input_sha256=(Get-FileHash -LiteralPath $InputFile).Hash.ToLower();assembly=$module.Assembly.FullName;declared_types=@($module.GetTypes()).Count;top_level_requested=$records.Count;exported=@($records|Where-Object{$_.status -eq 'CSharpExported'}).Count;errors=@($records|Where-Object{$_.status -eq 'Error'}).Count;target_executed=$false;csharp_compiled=$false;engine='Installed dnSpy ICSharpCode.Decompiler and dnlib; reflection invokes decompiler only'}
$summary|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $OutputDirectory 'summary.json') -Encoding utf8
$summary|ConvertTo-Json
if($summary.errors -gt 0){exit 2}
