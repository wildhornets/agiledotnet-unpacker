param([Parameter(Mandatory=$true)][string]$SourceDirectory, [Parameter(Mandatory=$true)][string]$Destination, [string]$DnlibPath='')
$ErrorActionPreference='Stop'
$src=(Resolve-Path -LiteralPath $SourceDirectory).Path
if(Test-Path -LiteralPath $Destination){throw 'Destination exists'}
New-Item -ItemType Directory -Path $Destination|Out-Null
Get-ChildItem -LiteralPath $src -File|ForEach-Object{Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $Destination $_.Name)}
. (Join-Path $PSScriptRoot '..\cleanup-tools\load_dnlib.ps1') -DnlibPath $DnlibPath
$m=[dnlib.DotNet.ModuleDefMD]::Load((Join-Path $src 'AgileDevirtualizer.dll'))
$t=@($m.GetTypes()|Where-Object{$_.FullName -eq 'AgileDevirtualizer.Lift.ExecuteInterpreter'})[0]
$q=@($t.Methods|Where-Object{$_.Name -eq 'TryHandlePointerValueAccess_StaticPatch'})[0]
$body=$q.Body;$anchor=$body.Instructions[11]
if($anchor.OpCode.Code -ne [dnlib.DotNet.Emit.Code]::Ldarg_0){throw 'Anchor mismatch'}
$no=$body.Instructions[$body.Instructions.Count-3]
$instrField=@($t.Fields|Where-Object{$_.Name -eq '_instr'})[0]
$opcodeField=@($instrField.FieldSig.Type.TypeDefOrRef.Fields|Where-Object{$_.Name -eq 'Opcode'})[0]
if($null -eq $opcodeField){throw 'Opcode field missing'}
$prefix=[dnlib.DotNet.Emit.CilBody]::new()
function AddI([string]$op,$operand=$null){$c=[dnlib.DotNet.Emit.OpCodes].GetField($op).GetValue($null);$i=[dnlib.DotNet.Emit.Instruction]::new($c);if($null -ne $operand){$i.Operand=$operand};$prefix.Instructions.Add($i)}
AddI Ldarg_0;AddI Ldfld $instrField;AddI Ldfld $opcodeField;AddI Ldc_I4 203;AddI Beq $anchor
AddI Ldarg_0;AddI Ldfld $instrField;AddI Ldfld $opcodeField;AddI Ldc_I4 572;AddI Bne_Un $no
for($i=$prefix.Instructions.Count-1;$i -ge 0;$i--){$body.Instructions.Insert(11,$prefix.Instructions[$i])}
$body.SimplifyBranches();$body.OptimizeBranches();$body.KeepOldMaxStack=$false
$out=Join-Path $Destination 'AgileDevirtualizer.dll';$options=[dnlib.DotNet.Writer.ModuleWriterOptions]::new($m);$options.MetadataOptions.Flags=[dnlib.DotNet.Writer.MetadataFlags]::PreserveAll
$m.Write($out,$options)
$check=[dnlib.DotNet.ModuleDefMD]::Load($out)
$record=[ordered]@{event='scope_pointer_value_reads_to_proven_top_stack_patterns';method=[string]$q.FullName;opcodes=@(203,572);reason='Do not dereference a buried reflection receiver; only the validated value-read idioms';source=(Join-Path $src 'AgileDevirtualizer.dll');modified=$out;sha256=(Get-FileHash -LiteralPath $out).Hash.ToLower();compiler_executed=$false;target_executed=$false;reopened=$true}
$record|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $Destination 'patch-scope-provenance.json') -Encoding utf8
$record|ConvertTo-Json
