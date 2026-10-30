param(
 [Parameter(Mandatory=$true)][string]$InputDirectory,
 [Parameter(Mandatory=$true)][string]$OutputDirectory,
 [string]$DnlibPath='')
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'load_dnlib.ps1') -DnlibPath $DnlibPath
$input=Join-Path $InputDirectory 'SeroXen.unpacked.bin';$runtime=Join-Path $InputDirectory 'C5VM.dll'
if((Get-FileHash -LiteralPath $input).Hash.ToLower() -ne 'afcfdb41a738192f54d1937910f48401d00fc294ba03243811e17dea76487f6f'){throw 'Unconfirmed baseline'}
if((Get-FileHash -LiteralPath $runtime).Hash.ToLower() -ne 'a5a84dcecaa6b9acd06c67e53d56b20dbf99e246b1937f3ce643b9163a4a1d2e'){throw 'Unconfirmed companion'}
if(Test-Path -LiteralPath $OutputDirectory){throw 'Output exists'}
New-Item -ItemType Directory -Path $OutputDirectory|Out-Null
$m=[dnlib.DotNet.ModuleDefMD]::Load($input);$rt=[dnlib.DotNet.ModuleDefMD]::Load($runtime)
# Preserve the recorded stack header on untouched source bodies. Inlined bodies
# explicitly clear this flag and must pass dnlib's max-stack computation.
foreach($sourceType in $m.GetTypes()){foreach($sourceMethod in $sourceType.Methods){if($sourceMethod.HasBody){$sourceMethod.Body.KeepOldMaxStack=$true}}}
$importer=[dnlib.DotNet.Importer]::new($m,[dnlib.DotNet.ImporterOptions]::TryToUseDefs)
$typeMap=@{};$methodMap=@{};$fieldMap=@{};$sourceMethods=@{}
foreach($t in $rt.GetTypes()){foreach($q in $t.Methods){$sourceMethods[$q.FullName]=$q}}
$errorMessage='An internal error occurred during CSVM method execution.'
$pureTypeNames=@('l3U=.0HU=','l3U=.6HU=','l3U=.JHY=','l3U=.tHU=','l3U=.w3U=','VMRuntime.Libraries.CSVMRuntimeException','l3U=.2nU=','l3U=.zXU=')
$descriptive=@{'l3U=.0HU='='ComparisonOperations';'l3U=.6HU='='NumericConversions';'l3U=.JHY='='UnaryOperations';'l3U=.tHU='='ShiftOperations';'l3U=.w3U='='BinaryOperations';'VMRuntime.Libraries.CSVMRuntimeException'='RecoveredOperationException';'l3U=.2nU='='ConversionKind';'l3U=.zXU='='UnorderedComparisonMode'}
function ImportType($t){
 if($null -eq $t){return $null}
 if($t.DefinitionAssembly.Name -eq 'C5VM'){
  if(-not $typeMap.ContainsKey($t.FullName)){throw ('Unapproved helper type '+$t.FullName)}
  return $typeMap[$t.FullName]
 }
 return $importer.Import([dnlib.DotNet.ITypeDefOrRef]$t)
}
function ImportSig($s){
 if($null -eq $s){return $null}
 switch($s.ElementType.ToString()){
  'Class' {return [dnlib.DotNet.ClassSig]::new((ImportType $s.TypeDefOrRef))}
  'ValueType' {return [dnlib.DotNet.ValueTypeSig]::new((ImportType $s.TypeDefOrRef))}
  'SZArray' {return [dnlib.DotNet.SZArraySig]::new((ImportSig $s.Next))}
  'ByRef' {return [dnlib.DotNet.ByRefSig]::new((ImportSig $s.Next))}
  'Ptr' {return [dnlib.DotNet.PtrSig]::new((ImportSig $s.Next))}
  'Pinned' {return [dnlib.DotNet.PinnedSig]::new((ImportSig $s.Next))}
  'GenericInst' {
    $g=[dnlib.DotNet.GenericInstSig]::new((ImportSig $s.GenericType))
    foreach($a in $s.GenericArguments){$g.GenericArguments.Add((ImportSig $a))};return $g
  }
  default {return $importer.Import([dnlib.DotNet.TypeSig]$s)}
 }
}
function ImportMethodSig($s){
 $p=[dnlib.DotNet.TypeSig[]]@($s.Params|ForEach-Object{ImportSig $_})
 if($s.HasThis){$new=[dnlib.DotNet.MethodSig]::CreateInstance((ImportSig $s.RetType),$p)}
 else{$new=[dnlib.DotNet.MethodSig]::CreateStatic((ImportSig $s.RetType),$p)}
 $new.GenParamCount=$s.GenParamCount;return $new
}
foreach($name in $pureTypeNames){
 $src=@($rt.GetTypes()|Where-Object{$_.FullName -eq $name})[0]
 if($null -eq $src){throw ('Type not found '+$name)}
 $dst=[dnlib.DotNet.TypeDefUser]::new('Recovered.Support',$descriptive[$name],(ImportType $src.BaseType))
 $dst.Attributes=$src.Attributes;$m.Types.Add($dst);$typeMap[$name]=$dst
}
foreach($name in @('l3U=.2nU=','l3U=.zXU=')){
 $src=@($rt.GetTypes()|Where-Object{$_.FullName -eq $name})[0]
 foreach($f in $src.Fields){
  $dst=[dnlib.DotNet.FieldDefUser]::new($f.Name,[dnlib.DotNet.FieldSig]::new((ImportSig $f.FieldSig.Type)),$f.Attributes)
  if($f.HasConstant){$dst.Constant=[dnlib.DotNet.ConstantUser]::new($f.Constant.Value)}
  $typeMap[$name].Fields.Add($dst);$fieldMap[$f.FullName]=$dst
 }
}
$audit=Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'helper-closure.json')|ConvertFrom-Json
$selected=@($audit.closure|Where-Object{$pureTypeNames -contains ([regex]::Match($_.method,' ([^ ]+)::').Groups[1].Value)})
foreach($row in $selected){
 $src=$sourceMethods[$row.method]
 if(-not $src.HasBody -or $src.IsPinvokeImpl){throw 'Refuse non-managed helper'}
 $dst=[dnlib.DotNet.MethodDefUser]::new($src.Name,(ImportMethodSig $src.MethodSig),$src.ImplAttributes,$src.Attributes)
 foreach($p in $src.ParamDefs){$dst.ParamDefs.Add([dnlib.DotNet.ParamDefUser]::new($p.Name,$p.Sequence,$p.Attributes))}
 $typeMap[$src.DeclaringType.FullName].Methods.Add($dst);$methodMap[$src.FullName]=$dst
}
if($methodMap.Count -ne 16){throw ('Expected 14 arithmetic methods +2 constructors, got '+$methodMap.Count)}

function ImportOperand($o){
 if($o -is [dnlib.DotNet.IMethod]){
  if($o.DeclaringType.DefinitionAssembly.Name -eq 'C5VM'){
   if(-not $methodMap.ContainsKey($o.FullName)){throw ('Unapproved helper method '+$o.FullName)}
   return $methodMap[$o.FullName]
  }
  return $importer.Import([dnlib.DotNet.IMethod]$o)
 }
 if($o -is [dnlib.DotNet.IField]){
  if($o.DeclaringType.DefinitionAssembly.Name -eq 'C5VM'){
   if(-not $fieldMap.ContainsKey($o.FullName)){throw ('Unapproved helper field '+$o.FullName)}
   return $fieldMap[$o.FullName]
  }
  return $importer.Import([dnlib.DotNet.IField]$o)
 }
 if($o -is [dnlib.DotNet.ITypeDefOrRef]){return ImportType $o}
 if($o -is [dnlib.DotNet.TypeSig]){return ImportSig $o}
 return $o
}
# Decode two proven metadata-only error strings, never loading the runtime assembly.
$codec=@($rt.GetTypes()|Where-Object{$_.FullName -eq '<C5VM86>'})[0]
$cctor=@($codec.Methods|Where-Object{$_.IsStaticConstructor})[0]
$key=@($cctor.Body.Instructions|Where-Object{$_.OpCode.Code -eq [dnlib.DotNet.Emit.Code]::Ldtoken})[0].Operand.InitialValue
function DecodeString([string]$s){$c=$s.ToCharArray();for($j=0;$j -lt $c.Length;$j++){$c[$j]=[char]([int]$c[$j] -bxor [int]$key[$j%$key.Length])};return -join $c}
$literalFolds=[Collections.Generic.List[object]]::new()
foreach($name in $methodMap.Keys){
 $src=$sourceMethods[$name];$dst=$methodMap[$name];$body=[dnlib.DotNet.Emit.CilBody]::new();$body.InitLocals=$src.Body.InitLocals;$dst.Body=$body
 foreach($l in $src.Body.Variables){$body.Variables.Add([dnlib.DotNet.Emit.Local]::new((ImportSig $l.Type)))|Out-Null}
 $map=[Collections.Generic.Dictionary[dnlib.DotNet.Emit.Instruction,dnlib.DotNet.Emit.Instruction]]::new()
 foreach($old in $src.Body.Instructions){$copy=[dnlib.DotNet.Emit.Instruction]::new($old.OpCode);$body.Instructions.Add($copy);$map.Add($old,$copy)}
 for($j=0;$j -lt $src.Body.Instructions.Count;$j++){
  $old=$src.Body.Instructions[$j];$copy=$map[$old];$o=$old.Operand
  if($o -is [dnlib.DotNet.IMethod] -and $o.FullName -eq 'System.String l3U=.VnY=::XHY=()'){
   $copy.OpCode=[dnlib.DotNet.Emit.OpCodes]::Ldstr;$copy.Operand=$errorMessage;$literalFolds.Add([ordered]@{method=$name;offset=$old.Offset;value=$errorMessage});continue
  }
  if($o -is [dnlib.DotNet.IMethod] -and $o.FullName -eq 'System.String <C5VM86>::zoY=(System.String)'){
   $previous=$src.Body.Instructions[$j-1]
   if($previous.OpCode.Code -ne [dnlib.DotNet.Emit.Code]::Ldstr){throw 'Nonliteral error format'}
   $decoded=DecodeString $previous.Operand
   if($decoded -ne '{0}'){throw 'Unexpected exception format'}
   $map[$previous].Operand=$decoded;$copy.OpCode=[dnlib.DotNet.Emit.OpCodes]::Nop;$literalFolds.Add([ordered]@{method=$name;offset=$old.Offset;value=$decoded});continue
  }
  if($o -is [dnlib.DotNet.Emit.Instruction]){$copy.Operand=$map[$o]}
  elseif($o -is [Collections.Generic.IList[dnlib.DotNet.Emit.Instruction]]){$copy.Operand=[dnlib.DotNet.Emit.Instruction[]]@($o|ForEach-Object{$map[$_]})}
  elseif($o -is [dnlib.DotNet.Emit.Local]){$copy.Operand=$body.Variables[$o.Index]}
  elseif($o -is [dnlib.DotNet.Parameter]){$copy.Operand=$dst.Parameters[$o.Index]}
  else{$copy.Operand=ImportOperand $o}
 }
 foreach($h in $src.Body.ExceptionHandlers){
  $e=[dnlib.DotNet.Emit.ExceptionHandler]::new($h.HandlerType)
  foreach($p in @('TryStart','TryEnd','HandlerStart','HandlerEnd','FilterStart')){if($null -ne $h.$p){$e.$p=$map[$h.$p]}}
  if($h.CatchType){$e.CatchType=ImportType $h.CatchType};$body.ExceptionHandlers.Add($e)
 }
}

$static=[Collections.Generic.HashSet[dnlib.DotNet.MethodDef]]::new()
foreach($q in $methodMap.Values){if($q.IsStatic){$static.Add($q)|Out-Null}}
$inlineRecords=[Collections.Generic.List[object]]::new()
function InlineOne($caller,$call,$callee){
 if(-not $callee.IsStatic -or $callee.MethodSig.HasThis -or $callee.MethodSig.GenParamCount){throw 'Only concrete static arithmetic methods may inline'}
 $body=$caller.Body;$args=[Collections.Generic.List[dnlib.DotNet.Emit.Local]]::new();$locals=[Collections.Generic.List[dnlib.DotNet.Emit.Local]]::new()
 foreach($s in $callee.MethodSig.Params){$l=[dnlib.DotNet.Emit.Local]::new($s);$body.Variables.Add($l)|Out-Null;$args.Add($l)}
 foreach($v in $callee.Body.Variables){$l=[dnlib.DotNet.Emit.Local]::new($v.Type);$body.Variables.Add($l)|Out-Null;$locals.Add($l)}
 $sequence=[Collections.Generic.List[dnlib.DotNet.Emit.Instruction]]::new()
 for($j=$args.Count-1;$j -ge 0;$j--){$sequence.Add([dnlib.DotNet.Emit.Instruction]::Create([dnlib.DotNet.Emit.OpCodes]::Stloc,$args[$j]))}
 $map=[Collections.Generic.Dictionary[dnlib.DotNet.Emit.Instruction,dnlib.DotNet.Emit.Instruction]]::new()
 $end=[dnlib.DotNet.Emit.Instruction]::Create([dnlib.DotNet.Emit.OpCodes]::Nop)
 foreach($old in $callee.Body.Instructions){$copy=[dnlib.DotNet.Emit.Instruction]::new($old.OpCode);$sequence.Add($copy);$map.Add($old,$copy)}
 foreach($old in $callee.Body.Instructions){
  $copy=$map[$old];$code=$old.OpCode.Code.ToString();$o=$old.Operand
  if($code -eq 'Ret'){$copy.OpCode=[dnlib.DotNet.Emit.OpCodes]::Br;$copy.Operand=$end;continue}
  if($code -match '^Ldarg_([0-3])$'){$copy.OpCode=[dnlib.DotNet.Emit.OpCodes]::Ldloc;$copy.Operand=$args[[int]$Matches[1]];continue}
  if($code -in @('Ldarg','Ldarg_S','Ldarga','Ldarga_S','Starg','Starg_S')){
   $index=if($o -is [dnlib.DotNet.Parameter]){$o.Index}else{[int]$o}
   $copy.OpCode=if($code.StartsWith('Ldarga')){[dnlib.DotNet.Emit.OpCodes]::Ldloca}elseif($code.StartsWith('Starg')){[dnlib.DotNet.Emit.OpCodes]::Stloc}else{[dnlib.DotNet.Emit.OpCodes]::Ldloc}
   $copy.Operand=$args[$index];continue
  }
  if($code -match '^(Ldloc|Stloc)_([0-3])$'){$copy.OpCode=if($Matches[1] -eq 'Ldloc'){[dnlib.DotNet.Emit.OpCodes]::Ldloc}else{[dnlib.DotNet.Emit.OpCodes]::Stloc};$copy.Operand=$locals[[int]$Matches[2]];continue}
  if($o -is [dnlib.DotNet.Emit.Local]){$copy.Operand=$locals[$o.Index]}
  elseif($o -is [dnlib.DotNet.Emit.Instruction]){$copy.Operand=$map[$o]}
  elseif($o -is [Collections.Generic.IList[dnlib.DotNet.Emit.Instruction]]){$copy.Operand=[dnlib.DotNet.Emit.Instruction[]]@($o|ForEach-Object{$map[$_]})}
  else{$copy.Operand=$o}
 }
 $sequence.Add($end)
 foreach($h in $callee.Body.ExceptionHandlers){
  $e=[dnlib.DotNet.Emit.ExceptionHandler]::new($h.HandlerType);$e.CatchType=$h.CatchType
  foreach($p in @('TryStart','TryEnd','HandlerStart','HandlerEnd','FilterStart')){if($null -ne $h.$p){$e.$p=$map[$h.$p]}elseif($p -in @('TryEnd','HandlerEnd')){$e.$p=$end}}
  $body.ExceptionHandlers.Add($e)
 }
 $at=$body.Instructions.IndexOf($call);$call.OpCode=[dnlib.DotNet.Emit.OpCodes]::Nop;$call.Operand=$null
 for($j=0;$j -lt $sequence.Count;$j++){$body.Instructions.Insert($at+1+$j,$sequence[$j])}
 $body.KeepOldMaxStack=$false
 $inlineRecords.Add([ordered]@{caller=$caller.FullName;callee=$callee.FullName;argument_locals=@($args|ForEach-Object{$_.Index});cloned_instructions=$callee.Body.Instructions.Count;cloned_exception_handlers=$callee.Body.ExceptionHandlers.Count})
}
# First flatten the pure helper graph, then its twelve application call sites.
for($pass=0;$pass -lt 20;$pass++){
 $count=0
 foreach($caller in @($static)){
  foreach($i in @($caller.Body.Instructions)){
   if($i.OpCode.Code -eq [dnlib.DotNet.Emit.Code]::Call -and $i.Operand -is [dnlib.DotNet.MethodDef] -and $static.Contains($i.Operand)){
    if($i.Operand -eq $caller){throw 'Recursive helper graph'};InlineOne $caller $i $i.Operand;$count++
   }
  }
 }
 if($count -eq 0){break}
 if($pass -eq 19){throw 'Helper graph did not flatten'}
}
$direct=0
foreach($t in @($m.GetTypes())){foreach($caller in @($t.Methods)){
 if(-not $caller.HasBody -or $static.Contains($caller)){continue}
 foreach($i in @($caller.Body.Instructions)){
  $o=$i.Operand
  if($i.OpCode.Code -eq [dnlib.DotNet.Emit.Code]::Call -and $o -is [dnlib.DotNet.IMethod] -and $o.DeclaringType.DefinitionAssembly.Name -eq 'C5VM'){
   if(-not $methodMap.ContainsKey($o.FullName)){throw ('Unmapped direct call '+$o.FullName)}
   InlineOne $caller $i $methodMap[$o.FullName];$direct++
  }
 }
}}
if($direct -ne 12){throw ('Expected12 direct arithmetic sites, got'+$direct)}
foreach($name in @('l3U=.0HU=','l3U=.6HU=','l3U=.JHY=','l3U=.tHU=','l3U=.w3U=')){$m.Types.Remove($typeMap[$name])|Out-Null}

$native=@($m.GetTypes()|Where-Object{$_.FullName -eq '<C5VM86>'})[0]
$removedHooks=0
foreach($t in @($m.GetTypes())){if($t -eq $native -or $t.DeclaringType -eq $native){continue};foreach($q in $t.Methods){if(-not $q.HasBody){continue};foreach($i in $q.Body.Instructions){
 $o=$i.Operand
 if($o -is [dnlib.DotNet.IMethod] -and $o.DeclaringType -eq $native){
  if($o.Name -notin @('Initialize','PostInitialize') -or $o.MethodSig.Params.Count -ne 0){throw ('Unexpected native dependency '+$o.FullName)}
  $i.OpCode=[dnlib.DotNet.Emit.OpCodes]::Nop;$i.Operand=$null;$removedHooks++
 }
}}}
if($removedHooks -ne 464){throw ('Unexpected hook count '+$removedHooks)}
$m.Types.Remove($native)|Out-Null
$removedResources=@('640b4456-ab98-4d0e-ad90-be8a8a0e5747','e598627d-8851-4529-8c98-58e978071e98')
foreach($name in $removedResources){
 foreach($t in $m.GetTypes()){foreach($q in $t.Methods){if($q.HasBody -and @($q.Body.Instructions|Where-Object{$_.Operand -is [string] -and $_.Operand -eq $name}).Count){throw ('Resource still referenced '+$name)}}}
 $r=@($m.Resources|Where-Object{$_.Name.ToString() -eq $name});if($r.Count -ne 1){throw 'Resource not unique'};$m.Resources.Remove($r[0])|Out-Null
}
foreach($t in $m.GetTypes()){foreach($q in $t.Methods){if($q.HasBody){$q.Body.SimplifyBranches();$q.Body.OptimizeBranches()}}}
$output=Join-Path $OutputDirectory 'helperfree.bin'
$opts=[dnlib.DotNet.Writer.ModuleWriterOptions]::new($m)
$m.Write($output,$opts)
$check=[dnlib.DotNet.ModuleDefMD]::Load($output)
$remaining=@($check.GetAssemblyRefs()|Where-Object{$_.Name.ToString() -like '*C5VM*'})
$nativeImports=@($check.GetTypes()|ForEach-Object{$_.Methods}|Where-Object{$_.IsPinvokeImpl -and $_.ImplMap.Module.Name.ToString() -like '*C5VM*'})
if($remaining.Count -or $nativeImports.Count){throw 'C5VM dependency survived write'}
$record=[ordered]@{event='static_c5vm_removal_completed';input=$input;input_sha256=(Get-FileHash -LiteralPath $input).Hash.ToLower();output=$output;output_sha256=(Get-FileHash -LiteralPath $output).Hash.ToLower();direct_calls_inlined=$direct;inline_expansions=$inlineRecords.Count;inline_records=@($inlineRecords.ToArray());literal_error_folds=@($literalFolds.ToArray());protection_init_calls_removed=$removedHooks;native_loader_type_removed=$true;native_payload_resources_removed=$removedResources;remaining_c5vm_assembly_refs=$remaining.Count;remaining_c5vm_pinvoke=$nativeImports.Count;source_unchanged=((Get-FileHash -LiteralPath $input).Hash.ToLower() -eq 'afcfdb41a738192f54d1937910f48401d00fc294ba03243811e17dea76487f6f');target_executed=$false;application_compiled=$false;limitation='Static IL transformation; original runtime behaviour is not claimed without isolated execution tests.'}
$record|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $OutputDirectory 'helper-removal.json') -Encoding utf8
[pscustomobject]$record|Select-Object event,output,output_sha256,direct_calls_inlined,inline_expansions,protection_init_calls_removed,remaining_c5vm_assembly_refs,remaining_c5vm_pinvoke,source_unchanged|ConvertTo-Json
