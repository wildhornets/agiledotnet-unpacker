param(
 [Parameter(Mandatory=$true)][string]$InputFile,
 [Parameter(Mandatory=$true)][string]$OutputDirectory,
 [string]$DnlibPath='', [string]$ReferenceDirectory='')
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'load_dnlib.ps1') -DnlibPath $DnlibPath
if(Test-Path -LiteralPath $OutputDirectory){throw 'Output exists'}
New-Item -ItemType Directory -Path $OutputDirectory|Out-Null
$context=[dnlib.DotNet.ModuleDef]::CreateModuleContext()
if($ReferenceDirectory){$context.AssemblyResolver.PreSearchPaths.Add((Resolve-Path -LiteralPath $ReferenceDirectory).Path)}
$context.AssemblyResolver.PreSearchPaths.Add((Split-Path -Parent $InputFile))
$m=[dnlib.DotNet.ModuleDefMD]::Load($InputFile,$context)
$context.AssemblyResolver.AddToCache($m)|Out-Null
$types=@($m.GetTypes());$methods=@($types|ForEach-Object{$_.Methods})
$oldNames=[Collections.Generic.Dictionary[object,string]]::new()
$oldFull=[Collections.Generic.Dictionary[object,string]]::new()
$methodKeys=[Collections.Generic.Dictionary[object,string]]::new()
foreach($t in $types){$oldNames[$t]=$t.Name.ToString();$oldFull[$t]=$t.FullName;foreach($collection in @($t.Methods,$t.Fields,$t.Properties,$t.Events)){foreach($d in $collection){$oldNames[$d]=$d.Name.ToString();$oldFull[$d]=$d.FullName}}}
foreach($q in $methods){$methodKeys[$q]=$q.Name.ToString()+'|'+$q.MethodSig.ToString()}
function IsObfuscated([string]$name){
 if($name -in @('.ctor','.cctor','value__','<Module>')){return $false}
 if($name -match '^(<.*>|CS\$<.*>|\$?VB\$.*)'){return $false}
 return $name -notmatch '^[_A-Za-z][_A-Za-z0-9]*(?:`[0-9]+)?$'
}
function Safe([string]$name){$s=[regex]::Replace($name,'[^A-Za-z0-9_]','_');if($s -notmatch '^[A-Za-z_]'){$s='Item_'+$s};return $s}
$records=[Collections.Generic.List[object]]::new()
function Record($def,[string]$kind,[string]$reason,[string]$oldName,[string]$newName){
 if($oldName -eq $newName){return}
 $records.Add([ordered]@{kind=$kind;old_name=$oldName;new_name=$newName;old_full_name=$oldFull[$def];original_token=$def.MDToken.ToString();reason=$reason;definition=$def})
}

# Capture all self-member/type references before any names change.
$bindings=[Collections.Generic.List[object]]::new();$typeBindings=[Collections.Generic.List[object]]::new();$unresolved=[Collections.Generic.List[string]]::new()
foreach($r in $m.GetMemberRefs()){
 if($r.DeclaringType.DefinitionAssembly.Name.ToString() -ne $m.Assembly.Name.ToString()){continue}
 try{$d=$r.Resolve();if($d -and $d.Module -eq $m){$bindings.Add(@($r,$d))}else{$unresolved.Add($r.FullName)}}catch{$unresolved.Add($r.FullName)}
}
foreach($r in $m.GetTypeRefs()){
 if($r.DefinitionAssembly.Name.ToString() -ne $m.Assembly.Name.ToString()){continue}
 try{$d=$r.Resolve();if($d -and $d.Module -eq $m){$typeBindings.Add(@($r,$d))}else{$unresolved.Add($r.FullName)}}catch{$unresolved.Add($r.FullName)}
}
if($unresolved.Count){$unresolved|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $OutputDirectory 'unresolved-self-references.json');throw ('Unresolved self references '+$unresolved.Count)}

# Recover control identities only from exact setter instruction patterns.
$fieldHints=@{};$formHints=@{};$methodHints=@{};$hintReasons=@{}
foreach($q in $methods){if(-not $q.HasBody){continue};$il=$q.Body.Instructions
 for($i=1;$i -lt $il.Count;$i++){
  $o=$il[$i].Operand
  if($o -is [dnlib.DotNet.IMethod] -and $o.Name -eq 'set_Name' -and $il[$i-1].OpCode.Code -eq [dnlib.DotNet.Emit.Code]::Ldstr){
   $text=[string]$il[$i-1].Operand
   if($text -notmatch '^[A-Za-z_][A-Za-z0-9_]{0,70}$'){continue}
   $k=$i-2
   while($k -ge 0 -and $il[$k].OpCode.Code -in @([dnlib.DotNet.Emit.Code]::Castclass,[dnlib.DotNet.Emit.Code]::Nop)){$k--}
   if($k -ge 0 -and $il[$k].OpCode.Code -eq [dnlib.DotNet.Emit.Code]::Ldfld -and $il[$k].Operand -is [dnlib.DotNet.FieldDef]){
    $f=$il[$k].Operand;if($f.DeclaringType -eq $q.DeclaringType){$fieldHints[$f]=$text}
   }elseif($k -ge 0 -and $il[$k].OpCode.Code -eq [dnlib.DotNet.Emit.Code]::Ldarg_0 -and -not $q.IsStatic){$formHints[$oldFull[$q.DeclaringType]]=$text}
  }
 }
}
foreach($q in $methods){
 foreach($ca in $q.CustomAttributes){
  if($ca.TypeFullName -eq 'System.Runtime.CompilerServices.AsyncStateMachineAttribute' -and $ca.ConstructorArguments.Count -eq 1){
   $state=$ca.ConstructorArguments[0].Value
   if($state -is [dnlib.DotNet.TypeSig] -and $state.TypeDefOrRef.Name.ToString() -match '^<([A-Za-z_][A-Za-z0-9_]*)>d__'){
    $methodHints[$q]=$Matches[1];$hintReasons[$q]='recovered: async state-machine metadata'
   }
  }
 }
}
# A control/event binding provides a descriptive name, not proof of the original name.
foreach($q in $methods){if(-not $q.HasBody){continue};$il=$q.Body.Instructions
 for($i=0;$i -lt $il.Count;$i++){
  $o=$il[$i].Operand
  if($o -isnot [dnlib.DotNet.IMethod] -or $o.Name.ToString() -notmatch '^add_([A-Za-z_][A-Za-z0-9_]*)$'){continue};$event=$Matches[1]
  $window=@($il|Select-Object -Skip ([math]::Max(0,$i-9)) -First ([math]::Min(9,$i)))
  $fn=@($window|Where-Object{$_.OpCode.Code -in @([dnlib.DotNet.Emit.Code]::Ldftn,[dnlib.DotNet.Emit.Code]::Ldvirtftn) -and $_.Operand -is [dnlib.DotNet.MethodDef]})
  $fields=@($window|Where-Object{$_.OpCode.Code -eq [dnlib.DotNet.Emit.Code]::Ldfld -and $_.Operand -is [dnlib.DotNet.FieldDef]})
  if($fn.Count -eq 1 -and $fields.Count -eq 1){$target=$fn[0].Operand;$f=$fields[0].Operand
   if($fieldHints.ContainsKey($f) -and -not $methodHints.ContainsKey($target)){$methodHints[$target]=$fieldHints[$f]+'_'+$event;$hintReasons[$target]='inferred: verified control/event binding'}
  }
 }
}
$methodHints[$m.EntryPoint]='Main';$hintReasons[$m.EntryPoint]='metadata: assembly entry point'
$cryptoMethod=@($methods|Where-Object{$oldFull[$_] -eq 'System.Byte[] ohM=.zhM=::wxM=(ohM=.yxM=,System.Byte[],System.Byte[],System.Byte[])'})[0]
if($cryptoMethod){$methodHints[$cryptoMethod]='TransformBytes';$hintReasons[$cryptoMethod]='inferred: Aes CreateEncryptor / XOR implementation'}

# Drop now-unused delegate-token initialization: renaming its encoded field names
# would otherwise make that dead initializer fail. Only unreferenced proxy fields qualify.
$proxyRemoved=0
$proxyResolvers=[Collections.Generic.HashSet[dnlib.DotNet.TypeDef]]::new()
$externallyUsedFields=[Collections.Generic.HashSet[string]]::new()
foreach($q in $methods){if(-not $q.HasBody){continue};foreach($i in $q.Body.Instructions){$o=$i.Operand;if($o -is [dnlib.DotNet.IField] -and $q.DeclaringType.FullName -ne $o.DeclaringType.FullName){$externallyUsedFields.Add($o.FullName)|Out-Null}}}
foreach($t in $types){
 if($t.BaseType.FullName -ne 'System.MulticastDelegate'){continue}
 $fields=@($t.Fields|Where-Object{$_.IsStatic});if(-not $fields.Count){continue}
 $used=@($fields|Where-Object{$externallyUsedFields.Contains($_.FullName)}).Count -gt 0
 if($used){continue}
 foreach($q in $t.Methods){if(-not $q.IsStaticConstructor -or -not $q.HasBody){continue};foreach($i in $q.Body.Instructions){$o=$i.Operand
  if($i.OpCode.Code -ne [dnlib.DotNet.Emit.Code]::Call -or $o -isnot [dnlib.DotNet.MethodDef] -or -not $o.HasBody){continue}
  $hasDecode=@($o.Body.Instructions|Where-Object{$_.Operand -is [dnlib.DotNet.IMethod] -and $_.Operand.FullName -like '*System.Convert::FromBase64String*'}).Count -gt 0
  if($hasDecode -and $o.MethodSig.Params.Count -eq 1 -and $o.MethodSig.Params[0].FullName -eq 'System.RuntimeTypeHandle' -and $o.MethodSig.RetType.FullName -eq 'System.Void'){$i.OpCode=[dnlib.DotNet.Emit.OpCodes]::Pop;$i.Operand=$null;$proxyRemoved++}
  elseif($o.IsStatic -and $o.MethodSig.Params.Count -eq 1 -and $o.MethodSig.Params[0].FullName -eq 'System.Int32' -and $o.MethodSig.RetType.FullName -eq 'System.Void'){
   $hasResolve=@($o.Body.Instructions|Where-Object{$_.Operand -is [dnlib.DotNet.IMethod] -and $_.Operand.FullName -like '*System.ModuleHandle::ResolveTypeHandle*'}).Count -gt 0
   $hasFields=@($o.Body.Instructions|Where-Object{$_.Operand -is [dnlib.DotNet.IMethod] -and $_.Operand.FullName -like '*System.Type::GetFields*'}).Count -gt 0
   $active=@($q.Body.Instructions|Where-Object{$_.OpCode.Code -ne [dnlib.DotNet.Emit.Code]::Nop})
   if($hasResolve -and $hasFields -and $active.Count -eq 3 -and $active[1] -eq $i -and $active[0].IsLdcI4() -and $active[2].OpCode.Code -eq [dnlib.DotNet.Emit.Code]::Ret){$proxyResolvers.Add($o.DeclaringType)|Out-Null;$i.OpCode=[dnlib.DotNet.Emit.OpCodes]::Pop;$i.Operand=$null;$proxyRemoved++}
  }
 }}
}
$removedResolvers=[Collections.Generic.List[string]]::new()
foreach($resolver in $proxyResolvers){
 $referenced=$false
 foreach($t in $types){if($t -eq $resolver){continue};foreach($q in $t.Methods){if($q.MethodSig.ToString().Contains($resolver.FullName)){$referenced=$true};if($q.HasBody){foreach($i in $q.Body.Instructions){if($i.Operand -is [dnlib.DotNet.IMemberRef] -and $i.Operand.DeclaringType -eq $resolver){$referenced=$true}}}};foreach($f in $t.Fields){if($f.FieldSig.Type.FullName.Contains($resolver.FullName)){$referenced=$true}}}
 if(-not $referenced){$removedResolvers.Add($oldFull[$resolver]);$m.Types.Remove($resolver)|Out-Null}
}
$types=@($m.GetTypes());$methods=@($types|ForEach-Object{$_.Methods})

$namespaceMap=@{};$namespaces=@($types|ForEach-Object{$_.Namespace.ToString()}|Sort-Object -Unique);$n=0
foreach($ns in $namespaces){if($ns -and @($ns.Split('.')|Where-Object{IsObfuscated $_}).Count){$n++;$namespaceMap[$ns]='Recovered.Group'+$n.ToString('000')}}
$usedTypes=@{}
foreach($t in $types){
 $old=$oldNames[$t];$ns=$t.Namespace.ToString();$new=$old;$reason='generated: stable metadata RID and base type'
 if($namespaceMap.ContainsKey($ns)){$t.Namespace=$namespaceMap[$ns]}
 if($t -eq $m.EntryPoint.DeclaringType){$new='Program';$t.Namespace='Recovered.Application';$reason='metadata: assembly entry-point owner'}
 elseif($oldFull[$t] -eq 'ohM=.zhM='){$new='ByteTransform';$t.Namespace='Recovered.Security';$reason='inferred: byte encryption/transform operations'}
 elseif($oldFull[$t] -eq 'ohM=.yxM='){$new='ByteTransformKind';$t.Namespace='Recovered.Security';$reason='inferred: AesCbc/Xor discriminator'}
 elseif(IsObfuscated $old){
  if($formHints.ContainsKey($oldFull[$t])){$new='Form_'+(Safe $formHints[$oldFull[$t]]);$reason='inferred: Control.Name literal'}
  elseif($t.IsInterface){$new='IContract_'+$t.MDToken.Rid.ToString('0000')}
  elseif($t.IsEnum){$new='Enum_'+$t.MDToken.Rid.ToString('0000')}
  elseif($t.BaseType.FullName -eq 'System.MulticastDelegate'){$new='Delegate_'+$t.MDToken.Rid.ToString('0000')}
  elseif($t.IsValueType){$new='Struct_'+$t.MDToken.Rid.ToString('0000')}
  elseif($t.BaseType.Name.ToString() -in @('Form','Control','UserControl','Button','ButtonBase','TextBox','ListView','Component','Stream')){$new=(Safe $t.BaseType.Name.ToString())+'_'+$t.MDToken.Rid.ToString('0000')}
  else{$new='Class_'+$t.MDToken.Rid.ToString('0000')}
  if($old -match '`([0-9]+)$'){$new+='`'+$Matches[1]}
 }
 $scope=if($t.DeclaringType){$oldFull[$t.DeclaringType]}else{$t.Namespace.ToString()}
 $key=$scope+'|'+$new
 if($usedTypes.ContainsKey($key) -and $usedTypes[$key] -ne $t){$new+='_'+$t.MDToken.Rid};$usedTypes[$scope+'|'+$new]=$t
 if($t.Namespace.ToString() -ne $ns){$records.Add([ordered]@{kind='namespace';old_name=$ns;new_name=$t.Namespace.ToString();old_full_name=$oldFull[$t];original_token=$t.MDToken.ToString();reason='generated: legal grouped namespace';definition=$t})}
 $t.Name=$new;Record $t 'type' $reason $old $new
}

$fieldMap=@{};$propertyMap=@{};$eventMap=@{};$methodMap=@{}
$conversionNames=@('Int8','Int16','Int32','Int64','Float32','Float64','UInt8','UInt16','UInt32','UInt64','Mode10','Mode11','Mode12')
foreach($t in $types){foreach($f in $t.Fields){
 $old=$oldNames[$f];$new=$old;$why='generated: stable field identifier'
 if($t.FullName -eq 'Recovered.Security.ByteTransformKind' -and $f.HasConstant){$new=if([int]$f.Constant.Value -eq 0){'AesCbc'}else{'Xor'};$why='inferred: discriminator branch semantics'}
 elseif($t.FullName -eq 'Recovered.Support.ConversionKind' -and $f.HasConstant){$new=$conversionNames[[int]$f.Constant.Value];$why='inferred: conversion switch opcode semantics'}
 elseif($t.FullName -eq 'Recovered.Support.UnorderedComparisonMode' -and $f.HasConstant){$new='UnorderedMode'+$f.Constant.Value;$why='generated: enum constant value'}
 elseif(IsObfuscated $old){
  if($fieldHints.ContainsKey($f)){$new=Safe $fieldHints[$f];$why='inferred: exact Control.Name setter'}
  else{
   $sig=$f.FieldSig.Type;$suffix=''
   while($sig -is [dnlib.DotNet.SZArraySig]){$suffix+='Array';$sig=$sig.Next}
   if($sig -is [dnlib.DotNet.GenericInstSig]){$typeName=$sig.GenericType.TypeDefOrRef.Name.ToString()}
   elseif($sig.TypeDefOrRef){$typeName=$sig.TypeDefOrRef.Name.ToString()}
   else{$typeName='Value'}
   $typeName=(Safe ($typeName -replace '`[0-9]+',''))+$suffix
   if($typeName.Length -gt 40){$typeName='Value'};$new='Field_'+$typeName+'_'+$f.MDToken.Rid.ToString('0000')
  }
 }
 if($new -ne $old){if(-not $fieldMap.ContainsKey($old)){$fieldMap[$old]=$new}elseif($fieldMap[$old] -ne $new){$fieldMap[$old]=$null};$f.Name=$new;Record $f 'field' $why $old $new}
}}
foreach($t in $types){
 foreach($p in $t.Properties){$old=$oldNames[$p];$new=$old;if(IsObfuscated $old){if($propertyMap.ContainsKey($old)){$new=$propertyMap[$old]}else{$new='Property_'+$p.MDToken.Rid.ToString('0000');$propertyMap[$old]=$new};$p.Name=$new;Record $p 'property' 'generated: property identifier' $old $new}
  if($p.GetMethod -and (IsObfuscated $oldNames[$p.GetMethod])){$methodHints[$p.GetMethod]='get_'+$new;$hintReasons[$p.GetMethod]='metadata: property getter'}
  if($p.SetMethod -and (IsObfuscated $oldNames[$p.SetMethod])){$methodHints[$p.SetMethod]='set_'+$new;$hintReasons[$p.SetMethod]='metadata: property setter'}
 }
 foreach($e in $t.Events){$old=$oldNames[$e];$new=$old;if(IsObfuscated $old){if($eventMap.ContainsKey($old)){$new=$eventMap[$old]}else{$new='Event_'+$e.MDToken.Rid.ToString('0000');$eventMap[$old]=$new};$e.Name=$new;Record $e 'event' 'generated: event identifier' $old $new}
  foreach($pair in @(@($e.AddMethod,'add_'),@($e.RemoveMethod,'remove_'))){if($pair[0] -and (IsObfuscated $oldNames[$pair[0]])){$methodHints[$pair[0]]=$pair[1]+$new;$hintReasons[$pair[0]]='metadata: event accessor'}}
 }
}
$virtualHints=@{}
foreach($q in $methods){if(($q.IsVirtual -or $q.DeclaringType.IsInterface) -and $methodHints.ContainsKey($q)){$key=$methodKeys[$q];if($virtualHints.ContainsKey($key) -and $virtualHints[$key] -ne $methodHints[$q]){$virtualHints[$key]=$null}else{$virtualHints[$key]=$methodHints[$q]}}}
foreach($q in $methods){
 $old=$oldNames[$q];$new=$old;$why='generated: consistent method-name mapping'
 if(IsObfuscated $old){
  if($methodHints.ContainsKey($q)){$new=Safe $methodHints[$q];$why=$hintReasons[$q]}
  elseif(($q.IsVirtual -or $q.DeclaringType.IsInterface) -and $virtualHints.ContainsKey($methodKeys[$q]) -and $virtualHints[$methodKeys[$q]]){$new=Safe $virtualHints[$methodKeys[$q]];$why='metadata: matching virtual/interface name and signature'}
  elseif($methodMap.ContainsKey($old)){$new=$methodMap[$old]}
  else{$new='Method_'+$q.MDToken.Rid.ToString('0000');$methodMap[$old]=$new}
  $q.Name=$new;Record $q 'method' $why $old $new
 }
 if($q.HasBody){$q.Body.KeepOldMaxStack=$true}
}
foreach($pair in $bindings){$pair[0].Name=$pair[1].Name}
foreach($pair in $typeBindings){$pair[0].Name=$pair[1].Name;$pair[0].Namespace=$pair[1].Namespace}

# Patch only exact self type-name strings and direct reflection member-name strings.
$typeStringMap=@{};foreach($t in $types){if($oldFull[$t] -ne $t.FullName){$typeStringMap[$oldFull[$t]]=$t.FullName}}
$memberStrings=@{};foreach($map in @($fieldMap,$propertyMap,$eventMap,$methodMap)){foreach($key in $map.Keys){if(-not $memberStrings.ContainsKey($key)){$memberStrings[$key]=$map[$key]}elseif($memberStrings[$key] -ne $map[$key]){$memberStrings[$key]=$null}}}
$stringUpdates=[Collections.Generic.List[object]]::new()
foreach($q in $methods){if(-not $q.HasBody){continue};$il=$q.Body.Instructions
 for($i=0;$i -lt $il.Count;$i++){if($il[$i].OpCode.Code -ne [dnlib.DotNet.Emit.Code]::Ldstr){continue};$old=[string]$il[$i].Operand;$new=$old;$reason=''
  if($typeStringMap.ContainsKey($old)){
   for($j=$i+1;$j -lt [math]::Min($il.Count,$i+7);$j++){$o=$il[$j].Operand
    if($o -is [dnlib.DotNet.IMethod] -and $o.Name.ToString() -eq 'GetType' -and $o.DeclaringType.FullName -in @('System.Type','System.Reflection.Assembly')){$new=$typeStringMap[$old];$reason='exact self type identity at direct type lookup';break}
    if($o -is [dnlib.DotNet.IMethod] -and $o.Name.ToString() -eq '.ctor' -and $o.DeclaringType.FullName -eq 'System.Resources.ResourceManager'){break}
   }
  }
  elseif($memberStrings.ContainsKey($old) -and $memberStrings[$old]){
   for($j=$i+1;$j -lt [math]::Min($il.Count,$i+6);$j++){$o=$il[$j].Operand;if($o -is [dnlib.DotNet.IMethod] -and $o.Name.ToString() -in @('GetMethod','GetField','GetProperty','GetEvent','GetMember')){$new=$memberStrings[$old];$reason='direct reflection member lookup';break}}
  }
  if($new -ne $old){$il[$i].Operand=$new;$stringUpdates.Add([ordered]@{caller=$q.FullName;old=$old;new=$new;reason=$reason})}
 }
}

$output=Join-Path $OutputDirectory 'SeroXen.cleaned.bin'
$options=[dnlib.DotNet.Writer.ModuleWriterOptions]::new($m);$m.Write($output,$options)
$check=[dnlib.DotNet.ModuleDefMD]::Load($output)
$newDefs=@{};foreach($t in $check.GetTypes()){$newDefs['type|'+$t.FullName]=$t;foreach($q in $t.Methods){$newDefs['method|'+$q.FullName]=$q};foreach($q in $t.Fields){$newDefs['field|'+$q.FullName]=$q};foreach($q in $t.Properties){$newDefs['property|'+$q.FullName]=$q};foreach($q in $t.Events){$newDefs['event|'+$q.FullName]=$q}}
foreach($r in $records){$d=$r.definition;$r.Remove('definition');$r.new_full_name=$d.FullName;$key=if($r.kind -eq 'namespace'){'type|'+$d.FullName}else{$r.kind+'|'+$d.FullName};if(-not $newDefs.ContainsKey($key)){throw ('Renamed definition missing '+$key)};$r.new_token=$newDefs[$key].MDToken.ToString()}
$invalid=[Collections.Generic.List[string]]::new()
foreach($t in $check.GetTypes()){
 if(IsObfuscated $t.Name.ToString()){$invalid.Add($t.FullName)}
 foreach($collection in @($t.Methods,$t.Fields,$t.Properties,$t.Events)){foreach($d in $collection){if(IsObfuscated $d.Name.ToString()){$invalid.Add($d.FullName)}}}
}
if($invalid.Count){$invalid|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $OutputDirectory 'invalid-names.json');throw ('Still obfuscated identifiers '+$invalid.Count)}
if(@($check.GetAssemblyRefs()|Where-Object{$_.Name.ToString() -like '*C5VM*'}).Count){throw 'C5VM dependency returned'}
$report=[ordered]@{event='static_identifier_cleanup_completed';input=$InputFile;input_sha256=(Get-FileHash -LiteralPath $InputFile).Hash.ToLower();output=$output;output_sha256=(Get-FileHash -LiteralPath $output).Hash.ToLower();renamed_definitions=$records.Count;renames=@($records.ToArray());exact_self_member_refs_updated=$bindings.Count;exact_self_type_refs_updated=$typeBindings.Count;reflection_string_updates=@($stringUpdates.ToArray());unused_proxy_initializers_removed=$proxyRemoved;unreferenced_proxy_resolvers_removed=@($removedResolvers.ToArray());control_name_hints=$fieldHints.Count;state_machine_or_event_hints=$methodHints.Count;remaining_non_generated_invalid_names=$invalid.Count;entrypoint=$check.EntryPoint.FullName;target_executed=$false;application_compiled=$false;limitations=@('Original names cannot generally be recovered: generated labels are explicit in this map.','Compiler-generated names are intentionally retained for async/lambda decompilation.','Serialization/reflection/wire compatibility is not claimed without isolated execution tests.')}
$report|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $OutputDirectory 'rename-map.json') -Encoding utf8
[pscustomobject]$report|Select-Object event,output,output_sha256,renamed_definitions,exact_self_member_refs_updated,unused_proxy_initializers_removed,control_name_hints,remaining_non_generated_invalid_names,entrypoint|ConvertTo-Json
