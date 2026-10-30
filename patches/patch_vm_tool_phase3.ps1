param([Parameter(Mandatory=$true)][string]$SourceDirectory, [Parameter(Mandatory=$true)][string]$Destination, [string]$DnlibPath='')
$ErrorActionPreference='Stop'
$source=(Resolve-Path -LiteralPath $SourceDirectory).Path
if(Test-Path -LiteralPath $Destination){throw 'Destination exists'}
New-Item -ItemType Directory -Path $Destination|Out-Null
Get-ChildItem -LiteralPath $source -File|ForEach-Object{Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $Destination $_.Name)}
. (Join-Path $PSScriptRoot '..\cleanup-tools\load_dnlib.ps1') -DnlibPath $DnlibPath
$m=[dnlib.DotNet.ModuleDefMD]::Load((Join-Path $source 'AgileDevirtualizer.dll'));$refs=@($m.GetMemberRefs())
function T([string]$name){return @($m.GetTypes()|Where-Object{$_.FullName -eq $name})[0]}
function IM([string]$name){$a=@((T 'AgileDevirtualizer.Lift.ExecuteInterpreter').Methods|Where-Object{$_.Name -eq $name});if($a.Count -ne 1){throw $name};return $a[0]}
function SM([string]$name){return @((T 'AgileDevirtualizer.Lift.SymValue/Resolved').Methods|Where-Object{$_.Name -eq $name})[0]}
function FindRef([string]$name){$a=@($refs|Where-Object{$_.FullName -eq $name});if($a.Count -ne 1){throw "Reference $name"};return $a[0]}
function E($b,[string]$op,$operand=$null){$code=[dnlib.DotNet.Emit.OpCodes].GetField($op).GetValue($null);$i=[dnlib.DotNet.Emit.Instruction]::new($code);if($null -ne $operand){$i.Operand=$operand};$b.Instructions.Add($i)}
function Label(){return [dnlib.DotNet.Emit.Instruction]::Create([dnlib.DotNet.Emit.OpCodes]::Nop)}
$interp=T 'AgileDevirtualizer.Lift.ExecuteInterpreter'
$descriptor=@($m.GetTypeRefs()|Where-Object{$_.FullName -eq 'AsmResolver.DotNet.IMethodDescriptor'})[0]
$resolved=T 'AgileDevirtualizer.Lift.SymValue/Resolved'
$signature=[dnlib.DotNet.MethodSig]::CreateInstance($m.CorLibTypes.Void,[dnlib.DotNet.TypeSig[]]@([dnlib.DotNet.ClassSig]::new($descriptor)))
$helper=[dnlib.DotNet.MethodDefUser]::new('ObserveReflectionArgumentPops_StaticPatch',$signature,[dnlib.DotNet.MethodImplAttributes]::IL,([dnlib.DotNet.MethodAttributes]::Private -bor [dnlib.DotNet.MethodAttributes]::HideBySig))
$helper.Body=[dnlib.DotNet.Emit.CilBody]::new();$helper.Body.InitLocals=$true;$interp.Methods.Add($helper)
$b=$helper.Body
foreach($s in @([dnlib.DotNet.ClassSig]::new($resolved),[dnlib.DotNet.ClassSig]::new($descriptor),$m.CorLibTypes.Int32)){$b.Variables.Add([dnlib.DotNet.Emit.Local]::new($s))|Out-Null}
$evalField=@($interp.Fields|Where-Object{$_.Name -eq '_eval'})[0]
$shadowField=@($interp.Fields|Where-Object{$_.Name -eq '_vmValueTypes'})[0]
$elementAt=@((IM 'TryHandleDefaultValueCall').Body.Instructions|Where-Object{$_.Operand -and $_.Operand.ToString() -like '*Enumerable::ElementAt<AgileDevirtualizer.Lift.SymValue>*'})[0].Operand
$getSignature=FindRef 'AsmResolver.DotNet.Signatures.MethodSignature AsmResolver.DotNet.IMethodDescriptor::get_Signature()'
$getParameters=FindRef 'System.Collections.Generic.IList`1<AsmResolver.DotNet.Signatures.TypeSignature> AsmResolver.DotNet.Signatures.MethodSignatureBase::get_ParameterTypes()'
$getItem=FindRef 'AsmResolver.DotNet.Signatures.TypeSignature System.Collections.Generic.IList`1<AsmResolver.DotNet.Signatures.TypeSignature>::get_Item(System.Int32)'
$isType=FindRef 'System.Boolean AsmResolver.DotNet.TypeDescriptorExtensions::IsTypeOf(AsmResolver.DotNet.ITypeDescriptor,System.String,System.String)'
$count=FindRef 'System.Int32 System.Collections.Generic.Stack`1<AgileDevirtualizer.Lift.SymValue>::get_Count()'
$shadowCount=FindRef 'System.Int32 System.Collections.Generic.Stack`1<AgileDevirtualizer.Lift.ExecuteInterpreter/VmStackType>::get_Count()'
$shadowPop=FindRef 'AgileDevirtualizer.Lift.ExecuteInterpreter/VmStackType System.Collections.Generic.Stack`1<AgileDevirtualizer.Lift.ExecuteInterpreter/VmStackType>::Pop()'
$done=Label;$loop=Label
E $b Ldarg_1;E $b Call (IM 'ParamCount');E $b Ldc_I4_4;E $b Bne_Un $done
E $b Ldarg_1;E $b Call (IM 'HasThis');E $b Brtrue $done
E $b Ldarg_1;E $b Callvirt $getSignature;E $b Callvirt $getParameters;E $b Ldc_I4_1;E $b Callvirt $getItem;E $b Ldstr 'System.Reflection';E $b Ldstr 'MethodBase';E $b Call $isType;E $b Brfalse $done
E $b Ldarg_0;E $b Ldfld $evalField;E $b Callvirt $count;E $b Ldc_I4_4;E $b Blt $done
E $b Ldarg_0;E $b Ldfld $evalField;E $b Ldc_I4_2;E $b Call $elementAt;E $b Isinst $resolved;E $b Stloc_0;E $b Ldloc_0;E $b Brfalse $done
E $b Ldloc_0;E $b Callvirt (SM 'get_Member');E $b Isinst $descriptor;E $b Stloc_1;E $b Ldloc_1;E $b Brfalse $done
E $b Ldloc_1;E $b Call (IM 'ParamCount');E $b Stloc_2
$b.Instructions.Add($loop)
E $b Ldloc_2;E $b Ldc_I4_0;E $b Ble $done
E $b Ldarg_0;E $b Ldfld $shadowField;E $b Callvirt $shadowCount;E $b Brfalse $done
E $b Ldarg_0;E $b Ldfld $shadowField;E $b Callvirt $shadowPop;E $b Pop
E $b Ldloc_2;E $b Ldc_I4_1;E $b Sub;E $b Stloc_2;E $b Br $loop
$b.Instructions.Add($done);E $b Ret
$transparent=IM 'Transparent';$prefix=[dnlib.DotNet.Emit.CilBody]::new();E $prefix Ldarg_0;E $prefix Ldarg_1;E $prefix Call $helper
for($i=$prefix.Instructions.Count-1;$i -ge 0;$i--){$transparent.Body.Instructions.Insert(0,$prefix.Instructions[$i])}
foreach($q in @($helper,$transparent)){$q.Body.SimplifyBranches();$q.Body.OptimizeBranches();$q.Body.KeepOldMaxStack=$false}
$out=Join-Path $Destination 'AgileDevirtualizer.dll';$opts=[dnlib.DotNet.Writer.ModuleWriterOptions]::new($m);$opts.MetadataOptions.Flags=[dnlib.DotNet.Writer.MetadataFlags]::PreserveAll;$m.Write($out,$opts)
$check=[dnlib.DotNet.ModuleDefMD]::Load($out)
$record=[ordered]@{event='static_tool_il_patch_phase3';source=(Join-Path $source 'AgileDevirtualizer.dll');source_sha256=(Get-FileHash -LiteralPath (Join-Path $source 'AgileDevirtualizer.dll')).Hash.ToLower();modified=$out;modified_sha256=(Get-FileHash -LiteralPath $out).Hash.ToLower();changed_methods=@('Transparent');added_methods=@([string]$helper.Name);compiler_executed=$false;target_executed=$false;reopened=$true}
$record|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $Destination 'patch-phase3-provenance.json') -Encoding utf8
$record|ConvertTo-Json -Depth 5
