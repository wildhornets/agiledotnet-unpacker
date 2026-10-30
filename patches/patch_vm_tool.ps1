param([Parameter(Mandatory=$true)][string]$Destination, [string]$VendorDirectory=(Join-Path $PSScriptRoot '..\vendor\AgileDevirtualizer-v1.0.1'), [string]$DnlibPath='')
$ErrorActionPreference='Stop'
$vendor=(Resolve-Path -LiteralPath $VendorDirectory).Path
if(Test-Path -LiteralPath $Destination){throw 'Destination already exists; preserve prior run'}
New-Item -ItemType Directory -Path $Destination | Out-Null
Get-ChildItem -LiteralPath $vendor -File | ForEach-Object {Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $Destination $_.Name)}
. (Join-Path $PSScriptRoot '..\cleanup-tools\load_dnlib.ps1') -DnlibPath $DnlibPath
$original=Join-Path $vendor 'AgileDevirtualizer.dll'
$m=[dnlib.DotNet.ModuleDefMD]::Load($original)
$interp=@($m.GetTypes() | Where-Object {$_.FullName -eq 'AgileDevirtualizer.Lift.ExecuteInterpreter'})[0]
$sym=@($m.GetTypes() | Where-Object {$_.FullName -eq 'AgileDevirtualizer.Lift.SymValue'})[0]
$refs=@($m.GetMemberRefs())
function FindRef([string]$full){$r=@($refs|Where-Object{$_.FullName -eq $full});if($r.Count -ne 1){throw "Reference not unique: $full count=$($r.Count)"};return $r[0]}
function M([string]$name){$r=@($interp.Methods|Where-Object{$_.Name -eq $name});if($r.Count -ne 1){throw "Method not unique: $name"};return $r[0]}
function S([string]$name){$r=@($m.GetTypes()|Where-Object{$_.FullName -eq ('AgileDevirtualizer.Lift.SymValue/'+$name)});if($r.Count -ne 1){throw "Symbol type not unique: $name"};return $r[0]}
function SM([string]$name,[string]$method){$r=@((S $name).Methods|Where-Object{$_.Name -eq $method});if($r.Count -ne 1){throw "Symbol member not unique: $name::$method"};return $r[0]}
function E($body,[string]$op,$operand=$null){
    $code=[dnlib.DotNet.Emit.OpCodes].GetField($op).GetValue($null)
    $instruction=[dnlib.DotNet.Emit.Instruction]::new($code)
    if($null -ne $operand){$instruction.Operand=$operand}
    $body.Instructions.Add($instruction)
}
function Label(){return [dnlib.DotNet.Emit.Instruction]::Create([dnlib.DotNet.Emit.OpCodes]::Nop)}
function NewHelper([string]$name,$ret,$parameters){
    $sig=[dnlib.DotNet.MethodSig]::CreateInstance($ret,[dnlib.DotNet.TypeSig[]]$parameters)
    $attrs=[dnlib.DotNet.MethodAttributes]::Private -bor [dnlib.DotNet.MethodAttributes]::HideBySig
    $method=[dnlib.DotNet.MethodDefUser]::new($name,$sig,[dnlib.DotNet.MethodImplAttributes]::IL,$attrs)
    $method.Body=[dnlib.DotNet.Emit.CilBody]::new()
    $method.Body.InitLocals=$true
    $interp.Methods.Add($method)
    return $method
}
function CodeField([string]$name){
    $r=@($refs|Where-Object{$_.FullName -eq ('AsmResolver.PE.DotNet.Cil.CilOpCode AsmResolver.PE.DotNet.Cil.CilOpCodes::'+$name)})
    if($r.Count -eq 1){return $r[0]}
    $prototype=@($refs|Where-Object{$_.FullName -eq 'AsmResolver.PE.DotNet.Cil.CilOpCode AsmResolver.PE.DotNet.Cil.CilOpCodes::Ldloca'})[0]
    if($null -eq $prototype){throw 'Missing opcode field prototype'}
    return [dnlib.DotNet.MemberRefUser]::new($m,$name,$prototype.FieldSig,$prototype.Class)
}
$pop=M 'Pop';$emit=M 'Emit';$emitPush=M 'EmitPush'
$evalField=@($interp.Fields|Where-Object{$_.Name -eq '_eval'})[0]
$push=FindRef 'System.Void System.Collections.Generic.Stack`1<AgileDevirtualizer.Lift.SymValue>::Push(AgileDevirtualizer.Lift.SymValue)'
$resolved=S 'Resolved';$slot=S 'SlotArray'
$fieldType=(@($m.GetTypeRefs()|Where-Object{$_.FullName -eq 'AsmResolver.DotNet.IFieldDescriptor'}))[0]
$typeSignature=(@($m.GetTypeRefs()|Where-Object{$_.FullName -eq 'AsmResolver.DotNet.Signatures.TypeSignature'}))[0]
$methodDescriptor=(@($m.GetTypeRefs()|Where-Object{$_.FullName -eq 'AsmResolver.DotNet.IMethodDescriptor'}))[0]
$getSignature=FindRef 'AsmResolver.DotNet.Signatures.MethodSignature AsmResolver.DotNet.IMethodDescriptor::get_Signature()'
$getParameters=FindRef 'System.Collections.Generic.IList`1<AsmResolver.DotNet.Signatures.TypeSignature> AsmResolver.DotNet.Signatures.MethodSignatureBase::get_ParameterTypes()'
$getParameter=FindRef 'AsmResolver.DotNet.Signatures.TypeSignature System.Collections.Generic.IList`1<AsmResolver.DotNet.Signatures.TypeSignature>::get_Item(System.Int32)'
$isType=FindRef 'System.Boolean AsmResolver.DotNet.TypeDescriptorExtensions::IsTypeOf(AsmResolver.DotNet.ITypeDescriptor,System.String,System.String)'
$getFieldSig=FindRef 'AsmResolver.DotNet.Signatures.FieldSignature AsmResolver.DotNet.IFieldDescriptor::get_Signature()'
$getFieldType=FindRef 'AsmResolver.DotNet.Signatures.TypeSignature AsmResolver.DotNet.Signatures.FieldSignature::get_FieldType()'
$roleType=@($m.GetTypes()|Where-Object{$_.FullName -eq 'AgileDevirtualizer.Lift.HelperRole'})[0]
$resolveField=[int](@($roleType.Fields|Where-Object{$_.Name -eq 'ResolveField'})[0].Constant.Value)

# The runtime constructor's two fields and reflection read/write accessors were inspected separately.
# Materialize field addresses eagerly and carry their exact pointed-to type; no runtime calls.
$helper=NewHelper 'TryEmitFieldAddressCtor_StaticPatch' $m.CorLibTypes.Boolean @(
    [dnlib.DotNet.ClassSig]::new($methodDescriptor),[dnlib.DotNet.SZArraySig]::new([dnlib.DotNet.ClassSig]::new($sym)))
$b=$helper.Body
foreach($sig in @([dnlib.DotNet.ClassSig]::new($resolved),[dnlib.DotNet.ClassSig]::new($fieldType),[dnlib.DotNet.ClassSig]::new($typeSignature))){$b.Variables.Add([dnlib.DotNet.Emit.Local]::new($sig))}
$no=Label;$instance=Label;$model=Label
E $b Ldarg_1;E $b Brfalse $no
E $b Ldarg_2;E $b Ldlen;E $b Conv_I4;E $b Ldc_I4_2;E $b Bne_Un $no
E $b Ldarg_2;E $b Ldc_I4_1;E $b Ldelem_Ref;E $b Isinst $resolved;E $b Stloc_0
E $b Ldloc_0;E $b Brfalse $no
E $b Ldloc_0;E $b Callvirt (SM 'Resolved' 'get_Kind');E $b Ldc_I4 $resolveField;E $b Bne_Un $no
E $b Ldloc_0;E $b Callvirt (SM 'Resolved' 'get_Member');E $b Isinst $fieldType;E $b Stloc_1
E $b Ldloc_1;E $b Brfalse $no
E $b Ldarg_1;E $b Callvirt $getSignature;E $b Callvirt $getParameters;E $b Ldc_I4_1;E $b Callvirt $getParameter
E $b Ldstr 'System.Reflection';E $b Ldstr 'FieldInfo';E $b Call $isType;E $b Brfalse $no
E $b Ldloc_1;E $b Callvirt $getFieldSig;E $b Callvirt $getFieldType;E $b Stloc_2
E $b Ldarg_0;E $b Ldloc_0;E $b Call (M 'IsStaticMember');E $b Brfalse $instance
E $b Ldarg_0;E $b Ldsfld (CodeField 'Ldsflda');E $b Ldloc_1;E $b Call $emit;E $b Br $model
$b.Instructions.Add($instance)
E $b Ldarg_0;E $b Ldarg_2;E $b Ldc_I4_0;E $b Ldelem_Ref;E $b Call $emitPush
E $b Ldarg_0;E $b Ldsfld (CodeField 'Ldflda');E $b Ldloc_1;E $b Call $emit
$b.Instructions.Add($model)
E $b Ldarg_0;E $b Ldfld $evalField;E $b Ldloc_2;E $b Ldc_I4_0;E $b Ldc_I4_1;E $b Ldc_I4_0
$onStackCtor=@((S 'OnStack').Methods|Where-Object{$_.Name -eq '.ctor' -and $_.MethodSig.Params.Count -eq 4})[0]
E $b Newobj $onStackCtor;E $b Callvirt $push;E $b Ldc_I4_1;E $b Ret
$b.Instructions.Add($no);E $b Ldc_I4_0;E $b Ret
$evalNew=M 'EvalNewobj'
$anchor=$evalNew.Body.Instructions[27]
if($anchor.OpCode.Code.ToString() -ne 'Ldloc_0'){throw 'Unexpected EvalNewobj IL anchor'}
$prefix=[dnlib.DotNet.Emit.CilBody]::new()
E $prefix Ldarg_0;E $prefix Ldarg_1;E $prefix Ldloc_1;E $prefix Call $helper;E $prefix Brfalse $anchor;E $prefix Ret
for($i=$prefix.Instructions.Count-1;$i -ge 0;$i--){$evalNew.Body.Instructions.Insert(27,$prefix.Instructions[$i])}

# A handler's stelem.ref into ctx.args/ctx.locals is a source argument/local store,
# not a native array store. Unsupported other targets still fail closed.
$store=NewHelper 'HandleSlotArrayStore_StaticPatch' $m.CorLibTypes.Void @()
$b=$store.Body
foreach($sig in @([dnlib.DotNet.ClassSig]::new($sym),[dnlib.DotNet.ClassSig]::new($sym),[dnlib.DotNet.ClassSig]::new($slot),$m.CorLibTypes.Int32)){$b.Variables.Add([dnlib.DotNet.Emit.Local]::new($sig))}
$bad=Label;$local=Label
E $b Ldarg_0;E $b Call $pop;E $b Stloc_0
E $b Ldarg_0;E $b Call $pop;E $b Stloc_1
E $b Ldarg_0;E $b Call $pop;E $b Isinst $slot;E $b Stloc_2
E $b Ldloc_2;E $b Brfalse $bad
E $b Ldloc_1;E $b Ldloca $b.Variables[3];E $b Call (M 'TryInt');E $b Brfalse $bad
E $b Ldloc_2;E $b Callvirt (SM 'SlotArray' 'get_IsArgs');E $b Brfalse $local
E $b Ldarg_0;E $b Ldloc_0;E $b Call $emitPush
E $b Ldarg_0;E $b Ldsfld (CodeField 'Starg');E $b Ldloc_3;E $b Box $m.CorLibTypes.Int32.TypeDefOrRef;E $b Call $emit;E $b Ret
$b.Instructions.Add($local)
E $b Ldarg_0;E $b Ldfld $evalField;E $b Ldloc_2;E $b Callvirt $push
E $b Ldarg_0;E $b Ldfld $evalField;E $b Ldloc_1;E $b Callvirt $push
E $b Ldarg_0;E $b Ldfld $evalField;E $b Ldloc_0;E $b Callvirt $push
E $b Ldarg_0;E $b Call (M 'DoSetLocal');E $b Ret
$b.Instructions.Add($bad);E $b Ldstr 'stelem.ref target is not a known VM argument/local slot'
$unsupported=@($m.GetTypes()|Where-Object{$_.FullName -eq 'AgileDevirtualizer.Lift.LiftUnsupported'})[0]
$exceptionCtor=@($unsupported.Methods|Where-Object{$_.Name -eq '.ctor'})[0]
E $b Newobj $exceptionCtor;E $b Throw
$step=M 'Step';$anchor=$step.Body.Instructions[0]
$getOpcode=FindRef 'AsmResolver.PE.DotNet.Cil.CilOpCode AsmResolver.PE.DotNet.Cil.CilInstruction::get_OpCode()'
$getCode=FindRef 'AsmResolver.PE.DotNet.Cil.CilCode AsmResolver.PE.DotNet.Cil.CilOpCode::get_Code()'
$opcodeLocal=[dnlib.DotNet.Emit.Local]::new($getOpcode.MethodSig.RetType)
$step.Body.Variables.Add($opcodeLocal)
$pe=[dnlib.DotNet.ModuleDefMD]::Load((Join-Path $vendor 'AsmResolver.PE.dll'))
$enum=@($pe.GetTypes()|Where-Object{$_.FullName -eq 'AsmResolver.PE.DotNet.Cil.CilCode'})[0]
$stelemRef=[int](@($enum.Fields|Where-Object{$_.Name -eq 'Stelem_Ref'})[0].Constant.Value)
$prefix=[dnlib.DotNet.Emit.CilBody]::new()
E $prefix Ldarg_1;E $prefix Callvirt $getOpcode;E $prefix Stloc $opcodeLocal;E $prefix Ldloca $opcodeLocal;E $prefix Call $getCode
E $prefix Ldc_I4 $stelemRef;E $prefix Bne_Un $anchor;E $prefix Ldarg_0;E $prefix Call $store;E $prefix Ldc_I4_1;E $prefix Ret
for($i=$prefix.Instructions.Count-1;$i -ge 0;$i--){$step.Body.Instructions.Insert(0,$prefix.Instructions[$i])}
foreach($method in @($helper,$store,$evalNew,$step)){$method.Body.SimplifyBranches();$method.Body.OptimizeBranches();$method.Body.KeepOldMaxStack=$false}
$out=Join-Path $Destination 'AgileDevirtualizer.dll'
$options=[dnlib.DotNet.Writer.ModuleWriterOptions]::new($m)
$options.MetadataOptions.Flags=[dnlib.DotNet.Writer.MetadataFlags]::PreserveAll
$m.Write($out,$options)
$check=[dnlib.DotNet.ModuleDefMD]::Load($out)
$found=@($check.GetTypes()|Where-Object{$_.FullName -eq $interp.FullName})[0]
foreach($n in @($helper.Name,$store.Name)){if(@($found.Methods|Where-Object{$_.Name -eq $n}).Count -ne 1){throw 'Helper missing on reopen'}}
$provenance=[ordered]@{event='static_tool_il_patch';original=$original;original_sha256=(Get-FileHash -LiteralPath $original -Algorithm SHA256).Hash.ToLower();modified=$out;modified_sha256=(Get-FileHash -LiteralPath $out -Algorithm SHA256).Hash.ToLower();changed_methods=@('EvalNewobj','Step');added_methods=@([string]$helper.Name,[string]$store.Name);compiler_executed=$false;target_executed=$false;preserve_original=$true}
$provenance|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $Destination 'patch-provenance.json') -Encoding utf8
$provenance|ConvertTo-Json -Depth 5
