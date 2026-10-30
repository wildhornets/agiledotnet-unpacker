param([Parameter(Mandatory=$true)][string]$SourceDirectory, [Parameter(Mandatory=$true)][string]$Destination, [string]$DnlibPath='')
$ErrorActionPreference='Stop'
$source=(Resolve-Path -LiteralPath $SourceDirectory).Path
if(Test-Path -LiteralPath $Destination){throw 'Destination exists'}
New-Item -ItemType Directory -Path $Destination|Out-Null
Get-ChildItem -LiteralPath $source -File|ForEach-Object{Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $Destination $_.Name)}
. (Join-Path $PSScriptRoot '..\cleanup-tools\load_dnlib.ps1') -DnlibPath $DnlibPath
$m=[dnlib.DotNet.ModuleDefMD]::Load((Join-Path $source 'AgileDevirtualizer.dll'))
$refs=@($m.GetMemberRefs());$changed=[Collections.Generic.List[object]]::new()
function T([string]$name){$a=@($m.GetTypes()|Where-Object{$_.FullName -eq $name});if($a.Count -ne 1){throw "Type $name"};return $a[0]}
function TM([string]$type,[string]$name){$a=@((T $type).Methods|Where-Object{$_.Name -eq $name});if($a.Count -ne 1){throw "Method $type::$name"};return $a[0]}
function IM([string]$name){return TM 'AgileDevirtualizer.Lift.ExecuteInterpreter' $name}
function SM([string]$type,[string]$name){return TM ('AgileDevirtualizer.Lift.SymValue/'+$type) $name}
function FindRef([string]$full){$a=@($refs|Where-Object{$_.FullName -eq $full});if($a.Count -ne 1){throw "Reference $full count=$($a.Count)"};return $a[0]}
function E($body,[string]$op,$operand=$null){$code=[dnlib.DotNet.Emit.OpCodes].GetField($op).GetValue($null);$i=[dnlib.DotNet.Emit.Instruction]::new($code);if($null -ne $operand){$i.Operand=$operand};$body.Instructions.Add($i)}
function Label(){return [dnlib.DotNet.Emit.Instruction]::Create([dnlib.DotNet.Emit.OpCodes]::Nop)}
function B(){return [dnlib.DotNet.Emit.CilBody]::new()}
function Prepend($method,$prefix){for($i=$prefix.Instructions.Count-1;$i -ge 0;$i--){$method.Body.Instructions.Insert(0,$prefix.Instructions[$i])};$changed.Add($method)}
function CodeField([string]$name){$full='AsmResolver.PE.DotNet.Cil.CilOpCode AsmResolver.PE.DotNet.Cil.CilOpCodes::'+$name;$a=@($refs|Where-Object{$_.FullName -eq $full});if($a.Count -eq 1){return $a[0]};$p=FindRef 'AsmResolver.PE.DotNet.Cil.CilOpCode AsmResolver.PE.DotNet.Cil.CilOpCodes::Ldloca';return [dnlib.DotNet.MemberRefUser]::new($m,$name,$p.FieldSig,$p.Class)}
function OpMethod([string]$name){return TM 'AgileDevirtualizer.Analysis.SemanticOperation' $name}
$operationEnum=T 'AgileDevirtualizer.Analysis.SemanticOperationCode'
$next=1+(@($operationEnum.Fields|Where-Object{$_.HasConstant}|ForEach-Object{[int]$_.Constant.Value})|Measure-Object -Maximum).Maximum
$instanceCode=[int]$next;$staticCode=$instanceCode+1
foreach($item in @(@('LoadFieldAddress_StaticPatch',$instanceCode),@('LoadStaticFieldAddress_StaticPatch',$staticCode))){
 $f=[dnlib.DotNet.FieldDefUser]::new([string]$item[0],[dnlib.DotNet.FieldSig]::new([dnlib.DotNet.ValueTypeSig]::new($operationEnum)),([dnlib.DotNet.FieldAttributes]::Public -bor [dnlib.DotNet.FieldAttributes]::Static -bor [dnlib.DotNet.FieldAttributes]::Literal -bor [dnlib.DotNet.FieldAttributes]::HasDefault))
 $f.Constant=[dnlib.DotNet.ConstantUser]::new([int]$item[1]);$operationEnum.Fields.Add($f)
}
$pe=[dnlib.DotNet.ModuleDefMD]::Load((Join-Path $source 'AsmResolver.PE.dll'))
$nativeEnum=@($pe.GetTypes()|Where-Object{$_.FullName -eq 'AsmResolver.PE.DotNet.Cil.CilCode'})[0]
$ldflda=[int](@($nativeEnum.Fields|Where-Object{$_.Name -eq 'Ldflda'})[0].Constant.Value)
$ldsflda=[int](@($nativeEnum.Fields|Where-Object{$_.Name -eq 'Ldsflda'})[0].Constant.Value)
$classify=TM 'AgileDevirtualizer.Analysis.LegacySemanticIrAdapter' 'Classify';$b=B;$other=Label
E $b Ldarg_0;E $b Ldc_I4 $ldflda;E $b Bne_Un $other;E $b Ldc_I4 $instanceCode;E $b Ret
$b.Instructions.Add($other);E $b Ldarg_0;E $b Ldc_I4 $ldsflda;E $b Bne_Un $classify.Body.Instructions[0];E $b Ldc_I4 $staticCode;E $b Ret;Prepend $classify $b
$lower=@((T 'AgileDevirtualizer.Analysis.SemanticCilLowerer').Methods|Where-Object{$_.Name -eq 'TryLower' -and $_.MethodSig.Params.Count -eq 2})[0]
$b=B;$other=Label
E $b Ldarg_0;E $b Callvirt (OpMethod 'get_Code');E $b Ldc_I4 $instanceCode;E $b Bne_Un $other
E $b Ldarg_1;E $b Ldsfld (CodeField 'Ldflda');E $b Stobj $lower.MethodSig.Params[1].Next.TypeDefOrRef;E $b Ldc_I4_1;E $b Ret
$b.Instructions.Add($other);E $b Ldarg_0;E $b Callvirt (OpMethod 'get_Code');E $b Ldc_I4 $staticCode;E $b Bne_Un $lower.Body.Instructions[0]
E $b Ldarg_1;E $b Ldsfld (CodeField 'Ldsflda');E $b Stobj $lower.MethodSig.Params[1].Next.TypeDefOrRef;E $b Ldc_I4_1;E $b Ret;Prepend $lower $b
$transfer=TM 'AgileDevirtualizer.Analysis.SemanticTransfer' 'Apply';$b=B;$instance=Label;$materialize=Label
E $b Ldarg_0;E $b Callvirt (OpMethod 'get_Code');E $b Ldc_I4 $instanceCode;E $b Beq $instance
E $b Ldarg_0;E $b Callvirt (OpMethod 'get_Code');E $b Ldc_I4 $staticCode;E $b Beq $materialize;E $b Br $transfer.Body.Instructions[0]
$b.Instructions.Add($instance);E $b Ldarg_1;E $b Callvirt (TM 'AgileDevirtualizer.Analysis.AbstractStateBuilder' 'Pop');E $b Pop
$b.Instructions.Add($materialize)
E $b Ldarg_1;E $b Ldarg_0;E $b Callvirt (OpMethod 'get_Operand');E $b Call (TM 'AgileDevirtualizer.Analysis.SemanticTransfer' 'FieldValue')
E $b Callvirt (TM 'AgileDevirtualizer.Analysis.AbstractValue' 'get_ExactType');E $b Call (TM 'AgileDevirtualizer.Analysis.AbstractValue' 'ManagedPointer');E $b Callvirt (TM 'AgileDevirtualizer.Analysis.AbstractStateBuilder' 'Push');E $b Ret;Prepend $transfer $b
$stack=TM 'AgileDevirtualizer.Analysis.SsaStackSemantics' 'ForOperation';$b=B;$other=Label
E $b Ldarg_0;E $b Callvirt (OpMethod 'get_Code');E $b Ldc_I4 $instanceCode;E $b Bne_Un $other;E $b Ldc_I4_1;E $b Ldc_I4_1;E $b Call (TM 'AgileDevirtualizer.Analysis.SsaStackSemantics' 'General');E $b Ret
$b.Instructions.Add($other);E $b Ldarg_0;E $b Callvirt (OpMethod 'get_Code');E $b Ldc_I4 $staticCode;E $b Bne_Un $stack.Body.Instructions[0];E $b Ldc_I4_0;E $b Ldc_I4_1;E $b Call (TM 'AgileDevirtualizer.Analysis.SsaStackSemantics' 'General');E $b Ret;Prepend $stack $b
$inference=TM 'AgileDevirtualizer.Analysis.SsaValueInference' 'ForOperation';$b=B;$materialize=Label
E $b Ldarg_0;E $b Callvirt (OpMethod 'get_Code');E $b Ldc_I4 $instanceCode;E $b Beq $materialize
E $b Ldarg_0;E $b Callvirt (OpMethod 'get_Code');E $b Ldc_I4 $staticCode;E $b Bne_Un $inference.Body.Instructions[0]
$b.Instructions.Add($materialize);E $b Ldarg_0;E $b Callvirt (OpMethod 'get_Operand');E $b Call (TM 'AgileDevirtualizer.Analysis.SsaValueInference' 'FieldValue');E $b Callvirt (TM 'AgileDevirtualizer.Analysis.AbstractValue' 'get_ExactType');E $b Call (TM 'AgileDevirtualizer.Analysis.AbstractValue' 'ManagedPointer');E $b Ret;Prepend $inference $b

# LXY.MnY dereferences RHY wrappers. A value setter writes through an existing
# managed pointer; this is different from dropping the call as bookkeeping.
$interp=T 'AgileDevirtualizer.Lift.ExecuteInterpreter';$sym=T 'AgileDevirtualizer.Lift.SymValue';$onStack=T 'AgileDevirtualizer.Lift.SymValue/OnStack'
$descriptor=@($m.GetTypeRefs()|Where-Object{$_.FullName -eq 'AsmResolver.DotNet.IMethodDescriptor'})[0]
$definition=@($m.GetTypeRefs()|Where-Object{$_.FullName -eq 'AsmResolver.DotNet.MethodDefinition'})[0]
$signature=@($m.GetTypeRefs()|Where-Object{$_.FullName -eq 'AsmResolver.DotNet.Signatures.TypeSignature'})[0]
$sig=[dnlib.DotNet.MethodSig]::CreateInstance($m.CorLibTypes.Boolean,[dnlib.DotNet.TypeSig[]]@([dnlib.DotNet.ClassSig]::new($descriptor),[dnlib.DotNet.ClassSig]::new($definition)))
$helper=[dnlib.DotNet.MethodDefUser]::new('TryHandlePointerValueAccess_StaticPatch',$sig,[dnlib.DotNet.MethodImplAttributes]::IL,([dnlib.DotNet.MethodAttributes]::Private -bor [dnlib.DotNet.MethodAttributes]::HideBySig))
$helper.Body=B;$helper.Body.InitLocals=$true;$interp.Methods.Add($helper);$changed.Add($helper);$b=$helper.Body
foreach($s in @([dnlib.DotNet.ClassSig]::new($onStack),[dnlib.DotNet.ClassSig]::new($sym),[dnlib.DotNet.ClassSig]::new($signature))){$b.Variables.Add([dnlib.DotNet.Emit.Local]::new($s))|Out-Null}
$evalField=@($interp.Fields|Where-Object{$_.Name -eq '_eval'})[0];$vocabField=@($interp.Fields|Where-Object{$_.Name -eq '_vocab'})[0]
$count=FindRef 'System.Int32 System.Collections.Generic.Stack`1<AgileDevirtualizer.Lift.SymValue>::get_Count()'
$peek=FindRef 'AgileDevirtualizer.Lift.SymValue System.Collections.Generic.Stack`1<AgileDevirtualizer.Lift.SymValue>::Peek()'
$push=FindRef 'System.Void System.Collections.Generic.Stack`1<AgileDevirtualizer.Lift.SymValue>::Push(AgileDevirtualizer.Lift.SymValue)'
$elementAt=@((IM 'TryHandleDefaultValueCall').Body.Instructions|Where-Object{$_.Operand -and $_.Operand.ToString() -like '*Enumerable::ElementAt<AgileDevirtualizer.Lift.SymValue>*'})[0].Operand
$isType=FindRef 'System.Boolean AsmResolver.DotNet.TypeDescriptorExtensions::IsTypeOf(AsmResolver.DotNet.ITypeDescriptor,System.String,System.String)'
$toType=FindRef 'AsmResolver.DotNet.ITypeDefOrRef AsmResolver.DotNet.Signatures.TypeSignature::ToTypeDefOrRef()'
$getterOwner=FindRef 'AsmResolver.DotNet.TypeDefinition AsmResolver.DotNet.MethodDefinition::get_DeclaringType()'
$getSignature=FindRef 'AsmResolver.DotNet.Signatures.MethodSignature AsmResolver.DotNet.IMethodDescriptor::get_Signature()'
$getVocabType=TM 'AgileDevirtualizer.Runtime.RuntimeVocabulary' 'get_ValueType'
$onStackCtor=@($onStack.Methods|Where-Object{$_.Name -eq '.ctor' -and $_.MethodSig.Params.Count -eq 4})[0]
$no=Label;$setter=Label;$knownValue=Label;$castReference=Label;$write=Label
E $b Ldarg_2;E $b Brfalse $no
E $b Ldarg_2;E $b Callvirt $getterOwner;E $b Ldarg_0;E $b Ldfld $vocabField;E $b Callvirt $getVocabType;E $b Bne_Un $no
E $b Ldarg_1;E $b Call (IM 'ParamCount');E $b Brtrue $setter
E $b Ldarg_0;E $b Ldfld $evalField;E $b Callvirt $count;E $b Brfalse $no
E $b Ldarg_1;E $b Call (IM 'SigReturn');E $b Ldstr 'System';E $b Ldstr 'Object';E $b Call $isType;E $b Brfalse $no
E $b Ldarg_0;E $b Ldfld $evalField;E $b Callvirt $peek;E $b Isinst $onStack;E $b Stloc_0
E $b Ldloc_0;E $b Brfalse $no;E $b Ldloc_0;E $b Callvirt (SM 'OnStack' 'get_ManagedPointer');E $b Brfalse $no
E $b Ldloc_0;E $b Callvirt (SM 'OnStack' 'get_KnownType');E $b Brfalse $no
E $b Ldarg_0;E $b Call (IM 'Pop');E $b Pop
E $b Ldarg_0;E $b Ldloc_0;E $b Call (IM 'EmitPush')
E $b Ldarg_0;E $b Ldsfld (CodeField 'Ldobj');E $b Ldloc_0;E $b Callvirt (SM 'OnStack' 'get_KnownType');E $b Callvirt $toType;E $b Call (IM 'Emit')
E $b Ldarg_0;E $b Ldfld $evalField;E $b Ldloc_0;E $b Callvirt (SM 'OnStack' 'get_KnownType');E $b Ldc_I4_0;E $b Ldc_I4_0;E $b Ldc_I4_0;E $b Newobj $onStackCtor;E $b Callvirt $push;E $b Ldc_I4_1;E $b Ret
$b.Instructions.Add($setter)
E $b Ldarg_0;E $b Ldarg_2;E $b Ldarg_1;E $b Callvirt $getSignature;E $b Call (IM 'IsValueSetter');E $b Brfalse $no
E $b Ldarg_0;E $b Ldfld $evalField;E $b Callvirt $count;E $b Ldc_I4_2;E $b Blt $no
E $b Ldarg_0;E $b Ldfld $evalField;E $b Callvirt $peek;E $b Isinst (T 'AgileDevirtualizer.Lift.SymValue/DefaultValue');E $b Brtrue $no
E $b Ldarg_0;E $b Ldfld $evalField;E $b Ldc_I4_1;E $b Call $elementAt;E $b Isinst $onStack;E $b Stloc_0
E $b Ldloc_0;E $b Brfalse $no;E $b Ldloc_0;E $b Callvirt (SM 'OnStack' 'get_ManagedPointer');E $b Brfalse $no
E $b Ldloc_0;E $b Callvirt (SM 'OnStack' 'get_Peeked');E $b Brtrue $no
E $b Ldloc_0;E $b Callvirt (SM 'OnStack' 'get_KnownType');E $b Brfalse $no
E $b Ldarg_0;E $b Call (IM 'Pop');E $b Stloc_1;E $b Ldarg_0;E $b Call (IM 'Pop');E $b Pop
E $b Ldarg_0;E $b Ldloc_1;E $b Call (IM 'EmitPush')
E $b Ldarg_0;E $b Ldloc_1;E $b Call (IM 'KnownTypeOf');E $b Stloc_2;E $b Ldloc_2;E $b Brfalse $write
E $b Ldloc_2;E $b Ldstr 'System';E $b Ldstr 'Object';E $b Call $isType;E $b Brfalse $write
E $b Ldloc_0;E $b Callvirt (SM 'OnStack' 'get_KnownType');E $b Callvirt (FindRef 'System.Boolean AsmResolver.DotNet.Signatures.TypeSignature::get_IsValueType()');E $b Brfalse $castReference
E $b Ldarg_0;E $b Ldsfld (CodeField 'Unbox_Any');E $b Ldloc_0;E $b Callvirt (SM 'OnStack' 'get_KnownType');E $b Callvirt $toType;E $b Call (IM 'Emit');E $b Br $write
$b.Instructions.Add($castReference)
E $b Ldarg_0;E $b Ldsfld (CodeField 'Castclass');E $b Ldloc_0;E $b Callvirt (SM 'OnStack' 'get_KnownType');E $b Callvirt $toType;E $b Call (IM 'Emit')
$b.Instructions.Add($write)
E $b Ldarg_0;E $b Ldsfld (CodeField 'Stobj');E $b Ldloc_0;E $b Callvirt (SM 'OnStack' 'get_KnownType');E $b Callvirt $toType;E $b Call (IM 'Emit');E $b Ldc_I4_1;E $b Ret
$b.Instructions.Add($no);E $b Ldc_I4_0;E $b Ret
$default=IM 'TryHandleDefaultValueCall';$b=B
E $b Ldarg_0;E $b Ldarg_1;E $b Ldarg_2;E $b Call $helper;E $b Brfalse $default.Body.Instructions[0];E $b Ldc_I4_1;E $b Ret;Prepend $default $b
foreach($method in $changed){$method.Body.SimplifyBranches();$method.Body.OptimizeBranches();$method.Body.KeepOldMaxStack=$false}
$out=Join-Path $Destination 'AgileDevirtualizer.dll'
$options=[dnlib.DotNet.Writer.ModuleWriterOptions]::new($m);$options.MetadataOptions.Flags=[dnlib.DotNet.Writer.MetadataFlags]::PreserveAll
$m.Write($out,$options)
$check=[dnlib.DotNet.ModuleDefMD]::Load($out)
$record=[ordered]@{event='static_tool_il_patch_phase2';source=(Join-Path $source 'AgileDevirtualizer.dll');source_sha256=(Get-FileHash -LiteralPath (Join-Path $source 'AgileDevirtualizer.dll')).Hash.ToLower();modified=$out;modified_sha256=(Get-FileHash -LiteralPath $out).Hash.ToLower();changed_methods=@($changed|ForEach-Object{$_.FullName});new_semantic_codes=@($instanceCode,$staticCode);compiler_executed=$false;target_executed=$false;reopened=$true}
$record|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $Destination 'patch-phase2-provenance.json') -Encoding utf8
$record|ConvertTo-Json -Depth 6
