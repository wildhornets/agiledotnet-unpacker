#!/usr/bin/env python3
"""Static, no-build readability pipeline for the supplied Agile.NET sample.

Runs the bundled prebuilt devirtualizer, never the input program. For analysis
only: remaining encrypted methods are NOT silently classified as recovered.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
HOME = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('static_unpacker', HOME / 'unpacker.py')
u = importlib.util.module_from_spec(spec)
spec.loader.exec_module(u)


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def rollback_text(baseline_sha, modified_sha):
    return '''#!/bin/sh
""":"
if command -v python3 >/dev/null 2>&1; then exec python3 -B "$0" "$@"; fi
exec python -B "$0" "$@"
":"""
import hashlib
import os
from pathlib import Path
import sys
import tempfile
BASELINE_SHA = %r
MODIFIED_SHA = %r
def sha(b): return hashlib.sha256(b).hexdigest()
def main():
    if len(sys.argv) != 2:
        print('Usage: ROLLBACK.sh TARGET_COPY', file=sys.stderr); return 2
    base = Path(__file__).resolve().parent / 'result' / 'baseline.bin'
    target = Path(sys.argv[1]).resolve()
    if target == base.resolve():
        print('ERROR: Cannot overwrite baseline', file=sys.stderr); return 1
    clean = base.read_bytes()
    if sha(clean) != BASELINE_SHA:
        print('ERROR: Baseline hash mismatch', file=sys.stderr); return 1
    if not target.is_file() or sha(target.read_bytes()) != MODIFIED_SHA:
        print('ERROR: Target is not the verified modified image', file=sys.stderr); return 1
    fd, name = tempfile.mkstemp(prefix='.rollback-', dir=str(target.parent))
    try:
        with os.fdopen(fd, 'wb') as f: f.write(clean)
        os.replace(name, target)
    finally:
        if os.path.exists(name): os.unlink(name)
    if sha(target.read_bytes()) != BASELINE_SHA:
        print('ERROR: Restored hash mismatch', file=sys.stderr); return 1
    print('ROLLBACK_OK SHA256=' + BASELINE_SHA)
    return 0
if __name__ == '__main__':
    try: sys.exit(main())
    except OSError as e:
        print('ERROR: ' + str(e), file=sys.stderr); sys.exit(1)
''' % (baseline_sha, modified_sha)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('source', type=Path)
    p.add_argument('--runtime', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True, help='NEW output directory')
    p.add_argument('--resume-candidate', type=Path, help='Resume verification of an already observed successful run')
    p.add_argument('--resume-execution', type=Path)
    p.add_argument('--stage1-result', type=Path)
    args = p.parse_args()
    source, runtime, out = args.source.resolve(), args.runtime.resolve(), args.out.resolve()
    data = source.read_bytes()
    before = u.PE(data)
    source_sha = u.digest(data)
    if out.exists() and not args.resume_candidate:
        raise ValueError('Choose a NEW output directory; no overwrite by default')
    if args.resume_candidate and not (args.stage1_result and args.resume_execution):
        raise ValueError('Resume requires existing stage1-result and command_execution record')
    out.mkdir(parents=True, exist_ok=bool(args.resume_candidate))
    result = out / 'result'
    result.mkdir(exist_ok=True)
    events = []

    def run(label, cmd, expected=0):
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_NOLOGO='1')
        proc = subprocess.run([str(x) for x in cmd], cwd=str(out), env=env,
                              capture_output=True, text=True, encoding='utf-8')
        events.append(dict(event='command_execution', label=label, command=[str(x) for x in cmd],
                           cwd=str(out), stdout=proc.stdout, stderr=proc.stderr, exit_status=proc.returncode))
        print(label + ' exit=' + str(proc.returncode), flush=True)
        print(proc.stdout.strip(), flush=True)
        if proc.stderr:
            print(proc.stderr.strip(), flush=True)
        if proc.returncode != expected:
            raise ValueError(label + ' failed; see literal command output')
        return proc

    if args.resume_candidate:
        old_exec = json.loads(args.resume_execution.read_text(encoding='utf-8'))
        if old_exec.get('event') != 'command_execution' or old_exec.get('exit_status') != 0:
            raise ValueError('Resume record is not an observed successful command execution')
        stage1 = args.stage1_result.resolve()
        stage_report = json.loads((stage1 / 'report.json').read_text(encoding='utf-8'))
        if stage_report['baseline']['sha256'] != source_sha:
            raise ValueError('Resume baseline identity mismatch')
        candidate = args.resume_candidate.resolve()
        if str(candidate) != old_exec['command'][3]:
            raise ValueError('Candidate path does not match observed command')
        vm_stdout = Path(old_exec['stdout_path']).read_text(encoding='utf-8')
        old_exec['label'] = 'RESUMED_SUCCESSFUL_VM_DECODE'
        old_exec['stdout'] = vm_stdout
        old_exec['stderr'] = Path(old_exec['stderr_path']).read_text(encoding='utf-8')
        events.append(old_exec)
        origin_label = candidate.parent.parent.name if candidate.parent.name=='result' else candidate.parent.name
        archive = out / 'runs' / origin_label / 'previous-confirmed'
        if archive.exists():
            pristine = archive / 'result' / 'baseline.bin'
            if not pristine.is_file() or sha(pristine) != source_sha:
                raise ValueError('Existing archive belongs to a different baseline')
            print('REUSING_VERIFIED_PREVIOUS_STATE_ARCHIVE ' + str(archive), flush=True)
        for relative in ['result/SeroXen.unpacked.bin', 'result/DIFF.json', 'result/report.json',
                         'result/baseline.bin', 'ROLLBACK.sh', 'VERIFICATION.txt', 'verification.json', 'READ_THIS.txt']:
            existing = out / relative
            if existing.is_file() and not (archive / relative).exists():
                dest = archive / relative
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(existing, dest)
    else:
        stage1 = out / 'stage1'
        run('STATIC_PREPARATION', [sys.executable, '-B', HOME / 'unpacker.py', 'unpack', source,
                                  '--out', stage1, '--allow-partial'])
        # These files are read as metadata by the lifter, never imported/executed.
        # Missing local references otherwise prevent field static-ness resolution.
        references = []
        for reference in source.parent.glob('*.dll'):
            copied = stage1 / reference.name
            shutil.copyfile(reference, copied)
            references.append(dict(source=str(reference), copy=str(copied), sha256=sha(reference)))
        (stage1 / 'reference-provenance.json').write_text(json.dumps(references, indent=2), encoding='utf-8')
        stage_report = json.loads((stage1 / 'report.json').read_text(encoding='utf-8'))
        candidate = result / 'SeroXen.unpacked.bin'
        exe = HOME / 'vendor' / 'AgileDevirtualizer-v1.0.1' / 'AgileDevirtualizer.exe'
        profile_path = HOME / 'vendor' / 'AgileDevirtualizer-SeroXen-staticfix' / 'profile.json'
        if profile_path.is_file():
            profile = json.loads(profile_path.read_text(encoding='utf-8'))
            if profile['source_sha256'] == source_sha and profile['runtime_sha256'] == sha(runtime):
                patched = profile_path.parent / profile['assembly']
                if sha(patched) != profile['assembly_sha256']:
                    raise ValueError('Bound static VM tool profile hash mismatch')
                exe = profile_path.parent / profile['executable']
        proc = run('VM_DECODE', [exe, stage1 / 'SeroXen.unpacked.bin', runtime, candidate, '--show-failures'])
        vm_stdout = proc.stdout

    image = candidate.read_bytes()
    after = u.PE(image)
    vm_records = json.loads((stage1 / 'vm_methods.json').read_text(encoding='utf-8'))
    # Nested types can be reordered by AsmResolver. Never equate raw RIDs across
    # rebuilt files: use complete declaring-type chains and normalized signatures.
    source_ids = u.method_identities(before)
    output_ids = u.method_identities(after)
    if set(source_ids) != set(output_ids):
        raise ValueError('The rebuilt image lost or added method identities unexpectedly')
    source_keys = {rid:key for key,rid in source_ids.items()}
    failed = {int(x,16) for x in re.findall(
        r'0x(06[0-9A-Fa-f]{6})[^\r\n]*?: (?:not fully lifted|semantic emission rejected|rejected)', vm_stdout)}
    recovered, remaining, unchanged = [], [], []
    for rec in vm_records:
        rid = int(rec['token'], 16) & 0xffffff
        mapped_rid = output_ids[source_keys[rid]]
        a, b = before.body(rid), after.body(mapped_rid)
        old_code = a['code'] if a else None
        new_code = b['code'] if b else None
        row = dict(token=rec['token'], original_token=rec['token'],
                   output_token='0x%08X'%(0x06000000|mapped_rid), name=rec['name'],
                   qualified_name=source_keys[rid][0]+'::'+source_keys[rid][1],
                   baseline_cil_size=a['size'] if a else None,
                   modified_cil_size=b['size'] if b else None, body_changed=old_code != new_code)
        if int(rec['token'],16) in failed:
            remaining.append(row)
        elif b is not None:
            recovered.append(row)
            if old_code == new_code:
                unchanged.append(row)
        else:
            raise ValueError('Accepted method has no readable body: '+rec['token'])
    observed = re.search(r'Devirtualized (\d+)/(\d+) method', vm_stdout)
    if not observed or int(observed[1]) != len(recovered) or int(observed[2]) != len(vm_records):
        raise ValueError('Independent method comparison disagrees with tool output')
    encrypted_nonvm = []
    encrypted_total = 0
    cipher_recovered = stage_report.get('method_recovery_error') is None and stage_report.get('restored_methods',0)>0
    if cipher_recovered:
        crypto_header = u.header(before)
        vm_rids = {int(r['token'],16)&0xffffff for r in vm_records}
        table = crypto_header['offset'] + 48 + crypto_header['total']
        for rid in range(1,crypto_header['count']+1):
            if not u.num(before.data,table+(rid-1)*16):continue
            encrypted_total += 1
            if rid in vm_rids:continue
            mapped = output_ids[source_keys[rid]]
            original_body, final_body = before.body(rid), after.body(mapped)
            if final_body is None:
                raise ValueError('Decrypted non-VM body was lost: %08X'%(0x06000000|rid))
            encrypted_nonvm.append(dict(original_token='0x%08X'%(0x06000000|rid),
                output_token='0x%08X'%(0x06000000|mapped),
                qualified_name=source_keys[rid][0]+'::'+source_keys[rid][1],
                baseline_cil_size=original_body['size'] if original_body else None,
                modified_cil_size=final_body['size']))
        if encrypted_total != stage_report['restored_methods']:
            raise ValueError('Encrypted-body recovery count disagrees with original header')
    ops = u.opcode_table()
    parsed = 0
    for rid, body in u.all_bodies(after, {}):
        ins = list(u.instructions(body['code'], ops))
        boundaries = {x['offset'] for x in ins}
        for x in ins:
            targets = x['operand'] if x['kind'] == 'InlineSwitch' else (
                [x['operand']] if x['kind'] in ('InlineBrTarget', 'ShortInlineBrTarget') else [])
            if any(t not in boundaries for t in targets):
                raise ValueError('Invalid branch target in method %08X' % (0x06000000 | rid))
        parsed += 1
    if not recovered:
        raise ValueError('No method bodies were recovered')

    modified = result / 'SeroXen.unpacked.bin'
    diff = result / 'DIFF.json'
    rollback = out / 'ROLLBACK.sh'
    verification = out / 'VERIFICATION.txt'
    if candidate != modified:
        shutil.copyfile(candidate, modified)
        companion = candidate.with_name('C5VM.dll')
        if companion.is_file():
            shutil.copyfile(companion, result / 'C5VM.dll')
    (result / 'baseline.bin').write_bytes(data)
    u.write_resource_delta(data, image, diff)
    rollback.write_text(rollback_text(source_sha, u.digest(image)), encoding='utf-8', newline='\n')
    os.chmod(rollback, 0o755)

    scratch = Path(tempfile.mkdtemp(prefix='verify-readable-', dir=str(out / 'runs' if (out / 'runs').exists() else out)))
    baseline_run = run('BASELINE', [sys.executable, '-B', HOME / 'unpacker.py', 'inspect', source])
    modified_run = run('MODIFIED', [sys.executable, '-B', HOME / 'unpacker.py', 'inspect', modified])
    restored = scratch / 'rollback-copy.bin'
    shutil.copyfile(modified, restored)
    if os.name == 'nt' and Path(r'C:\Program Files\Git\bin\bash.exe').is_file():
        run('EXECUTE_ROLLBACK_SH', [r'C:\Program Files\Git\bin\bash.exe', rollback.as_posix(), restored.as_posix()])
    else:
        run('EXECUTE_ROLLBACK_SH', [sys.executable, '-B', rollback, restored])
    rollback_run = run('ROLLBACK', [sys.executable, '-B', HOME / 'unpacker.py', 'inspect', restored])
    if baseline_run.stdout != rollback_run.stdout or sha(restored) != source_sha:
        raise ValueError('Rollback did not restore exact baseline')
    reconstructed = scratch / 'reconstructed.bin'
    run('RECONSTRUCT_DIFF', [sys.executable, '-B', HOME / 'unpacker.py', 'apply-patch', source, diff, reconstructed])
    if sha(reconstructed) != u.digest(image):
        raise ValueError('Diff reconstruction hash mismatch')
    # Reapply the exact verified GOAL bytes after exercising rollback on a separate copy.
    shutil.copyfile(reconstructed, modified)
    if sha(source) != source_sha:
        raise ValueError('Original input changed unexpectedly')
    il_errors = u.dump_il(after, ops, result / 'recovered.il')
    if il_errors:
        raise ValueError('Visible IL disassembly reported errors')
    roles = {'MODIFIED_FILE': str(modified), 'DIFF_FILE': str(diff),
             'VERIFICATION.txt': str(verification), 'ROLLBACK.sh': str(rollback)}
    report = dict(status=('READABLE_VM_COMPLETE' if not remaining and cipher_recovered else 'READABLE_PARTIAL'), target=str(source), baseline=u.summary(before),
                  modified=u.summary(after), restored_vm_methods=len(recovered),
                  vm_method_count=len(vm_records), remaining_vm_methods=remaining,
                  changed_recovered_vm_methods=len(recovered)-len(unchanged),
                  accepted_unchanged_vm_methods=unchanged,
                  stable_method_identities_matched=len(source_ids),
                  recovered_methods=recovered, parsed_visible_cil_bodies=parsed,
                  encrypted_method_cipher_recovered=cipher_recovered,
                  decrypted_encrypted_bodies=encrypted_total,
                  decrypted_nonvm_methods=len(encrypted_nonvm),
                  recovered_nonvm_method_records=encrypted_nonvm,
                  method_cipher_decoder=stage_report.get('attempted_method_decoder'),
                  known_header_constraints=stage_report.get('known_header_constraints',0),
                  fixed_proxy_calls=stage_report.get('resolved_proxy_calls',0),
                  inlined_string_calls=stage_report.get('inlined_string_calls',0),
                  target_executed=False, csharp_project_compiled=False, roles=roles,
                  limitations=[('Not a full unpack: '+str(len(remaining))+' VM methods remain rejected.' if remaining else 'All identified VM bodies recovered; runtime-equivalence and buildability are not claimed.'),
                               ('Identified non-VM encrypted bodies are decoded; runtime-equivalence is not tested.' if cipher_recovered
                                else 'Non-VM native-encrypted methods remain unresolved.'),
                               'Obfuscated names retained; source snapshot is not a buildable project.',
                               'Static readability verified, NOT runtime-equivalence tested. Never execute the sample.'])
    (result / 'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    (result / 'vm_methods.json').write_text(json.dumps(vm_records, indent=2), encoding='utf-8')
    ledger = dict(report=report, command_executions=events,
                  prior_results_preserved=str(archive) if args.resume_candidate else None,
                  identity_verification='Matched all declaring-type chains, method names and normalized signatures; raw MethodDef RIDs are not assumed stable.',
                  parser_compatibility='EH DataSize // clause size, accepting AsmResolver payload-only sizes.')
    (out / 'verification.json').write_text(json.dumps(ledger, indent=2), encoding='utf-8')
    with verification.open('w', encoding='utf-8', newline='\n') as f:
        f.write('STATUS: '+report['status']+' - STATIC ANALYSIS OUTPUT\nTARGET: ' + str(source) + '\n')
        f.write('Changed symbols/fields: MethodDef.RVA, local signatures, and CIL bodies of '+str(len(recovered)-len(unchanged))+' VM methods; '+str(len(unchanged))+' accepted methods retain identical bodies.\n')
        f.write('Observed entry CIL bytes: BASELINE='+str(report['baseline']['entrypoint']['cil_size'])+', MODIFIED='+str(report['modified']['entrypoint']['cil_size'])+', ROLLBACK='+str(report['baseline']['entrypoint']['cil_size'])+'\n')
        f.write('Observed delegate loads: BASELINE='+str(report['baseline']['visible_delegate_loads'])+', MODIFIED='+str(report['modified']['visible_delegate_loads'])+', ROLLBACK='+str(report['baseline']['visible_delegate_loads'])+'\n')
        f.write('Restored baseline SHA256=' + source_sha + '\nModified SHA256=' + sha(modified) + '\n')
        f.write('Recovered VM methods=' + str(len(recovered)) + '/' + str(len(vm_records)) + '; remaining=' + str(len(remaining)) + '\n')
        f.write('Method cipher recovered='+str(cipher_recovered)+'; decoded encrypted bodies='+str(encrypted_total)+'; non-VM='+str(len(encrypted_nonvm))+'; known-header byte constraints='+str(stage_report.get('known_header_constraints',0))+'\n')
        f.write('Stable method identities matched='+str(len(source_ids))+'. Nested definitions were reordered; output tokens are recorded per method.\n')
        for record in recovered:
            if record['name'] in ('ohM=.phM=::pxM=','rxs=.rhs=::tRs='):
                f.write('Additional observed body: '+record['name']+' '+record['original_token']+': '+str(record['baseline_cil_size'])+' -> '+str(record['modified_cil_size'])+' CIL bytes.\n')
        f.write('Original bytes unchanged. No sample/native-runtime execution. No C# project compilation.\n')
        f.write('No runtime equivalence claim: verification is static parsing, exact diff/rollback, and dnSpy readability.\n')
        for role, path in roles.items():
            f.write(role + ': ' + path + '\n')
        for event in events:
            f.write('\n=== ' + event['label'] + ' ===\nCOMMAND: ' + json.dumps(event['command']) + '\n')
            f.write('EXIT STATUS: ' + str(event['exit_status']) + '\n')
            f.write('LITERAL STDOUT BEGIN\n' + event['stdout'] + 'LITERAL STDOUT END\n')
            f.write('LITERAL STDERR BEGIN\n' + event['stderr'] + 'LITERAL STDERR END\n')
        f.write('\nRECOVERED METHOD RECORDS\n' + json.dumps(recovered, indent=2) + '\n')
        f.write('\nREMAINING VM METHOD RECORDS\n' + json.dumps(remaining, indent=2) + '\n')
        f.write('\nRECOVERED NON-VM METHOD RECORDS\n' + json.dumps(encrypted_nonvm, indent=2) + '\n')
    for role, path in roles.items():
        content = Path(path).read_bytes()
        if not content:
            raise ValueError('Empty final role: ' + role)
        if role == 'MODIFIED_FILE':
            u.summary(u.PE(content))
        elif role == 'DIFF_FILE':
            json.loads(content)
        else:
            content.decode('utf-8')
        print('ROLE_REOPENED ' + role + ' ' + path + ' SHA256=' + u.digest(content), flush=True)
    print(json.dumps(dict(status=report['status'],recovered_vm_methods=len(recovered),
                          decrypted_nonvm_methods=len(encrypted_nonvm),
                          entrypoint_cil_bytes=report['modified']['entrypoint']['cil_size'],
                          output=str(modified), original_unchanged=sha(source)==source_sha)), flush=True)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, u.Invalid) as exc:
        print('ERROR: ' + str(exc), file=sys.stderr)
        sys.exit(1)
