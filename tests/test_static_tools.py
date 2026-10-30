"""Sample-free checks. No target execution, target loading, or compilation."""
from pathlib import Path
from types import SimpleNamespace
import contextlib
import io
import json
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import unpacker as u

class StaticToolsTests(unittest.TestCase):
    def test_opcode_table(self):
        ops = u.opcode_table()
        self.assertEqual(ops[0x2a]['name'], 'ret')
        parsed = list(u.instructions(bytes.fromhex('16022a'), ops))
        self.assertEqual([x['name'] for x in parsed], ['ldc.i4.0', 'ldarg.0', 'ret'])

    def test_invalid_input_rejected(self):
        with self.assertRaises(u.Invalid):
            u.PE(bytes(1024))

    def test_bundled_tool_is_managed_pe(self):
        p = ROOT/'vendor'/'AgileDevirtualizer-v1.0.1'/'AgileDevirtualizer.dll'
        pe = u.PE(p.read_bytes())
        self.assertGreater(pe.rows.get(2, 0), 1)
        self.assertGreater(pe.rows.get(6, 0), 1)

    def test_known_profile_hash(self):
        folder = ROOT/'vendor'/'AgileDevirtualizer-SeroXen-staticfix'
        profile = json.loads((folder/'profile.json').read_text(encoding='utf-8-sig'))
        self.assertEqual(u.digest((folder/profile['assembly']).read_bytes()), profile['assembly_sha256'])
        self.assertFalse(profile['target_execution_required'])
        self.assertFalse(profile['compilation_required'])

    def test_resource_delta_roundtrip_and_overwrite_guard(self):
        source = ROOT/'vendor'/'AgileDevirtualizer-v1.0.1'/'AgileDevirtualizer.dll'
        before = source.read_bytes()
        after = bytearray(before)
        after[0x28] ^= 1  # DOS reserved byte in a trusted utility fixture, not application IL.
        with tempfile.TemporaryDirectory(prefix='static-delta-') as temp:
            temp = Path(temp)
            patch, output = temp/'delta.json', temp/'output.bin'
            u.write_resource_delta(before, bytes(after), patch)
            args = SimpleNamespace(source=source, patch=patch, output=output)
            with contextlib.redirect_stdout(io.StringIO()):
                u.apply_patch_file(args)
            self.assertEqual(output.read_bytes(), bytes(after))
            self.assertEqual(source.read_bytes(), before)
            with self.assertRaises(u.Invalid):
                u.apply_patch_file(args)

if __name__ == '__main__':
    unittest.main()
