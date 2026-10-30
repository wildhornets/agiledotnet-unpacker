#!/usr/bin/env python3
"""Static Agile.NET method recovery; never imports or executes the input PE.

Supports the observed, header-constrained XOR/subtract-one byte transform and
legacy normal XOR / pro TEA-variant formats. CSVM devirtualization is
explicitly NOT implemented. Binary-format reference and algorithm attribution:
de4dot, MethodsDecrypter.cs (2011-2015 de4dot@gmail.com), GPL-3.0-or-later.
This tool is distributed under GPL-3.0-or-later. See LICENSE.txt / SOURCES.txt.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import uuid
import zlib

LIMIT = 256 * 1024 * 1024
NORMAL = bytes.fromhex('084465e18c82134c9c85b417da51ad25')
PRO = bytes.fromhex('68a0bb6013655f41ae42ab429b6b4ec1')


class Invalid(ValueError):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def cut(data, off, size):
    if off < 0 or size < 0 or off + size > len(data):
        raise Invalid('Out-of-bounds file range: %x + %x' % (off, size))
    return data[off:off + size]


def num(data, off, fmt='I'):
    return struct.unpack('<' + fmt, cut(data, off, struct.calcsize('<' + fmt)))[0]


def align(n, a):
    if not a or a & (a - 1):
        raise Invalid('Invalid PE alignment')
    return (n + a - 1) & ~(a - 1)


def compressed(data, pos):
    a = num(data, pos, 'B')
    if a < 0x80:
        return a, pos + 1
    if a < 0xc0:
        return ((a & 0x3f) << 8) | num(data, pos + 1, 'B'), pos + 2
    if a < 0xe0:
        return ((a & 31) << 24) | int.from_bytes(cut(data, pos + 1, 3), 'big'), pos + 4
    raise Invalid('Invalid compressed metadata integer')


# ECMA-335 II.22 table layouts; H/I are fixed integers, s/g/b are heap indexes.
SCHEMAS = {
    0: ['H','s','g','g','g'], 1: ['ResolutionScope','s','s'],
    2: ['I','s','s','TypeDefOrRef',4,6], 3: [4],
    4: ['H','s','b'], 5: [6], 6: ['I','H','H','s','b',8], 7: [8],
    8: ['H','H','s'], 9: [2,'TypeDefOrRef'],
    10: ['MemberRefParent','s','b'], 11: ['H','HasConstant','b'],
    12: ['HasCustomAttribute','CustomAttributeType','b'],
    13: ['HasFieldMarshal','b'], 14: ['H','HasDeclSecurity','b'],
    15: ['H','I',2], 16: ['I',4], 17: ['b'], 18: [2,20], 19: [20],
    20: ['H','s','TypeDefOrRef'], 21: [2,23], 22: [23], 23: ['H','s','b'],
    24: ['H',6,'HasSemantics'], 25: [2,'MethodDefOrRef','MethodDefOrRef'],
    26: ['s'], 27: ['b'], 28: ['H','MemberForwarded','s',26], 29: ['I',4],
    30: ['I','I'], 31: ['I'], 32: ['I','H','H','H','H','I','b','s','s'],
    33: ['I'], 34: ['I','I','I'], 35: ['H','H','H','H','I','b','s','s','b'],
    36: ['I',35], 37: ['I','I','I',35], 38: ['I','s','b'],
    39: ['I','I','s','s','Implementation'], 40: ['I','I','s','Implementation'],
    41: [2,2], 42: ['H','H','TypeOrMethodDef','s'],
    43: ['MethodDefOrRef','b'], 44: [42,'TypeDefOrRef'],
}
CODED = {
    'ResolutionScope': (2,[0,26,35,1]), 'TypeDefOrRef': (2,[2,1,27]),
    'MemberRefParent': (3,[2,1,26,6,27]), 'HasConstant': (2,[4,8,23]),
    'HasCustomAttribute': (5,[6,4,1,2,8,9,10,0,14,23,20,17,26,27,32,35,38,39,40,42,44,43]),
    'CustomAttributeType': (3,[6,10]), 'HasFieldMarshal': (1,[4,8]),
    'HasDeclSecurity': (2,[2,6,32]), 'HasSemantics': (1,[20,23]),
    'MethodDefOrRef': (1,[6,10]), 'MemberForwarded': (1,[4,6]),
    'Implementation': (2,[38,35,39]), 'TypeOrMethodDef': (1,[2,6]),
}


class PE:
    def __init__(self, data):
        self.data = data
        if cut(data, 0, 2) != b'MZ':
            raise Invalid('Not a PE file')
        self.pe = num(data, 0x3c)
        if cut(data, self.pe, 4) != b'PE\0\0':
            raise Invalid('Bad PE signature')
        self.opt = self.pe + 24
        magic = num(data, self.opt, 'H')
        if magic not in (0x10b, 0x20b):
            raise Invalid('Unsupported optional header')
        self.dirs = self.opt + (96 if magic == 0x10b else 112)
        self.section_alignment = num(data, self.opt + 32)
        self.file_alignment = num(data, self.opt + 36)
        self.sections = []
        for i in range(num(data, self.pe + 6, 'H')):
            off = self.opt + num(data, self.pe + 20, 'H') + i * 40
            vs, va, size, raw = struct.unpack('<IIII', cut(data, off + 8, 16))
            cut(data, raw, size)
            self.sections.append(dict(name=cut(data, off, 8).rstrip(b'\0').decode('ascii', 'replace'),
                                      header=off, virtual_size=vs, rva=va, raw_size=size, raw=raw))
        self.cli = self.offset(num(data, self.dirs + 14 * 8))
        self.md_rva, self.md_size = struct.unpack('<II', cut(data, self.cli + 8, 8))
        self.md = self.offset(self.md_rva)
        cut(data, self.md, self.md_size)
        if cut(data, self.md, 4) != b'BSJB':
            raise Invalid('Missing CLR metadata')
        self.entry = num(data, self.cli + 20)
        self.streams = {}
        off = align(self.md + 16 + num(data, self.md + 12), 4)
        count = num(data, off + 2, 'H')
        off += 4
        for _ in range(count):
            start, size = struct.unpack('<II', cut(data, off, 8))
            end = data.find(b'\0', off + 8, off + 40)
            if end < 0:
                raise Invalid('Unterminated metadata stream name')
            name = cut(data, off + 8, end - off - 8).decode('ascii')
            if start + size > self.md_size:
                raise Invalid('Metadata stream outside metadata')
            self.streams[name] = (self.md + start, size)
            off = align(end + 1, 4)
        tables = self.streams.get('#~', self.streams.get('#-'))
        if not tables:
            raise Invalid('Missing metadata tables')
        p, length = tables
        heap = num(data, p + 6, 'B')
        self.heap_sizes = {'s': 4 if heap & 1 else 2, 'g': 4 if heap & 2 else 2,
                           'b': 4 if heap & 4 else 2}
        valid = num(data, p + 8, 'Q')
        self.rows = {}
        pos = p + 24
        for table in range(64):
            if valid & (1 << table):
                self.rows[table] = num(data, pos)
                pos += 4
        if heap & 0x40:
            pos += 4
        self.tables = {}
        for table in sorted(self.rows):
            if table not in SCHEMAS:
                raise Invalid('Unsupported metadata table %d' % table)
            sizes = [self.index_size(x) for x in SCHEMAS[table]]
            row_size = sum(sizes)
            if pos + row_size * self.rows[table] > p + length:
                raise Invalid('Metadata table out of bounds')
            self.tables[table] = (pos, row_size, sizes)
            pos += row_size * self.rows[table]
        self.owners = {}
        types = list(self.iterrows(2))
        for i, row in enumerate(types):
            stop = types[i + 1][5] if i + 1 < len(types) else self.rows.get(6, 0) + 1
            for rid in range(row[5], stop):
                self.owners[rid] = i + 1

    def offset(self, rva):
        for section in self.sections:
            if section['rva'] <= rva < section['rva'] + section['raw_size']:
                return section['raw'] + rva - section['rva']
        if 0 <= rva < num(self.data, self.opt + 60):
            return rva
        raise Invalid('Unmapped RVA %08x' % rva)

    def index_size(self, x):
        if isinstance(x, int):
            return 4 if self.rows.get(x, 0) >= 65536 else 2
        if x in ('H', 'I'):
            return 2 if x == 'H' else 4
        if x in self.heap_sizes:
            return self.heap_sizes[x]
        bits, tables = CODED[x]
        return 4 if max(self.rows.get(t, 0) for t in tables) >= 1 << (16 - bits) else 2

    def row(self, table, rid):
        if not 1 <= rid <= self.rows.get(table, 0):
            raise Invalid('Invalid table RID %d:%d' % (table, rid))
        off, size, sizes = self.tables[table]
        pos = off + size * (rid - 1)
        values = []
        for n in sizes:
            values.append(num(self.data, pos, 'H' if n == 2 else 'I'))
            pos += n
        return values

    def iterrows(self, table):
        for rid in range(1, self.rows.get(table, 0) + 1):
            yield self.row(table, rid)

    def string(self, index):
        start, size = self.streams['#Strings']
        if index >= size:
            raise Invalid('String heap index out of bounds')
        end = self.data.find(b'\0', start + index, start + size)
        if end < 0:
            raise Invalid('Unterminated metadata string')
        return self.data[start + index:end].decode('utf-8', 'replace')

    def blob(self, index):
        start, size = self.streams['#Blob']
        length, pos = compressed(self.data, start + index)
        if pos + length > start + size:
            raise Invalid('Blob heap index out of bounds')
        return cut(self.data, pos, length)

    def user_string(self, token):
        start, size = self.streams['#US']
        index = token & 0xffffff
        length, pos = compressed(self.data, start + index)
        if not length or pos + length > start + size or length % 2 != 1:
            raise Invalid('Invalid user string')
        return cut(self.data, pos, length - 1).decode('utf-16le', 'surrogatepass'), pos, length

    def type_name(self, table, rid):
        row = self.row(table, rid)
        name = self.string(row[1])
        ns = self.string(row[2])
        return (ns + '.' if ns else '') + name

    def label(self, token):
        table, rid = token >> 24, token & 0xffffff
        try:
            if table == 0x70:
                return json.dumps(self.user_string(token)[0], ensure_ascii=True)
            if table in (1, 2):
                return self.type_name(table, rid)
            if table == 6:
                return self.type_name(2, self.owners[rid]) + '::' + self.string(self.row(6, rid)[3])
            if table == 4:
                return self.string(self.row(4, rid)[1])
            if table == 10:
                row = self.row(10, rid)
                tag, parent = row[0] & 7, row[0] >> 3
                t = [2, 1, 26, 6, 27][tag]
                owner = self.type_name(t, parent) if t in (1, 2) else 'token:%02x:%d' % (t,parent)
                return owner + '::' + self.string(row[1])
        except (Invalid, IndexError, KeyError):
            pass
        return '0x%08X' % token

    def body(self, rid):
        rva = self.row(6, rid)[0]
        if not rva:
            return None
        return method_body(self.data, self.offset(rva))

    def resources(self):
        rva, length = struct.unpack('<II', cut(self.data, self.cli + 24, 8))
        if not rva:
            return
        start = self.offset(rva)
        for rid, row in enumerate(self.iterrows(40), 1):
            if row[3]:
                continue  # linked resources are never opened
            off = start + row[0]
            size = num(self.data, off)
            if row[0] + size + 4 > length:
                raise Invalid('Resource exceeds CLR resource directory')
            yield rid, self.string(row[2]), cut(self.data, off + 4, size)


def method_body(data, off):
    first = num(data, off, 'B')
    if first & 3 == 2:
        size, head, flags = first >> 2, 1, 2
    elif first & 3 == 3:
        flags = num(data, off, 'H')
        head = (flags >> 12) * 4
        if head < 12:
            raise Invalid('Invalid fat method header')
        size = num(data, off + 4)
    else:
        raise Invalid('Invalid CIL method header')
    code = cut(data, off + head, size)
    end = off + head + size
    if flags & 8:
        p = align(end, 4)
        for _ in range(1024):
            kind = num(data, p, 'B')
            size2 = int.from_bytes(cut(data,p+1,3), 'little') if kind & 0x40 else num(data,p+1,'B')
            stride = 24 if kind & 0x40 else 12
            # dnlib/dnSpy use DataSize // clause_size. AsmResolver 6 writes
            # payload-only DataSize; other writers include the four-byte header.
            if (kind & 0x3f) != 1 or size2 % stride not in (0, 4):
                raise Invalid('Invalid exception-handler section')
            section_size = 4 + (size2 // stride) * stride
            cut(data, p, section_size)
            end = p + section_size
            if not kind & 0x80:
                break
            p = align(end, 4)
        else:
            raise Invalid('Too many method sections')
    return dict(offset=off, header=head, code=code, size=len(code), flags=flags,
                bytes=cut(data, off, end-off))


def opcode_table():
    path = Path(__file__).with_name('opcodes.json')
    return {x['code']: x for x in json.loads(path.read_text(encoding='utf-8-sig'))}


def instructions(code, ops):
    p = 0
    fixed = {'InlineNone':0, 'ShortInlineI':1, 'ShortInlineVar':1,
             'ShortInlineBrTarget':1, 'InlineVar':2, 'InlineI':4, 'InlineI8':8,
             'ShortInlineR':4, 'InlineR':8, 'InlineBrTarget':4,
             'InlineField':4, 'InlineMethod':4, 'InlineSig':4,
             'InlineString':4, 'InlineTok':4, 'InlineType':4}
    while p < len(code):
        start = p
        op = num(code, p, 'B'); p += 1
        if op == 0xfe:
            op = 0xfe00 | num(code, p, 'B'); p += 1
        if op not in ops:
            raise Invalid('Unknown CIL opcode %04x at %x' % (op,start))
        info = ops[op]
        kind = info['operand']
        operand = None
        if kind == 'InlineSwitch':
            count = num(code,p); p += 4
            if count > len(code) // 4:
                raise Invalid('Oversize switch')
            base = p + count * 4
            operand = [base + num(code,p+4*i,'i') for i in range(count)]
            p = base
        else:
            n = fixed[kind]
            raw = cut(code, p, n); p += n
            if n:
                if kind in ('ShortInlineR','InlineR'):
                    operand = struct.unpack('<' + ('f' if n == 4 else 'd'),raw)[0]
                else:
                    operand = int.from_bytes(raw,'little',signed=kind in
                        ('ShortInlineI','InlineI','InlineI8','ShortInlineBrTarget','InlineBrTarget'))
                if kind in ('ShortInlineBrTarget','InlineBrTarget'):
                    operand += p
        yield dict(offset=start, end=p, name=info['name'], kind=kind, operand=operand)


def pro_decrypt(data, key):
    out = bytearray(data)
    k = struct.unpack('>4I',key)
    mask = 0xffffffff
    for off in range(0,len(data)-7,8):
        a,b = struct.unpack_from('>II',data,off)
        s = 0xc6ef3700
        for _ in range(32):
            b = (b - (((a << 4) + k[2]) ^ (s + a) ^ ((a >> 5) + k[3]))) & mask
            a = (a - (((b << 4) + k[0]) ^ (s + b) ^ ((b >> 5) + k[1]))) & mask
            s = (s - 0x9e3779b8) & mask
        struct.pack_into('>II',out,off,a,b)
    return bytes(out)


def header(pe):
    pos = pe.md + pe.md_size
    sig = cut(pe.data,pos,16)
    if sig not in (PRO,NORMAL):
        raise Invalid('Supported Agile.NET header not found after metadata; no dynamic fallback')
    total,count,table,size = struct.unpack('<IIII',cut(pe.data,pos+32,16))
    mpos,msize,_ = pe.tables[6]
    if count != pe.rows[6] or table != mpos-pe.md or size != msize:
        raise Invalid('Unsupported Agile.NET header layout; expected 5.2+ table mapping')
    cut(pe.data,pos+48+total,count*16)
    return dict(offset=pos, total=total, count=count, key=cut(pe.data,pos+16,16),
                kind='PRO-TEA' if sig == PRO else 'NORMAL-XOR')


def derive_xor_sub1_key(pe, h):
    """Infer the observed byte transform from exact known fat-header fields.

    Cipher byte = (plain byte + 1) XOR key[global_position % 16].
    Require every constraint to agree, not a majority or a guessed profile key.
    The key is independently constrained by flags and local-signature tokens
    distributed through the original method table. All bodies are then parsed.
    """
    key = [None] * 16
    counts = [0] * 16
    table = h['offset'] + 48 + h['total']
    for rid in range(1, h['count'] + 1):
        off, size, flags, locals_token = struct.unpack('<IIII', cut(pe.data, table + (rid-1)*16, 16))
        if not off or not flags:
            continue
        if off < 48 or size < 12 or off + size > 48 + h['total']:
            return None
        encrypted = cut(pe.data, h['offset'] + off, size)
        known = [(0,flags & 255), (1,(flags >> 8) & 255)]
        known += [(8+i,(locals_token >> (8*i)) & 255) for i in range(4)]
        for pos, plain in known:
            phase = (off - 48 + pos) % 16
            value = encrypted[pos] ^ ((plain + 1) & 255)
            if key[phase] is not None and key[phase] != value:
                return None
            key[phase] = value
            counts[phase] += 1
    if any(v is None for v in key) or min(counts) < 8:
        return None
    return bytes(key), sum(counts)


def recovery(pe, ops):
    h = header(pe)
    inferred = derive_xor_sub1_key(pe, h)
    if inferred is not None:
        h['derived_key'], h['known_header_constraints'] = inferred
        h['decoder_name'] = 'verified-periodic-xor-sub1'
    else:
        h['decoder_name'] = h['kind']
    table = h['offset'] + 48 + h['total']
    bodies = {}
    checked_operands = 0
    operand_tables = {'InlineMethod':{6,10,43}, 'InlineField':{4,10},
                      'InlineType':{1,2,27}, 'InlineTok':{1,2,4,6,10,27,43},
                      'InlineSig':{17}, 'InlineString':{0x70}}
    for rid in range(1,h['count']+1):
        offset,size,flags,locals_token = struct.unpack('<IIII',cut(pe.data,table+(rid-1)*16,16))
        if not offset:
            continue
        if offset < 48 or offset + size > 48+h['total'] or not size:
            raise Invalid('Encrypted method range invalid at RID %d' % rid)
        enc = cut(pe.data,h['offset']+offset,size)
        if inferred is not None:
            plain = bytes(((value ^ h['derived_key'][(offset-48+i)%16]) - 1) & 255
                          for i,value in enumerate(enc))
        elif h['kind'] == 'PRO-TEA':
            plain = pro_decrypt(enc,h['key'])
        else:
            plain = bytes(x ^ h['key'][(offset-48+i)%16] ^ h['key'][(offset-48+i+7)%16]
                          for i,x in enumerate(enc))
        body = method_body(plain,0)
        if inferred is not None and flags:
            if num(plain,0,'H') != flags or num(plain,8) != locals_token:
                raise Invalid('Recovered header does not match method record: %d' % rid)
        # Check every restored body before writing anything. No guessed replacements.
        ins = list(instructions(body['code'],ops))
        valid = {x['offset'] for x in ins}
        for x in ins:
            targets = x['operand'] if x['kind'] == 'InlineSwitch' else (
                [x['operand']] if x['kind'] in ('InlineBrTarget','ShortInlineBrTarget') else [])
            if any(t not in valid for t in targets):
                raise Invalid('Invalid recovered branch target at RID %d' % rid)
            if inferred is not None and x['kind'] in operand_tables:
                token=x['operand'];token_table=token>>24;token_rid=token&0xffffff
                if token_table not in operand_tables[x['kind']]:
                    raise Invalid('Recovered operand has wrong token kind at RID %d'%rid)
                if token_table==0x70:
                    pe.user_string(token)
                elif not 1<=token_rid<=pe.rows.get(token_table,0):
                    raise Invalid('Recovered operand is outside metadata at RID %d'%rid)
                checked_operands+=1
        body['bytes'] = bytes(body['bytes'])
        bodies[rid] = body
    h['validated_metadata_operands']=checked_operands
    return h,bodies


def all_bodies(pe, recovered):
    for rid in range(1,pe.rows.get(6,0)+1):
        body = recovered.get(rid)
        if body is None and not (pe.row(6,rid)[1] & 3):
            body = pe.body(rid)
        if body is not None:
            yield rid, body


def find_string_key(pe, bodies, ops):
    for tr, row in enumerate(pe.iterrows(2),1):
        if not pe.string(row[1]).startswith(('<C5VM','<CliSecure')):
            continue
        methods = [rid for rid in pe.owners if pe.owners[rid] == tr]
        decryptors = {0x06000000|rid for rid in methods
                      if pe.blob(pe.row(6,rid)[4]) == bytes([0,1,14,14])}
        rvamap = {r[1]:r[0] for r in pe.iterrows(29)}
        for rid in methods:
            if pe.string(pe.row(6,rid)[3]) != '.cctor' or rid not in bodies:
                continue
            ins = list(instructions(bodies[rid]['code'],ops))
            for i,x in enumerate(ins):
                if x['name'] != 'ldtoken' or x['operand'] >> 24 != 4:
                    continue
                field = x['operand'] & 0xffffff
                if field not in rvamap:
                    continue
                size = None
                for j in range(max(1,i-3),i):
                    if ins[j]['name'] == 'newarr' and pe.label(ins[j]['operand']) == 'System.Byte':
                        prev = ins[j-1]
                        if prev['name'] in ('ldc.i4','ldc.i4.s'):
                            size = prev['operand']
                        elif re.fullmatch(r'ldc\.i4\.[0-8]',prev['name']):
                            size = int(prev['name'][-1])
                if size and 1 <= size <= 4096 and decryptors:
                    return cut(pe.data,pe.offset(rvamap[field]),size),decryptors
    return None,set()


def decode_strings(pe, bodies, ops, image):
    key,decryptors = find_string_key(pe,bodies,ops)
    if key is None:
        return [],0,[]
    uses = {}
    branch_targets = {}
    for rid,body in all_bodies(pe,bodies):
        ins = list(instructions(body['code'],ops))
        targets = set()
        for inst in ins:
            if inst['kind']=='InlineSwitch':targets.update(inst['operand'])
            elif inst['kind'] in ('InlineBrTarget','ShortInlineBrTarget'):targets.add(inst['operand'])
        branch_targets[rid]=targets
        for i,x in enumerate(ins):
            if x['name'] == 'ldstr':
                call = ins[i+1] if i+1 < len(ins) else None
                direct = bool(call and call['name'] == 'call' and call['operand'] in decryptors)
                uses.setdefault(x['operand'],[]).append((rid,call,direct))
    decoded = []
    patched = 0
    modified_existing = []
    for token,locations in uses.items():
        if not any(x[2] for x in locations):
            continue
        text,pos,length = pe.user_string(token)
        units = struct.unpack('<%dH' % len(text.encode('utf-16le','surrogatepass')[::2]),
                              text.encode('utf-16le','surrogatepass'))
        raw = struct.pack('<%dH' % len(units),*(x ^ key[i%len(key)] for i,x in enumerate(units)))
        plain = raw.decode('utf-16le','surrogatepass')
        safe = (all(x[2] for x in locations) and all(rid in bodies for rid,_,_ in locations)
                and all(call['offset'] not in branch_targets[rid] for rid,call,_ in locations))
        decoded.append(dict(token='0x%08X'%token,value=plain,inlined=safe))
        if not safe:
            continue
        image[pos:pos+length-1] = raw
        special = any(x > 0xff or 1 <= x <= 8 or 14 <= x <= 31 or x in (0x27,0x2d,0x7f)
                      for x in struct.unpack('<%dH'%len(units),raw))
        image[pos+length-1] = int(special)
        for rid,call,_ in locations:
            body = bodies[rid]
            b = bytearray(body['bytes'])
            start = body['header']+call['offset']
            b[start:start+call['end']-call['offset']] = bytes(call['end']-call['offset'])
            body['bytes'] = bytes(b)
            body['code'] = body['bytes'][body['header']:body['header']+body['size']]
            patched += 1
    return decoded,patched,modified_existing


def summary(pe):
    try:
        h = header(pe)
        protected = 'PRO-signature' if h['kind']=='PRO-TEA' else 'NORMAL-signature'
    except Invalid:
        protected = None
    body = pe.body(pe.entry & 0xffffff) if pe.entry >> 24 == 6 else None
    entry = {'token':'0x%08X'%pe.entry,'name':pe.label(pe.entry),
             'cil_size':body['size'] if body else None,
             'first_bytes':body['code'][:16].hex() if body else None}
    return dict(sha256=digest(pe.data),size=len(pe.data),types=pe.rows.get(2,0),
                methods=pe.rows.get(6,0),resources=pe.rows.get(40,0),
                agile_header=protected,entrypoint=entry,
                visible_delegate_loads=proxy_load_count(pe))


def signature(pe, token):
    table,rid=token>>24,token&0xffffff
    if table not in (6,10):
        raise Invalid('Unsupported call signature token')
    row=pe.row(table,rid)
    blob=pe.blob(row[4] if table==6 else row[2])
    flags=num(blob,0,'B');pos=1
    if flags & 16:
        _,pos=compressed(blob,pos)
    count,pos=compressed(blob,pos)
    return count,bool(flags&32),num(blob,pos,'B')==1


def proxy_fields(pe):
    fields={};delegates=set()
    types=list(pe.iterrows(2))
    for i,row in enumerate(types):
        tag,rid=row[3]&3,row[3]>>2
        if tag!=1 or pe.type_name(1,rid)!='System.MulticastDelegate':
            continue
        owner=i+1
        # Only Agile's exact three-instruction RID/creator/ret initializer.
        valid=False
        for mr in pe.owners:
            if pe.owners[mr]!=owner or pe.string(pe.row(6,mr)[3])!='.cctor':continue
            body=pe.body(mr)
            if not body:continue
            ins=list(instructions(body['code'],opcode_table()))
            if len(ins)!=3 or ins[1]['name']!='call' or ins[2]['name']!='ret':continue
            x=ins[0];value=x['operand']
            if re.fullmatch(r'ldc\.i4\.[0-8]',x['name']):value=int(x['name'][-1])
            if x['name'].startswith('ldc.i4') and value==owner-1:valid=True
        if not valid:continue
        delegates.add(owner)
        stop=types[i+1][4] if i+1<len(types) else pe.rows.get(4,0)+1
        for fr in range(row[4],stop):
            name=pe.string(pe.row(4,fr)[1])
            try:
                raw=base64.b64decode(name.rstrip('%'),validate=True)
                if len(raw)!=4:continue
                target=0x0a000000|(int.from_bytes(raw,'little')+1)
                count,hasthis,isvoid=signature(pe,target)
                if pe.label(target).endswith(('::.ctor','::.cctor')):continue
                fields[0x04000000|fr]=(owner,target,0x6f if name.endswith('%') else 0x28,
                                          count+int(hasthis),isvoid)
            except (ValueError,Invalid):continue
    return fields,delegates


def proxy_load_count(pe):
    fields,_=proxy_fields(pe);ops=opcode_table();count=0
    for _,body in all_bodies(pe,{}):
        count+=sum(x['name']=='ldsfld' and x['operand'] in fields for x in instructions(body['code'],ops))
    return count


def fix_proxy_calls(pe,bodies,ops):
    fields,delegates=proxy_fields(pe);changed=set();count=0
    for rid,body in bodies.items():
        code=bytearray(body['code']);ins=list(instructions(code,ops));stack=[]
        targets=set()
        for x in ins:
            if x['kind']=='InlineSwitch':targets.update(x['operand'])
            elif x['kind'] in ('InlineBrTarget','ShortInlineBrTarget'):targets.add(x['operand'])
        for x in ins:
            if x['offset'] in targets:stack=[]
            if x['name']=='dup':
                stack.append(stack[-1] if stack else None);continue
            if x['name'] in ('call','callvirt','newobj'):
                try:params,hasthis,isvoid=signature(pe,x['operand'])
                except Invalid:stack=[];continue
                pop=params+(int(hasthis) if x['name']!='newobj' else 0)
                receiver=stack[-pop] if pop and len(stack)>=pop else None
                owner=pe.owners.get(x['operand']&0xffffff) if x['operand']>>24==6 else None
                if (receiver is not None and x['name']=='call' and
                    pe.label(x['operand']).endswith('::Invoke') and owner in delegates):
                    load,field=receiver;fo,target,op,n,isv=fields[field]
                    if fo==owner and params==n and isv==isvoid:
                        code[load:load+5]=bytes(5)
                        code[x['offset']:x['end']]=bytes([op])+struct.pack('<I',target)
                        count+=1;changed.add(rid)
                stack=stack[:-pop] if pop and len(stack)>=pop else (stack if not pop else [])
                if x['name']=='newobj' or not isvoid:stack.append(None)
            else:
                info=next((ops[o] for o in ops if ops[o]['name']==x['name']),None)
                pop=info['pop'];push=info['push']
                if pop in ('Varpop','PopAll'):stack=[]
                elif pop!='Pop0':
                    n=len(pop.split('_'));stack=stack[:-n] if len(stack)>=n else []
                if push not in ('Push0','Varpush'):
                    n=len(push.split('_'));stack.extend([None]*n)
                    if x['name']=='ldsfld' and x['operand'] in fields:
                        stack[-1]=(x['offset'],x['operand'])
            info=next((ops[o] for o in ops if ops[o]['name']==x['name']),None)
            if info['flow'] in ('Branch','Cond_Branch','Return','Throw'):stack=[]
        if rid in changed:
            b=bytearray(body['bytes']);b[body['header']:body['header']+body['size']]=code
            body['bytes']=bytes(b);body['code']=bytes(code)
    return count,changed


def safe_name(name):
    return re.sub('[^a-zA-Z0-9._-]','_',name)[:100] or 'unnamed'


def method_identities(pe):
    """Stable method identities even when a PE writer reorders nested definitions.

    Raw MethodDef RIDs and TypeDefOrRef integers are NOT stable across such a
    rebuild. Normalize the enclosing type chain and all signature type tokens.
    """
    parents = {r[0]:r[1] for r in pe.iterrows(41)}
    names = {}
    def typename(table,rid,depth=0):
        if depth>64:raise Invalid('Recursive type identity')
        key=(table,rid)
        if key in names:return names[key]
        if table==27:
            value=parse_type(pe.blob(pe.row(27,rid)[0]),0,depth+1)[0]
            return value
        if table not in (1,2):raise Invalid('Invalid signature type table')
        row=pe.row(table,rid);name=pe.string(row[1]);ns=pe.string(row[2])
        if table==2 and rid in parents:
            value=typename(2,parents[rid],depth+1)+'/'+name
        elif table==1 and row[0]&3==3:
            value=typename(1,row[0]>>2,depth+1)+'/'+name
        else:value=(ns+'.' if ns else '')+name
        names[key]=value
        return value
    def ref(blob,pos,depth):
        v,pos=compressed(blob,pos);tag=v&3;rid=v>>2
        if tag>2:raise Invalid('Invalid TypeDefOrRef signature')
        return typename([2,1,27][tag],rid,depth+1),pos
    def method_sig(blob,pos,depth):
        flags=num(blob,pos,'B');pos+=1;generic=0
        if flags&16:generic,pos=compressed(blob,pos)
        count,pos=compressed(blob,pos);ret,pos=parse_type(blob,pos,depth+1);args=[]
        for _ in range(count):
            value,pos=parse_type(blob,pos,depth+1);args.append(value)
        return str((flags,generic,ret,tuple(args))),pos
    def parse_type(blob,pos,depth=0):
        if depth>64:raise Invalid('Recursive type signature')
        et=num(blob,pos,'B');pos+=1
        if et in (0x11,0x12):
            name,pos=ref(blob,pos,depth+1);return '%02x:%s'%(et,name),pos
        if et in (0x13,0x1e):
            index,pos=compressed(blob,pos);return '%02x:%d'%(et,index),pos
        if et in (0x0f,0x10,0x1d,0x45,0x41):
            sub,pos=parse_type(blob,pos,depth+1);return '%02x:%s'%(et,sub),pos
        if et in (0x1f,0x20):
            name,pos=ref(blob,pos,depth+1);sub,pos=parse_type(blob,pos,depth+1)
            return '%02x:%s:%s'%(et,name,sub),pos
        if et==0x15:
            kind=num(blob,pos,'B');pos+=1;name,pos=ref(blob,pos,depth+1)
            count,pos=compressed(blob,pos);args=[]
            for _ in range(count):
                value,pos=parse_type(blob,pos,depth+1);args.append(value)
            return 'generic:%02x:%s:%s'%(kind,name,str(tuple(args))),pos
        if et==0x14:
            sub,pos=parse_type(blob,pos,depth+1);rank,pos=compressed(blob,pos)
            n,pos=compressed(blob,pos);sizes=[]
            for _ in range(n):v,pos=compressed(blob,pos);sizes.append(v)
            n,pos=compressed(blob,pos);bounds=[]
            for _ in range(n):v,pos=compressed(blob,pos);bounds.append(v)
            return 'array:%s:%s'%(sub,str((rank,sizes,bounds))),pos
        if et==0x1b:
            sub,pos=method_sig(blob,pos,depth+1);return 'fnptr:'+sub,pos
        if et in (0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,0x16,0x18,0x19,0x1c):
            return '%02x'%et,pos
        raise Invalid('Unsupported identity signature element %02x'%et)
    mapping={}
    for rid in range(1,pe.rows.get(6,0)+1):
        row=pe.row(6,rid);sig=pe.blob(row[4]);key=(typename(2,pe.owners[rid]),pe.string(row[3]),method_sig(sig,0,0)[0])
        if key in mapping:raise Invalid('Ambiguous stable method identity: '+str(key))
        mapping[key]=rid
    return mapping


def dump_il(pe, ops, path):
    errors = []
    with path.open('w',encoding='utf-8',errors='backslashreplace') as f:
        f.write('// Static disassembly, NOT reconstructed original C# names. Never execute the PE.\n')
        for rid,body in all_bodies(pe,{}):
            f.write('\n// 0x%08X %s\n' % (0x06000000|rid,pe.label(0x06000000|rid)))
            f.write('// RVA 0x%08X; %d CIL bytes\n' % (pe.row(6,rid)[0],body['size']))
            try:
                for x in instructions(body['code'],ops):
                    value = x['operand']
                    if x['kind'] in ('InlineMethod','InlineField','InlineTok','InlineType','InlineString','InlineSig'):
                        value = '0x%08X %s' % (value,pe.label(value))
                    elif x['kind'] in ('InlineBrTarget','ShortInlineBrTarget'):
                        value = 'IL_%04X'%value
                    elif x['kind'] == 'InlineSwitch':
                        value = ', '.join('IL_%04X'%t for t in value)
                    f.write('IL_%04X: %-14s %s\n' % (x['offset'],x['name'],'' if value is None else value))
            except Invalid as e:
                f.write('// DISASSEMBLY ERROR: %s\n'%e)
                errors.append(dict(token='0x%08X'%(0x06000000|rid),error=str(e)))
    return errors


def decompress_gzip(data):
    z = zlib.decompressobj(31)
    out = z.decompress(data,LIMIT+1)
    if len(out)>LIMIT or not z.eof:
        raise Invalid('Gzip size limit or incomplete stream')
    return out


def extract_resources(pe, directory, depth=0):
    directory.mkdir()
    results = []
    for rid,name,data in pe.resources():
        stem = '%03d_%s'%(rid,safe_name(name))
        path = directory/(stem+'.bin')
        path.write_bytes(data)
        item = dict(name=name,file=str(path),size=len(data),sha256=digest(data))
        decoded = None
        kind = None
        try:
            if data.startswith(b'\x1f\x8b'):
                decoded = decompress_gzip(data)
                kind = 'gzip'
                if len(decoded)>=6 and num(decoded,0)==len(decoded)-4 and decoded[4:6]==b'MZ':
                    decoded=decoded[4:];kind='gzip-length-prefixed-PE'
            elif len(data)>17 and data[0] == 8 and (len(data)-9)%8 == 0 and all(x<128 for x in data[1:9]):
                try:
                    from Crypto.Cipher import DES
                except ImportError:
                    item['warning']='DES resource requires optional pycryptodome; nothing installed automatically'
                else:
                    plain=DES.new(data[1:9],DES.MODE_CBC,data[1:9]).decrypt(data[9:])
                    pad=plain[-1]
                    if not 1<=pad<=8 or plain[-pad:] != bytes([pad])*pad:
                        raise Invalid('DES resource padding failed')
                    decoded=plain[:-pad];kind='DES-CBC'
            if decoded is not None:
                out=directory/(stem+'.decoded.bin')
                out.write_bytes(decoded)
                item['decoded']=dict(file=str(out),kind=kind,size=len(decoded),sha256=digest(decoded))
                if decoded[:2] == b'MZ':
                    try:
                        child=PE(decoded)
                        item['decoded']['managed']=summary(child)
                        if depth<2 and child.rows.get(40,0):
                            item['decoded']['resources']=extract_resources(child,directory/(stem+'_resources'),depth+1)
                    except Invalid:
                        item['decoded']['managed']=False
        except (Invalid,zlib.error,ValueError) as e:
            item['decode_error']=str(e)
        results.append(item)
    return results


def vm_methods(pe,ops):
    found=[]
    for rid,body in all_bodies(pe,{}):
        for x in instructions(body['code'],ops):
            if x['kind'] == 'InlineMethod' and pe.label(x['operand']).endswith('::RunMethod'):
                found.append({'token':'0x%08X'%(0x06000000|rid),'name':pe.label(0x06000000|rid)})
                break
    return found


def export_vm(pe,out):
    records=[]
    for _,name,data in pe.resources():
        if name!='_CSVM':continue
        count=num(data,0);pos=4
        if count>pe.rows[6]:raise Invalid('Oversize CSVM method count')
        for i in range(count):
            guid=str(uuid.UUID(bytes_le=cut(data,pos,16)));pos+=16
            token=num(data,pos);pos+=4
            if token>>24!=6 or not 1<=token&0xffffff<=pe.rows[6]:
                raise Invalid('Invalid CSVM method token')
            record=dict(guid=guid,token='0x%08X'%token,name=pe.label(token))
            for part in ('locals','instructions','exceptions'):
                size=num(data,pos);pos+=4
                record[part+'_hex']=cut(data,pos,size).hex();pos+=size
            records.append(record)
        if pos!=len(data):raise Invalid('Trailing bytes in CSVM resource')
    (out/'vm_methods.json').write_text(json.dumps(records,indent=2,ensure_ascii=True),encoding='utf-8')
    return records


def write_patch(before,after,path):
    patches=[];i=0
    while i<min(len(before),len(after)):
        if before[i]==after[i]:i+=1;continue
        start=i
        while i<min(len(before),len(after)) and before[i]!=after[i]:i+=1
        patches.append(dict(offset=start,old=base64.b64encode(before[start:i]).decode(),
                            new=base64.b64encode(after[start:i]).decode()))
    tail=after[len(before):]
    record=dict(format='static-unpacker-bytepatch-v1',baseline_sha256=digest(before),
                modified_sha256=digest(after),baseline_size=len(before),modified_size=len(after),
                replacements=patches,append_base64=base64.b64encode(tail).decode())
    path.write_text(json.dumps(record,indent=2),encoding='utf-8')


def write_resource_delta(before, after, path):
    """Copy unchanged embedded resources and encode only changed PE/IL/metadata.

    Handles rebuilt images which are smaller than the original. Each operation
    contributes exactly one segment to the new file, in output order.
    """
    old, new = PE(before), PE(after)
    def ranges(pe):
        rva = num(pe.data, pe.cli + 24)
        if not rva:
            return {}
        start = pe.offset(rva)
        result = {}
        for row in pe.iterrows(40):
            if row[3]:
                continue
            pos = start + row[0]
            size = num(pe.data, pos) + 4
            cut(pe.data, pos, size)
            result[pe.string(row[2])] = (pos, size)
        return result
    old_ranges, new_ranges = ranges(old), ranges(new)
    copies = []
    for name, (dst, size) in new_ranges.items():
        if name not in old_ranges:
            continue
        src, old_size = old_ranges[name]
        if old_size == size and before[src:src + size] == after[dst:dst + size]:
            copies.append((dst, src, size))
    operations = []
    cursor = 0
    for dst, src, size in sorted(copies):
        if dst < cursor:
            raise Invalid('Overlapping resource ranges in rebuilt image')
        if dst > cursor:
            raw = after[cursor:dst]
            operations.append(dict(kind='data-zlib', size=len(raw),
                                   data=base64.b64encode(zlib.compress(raw, 9)).decode()))
        operations.append(dict(kind='copy', offset=src, size=size))
        cursor = dst + size
    if cursor < len(after):
        raw = after[cursor:]
        operations.append(dict(kind='data-zlib', size=len(raw),
                               data=base64.b64encode(zlib.compress(raw, 9)).decode()))
    record = dict(format='static-unpacker-resource-delta-v2',
                  baseline_sha256=digest(before), modified_sha256=digest(after),
                  baseline_size=len(before), modified_size=len(after), operations=operations)
    path.write_text(json.dumps(record, indent=2), encoding='utf-8')


def apply_patch_file(args):
    src=args.source.resolve();out=args.output.resolve()
    if out==src or out.exists():raise Invalid('Patch output must be a NEW separate file')
    before=src.read_bytes();p=json.loads(args.patch.read_text(encoding='utf-8'))
    if digest(before)!=p['baseline_sha256']:raise Invalid('Patch baseline hash mismatch')
    if p.get('format') == 'static-unpacker-resource-delta-v2':
        result = bytearray()
        for x in p['operations']:
            if x['kind'] == 'copy':
                result.extend(cut(before, x['offset'], x['size']))
            elif x['kind'] == 'data-zlib':
                decoder = zlib.decompressobj()
                raw = decoder.decompress(base64.b64decode(x['data'], validate=True), LIMIT + 1)
                if not decoder.eof or len(raw) != x['size']:
                    raise Invalid('Invalid compressed delta segment')
                result.extend(raw)
            else:
                raise Invalid('Unknown delta operation')
            if len(result) > LIMIT:
                raise Invalid('Delta output exceeds limit')
        if len(result) != p['modified_size']:
            raise Invalid('Delta output size mismatch')
    elif p.get('format') == 'static-unpacker-bytepatch-v1':
        result=bytearray(before)
        for x in p['replacements']:
            old=base64.b64decode(x['old'],validate=True);new=base64.b64decode(x['new'],validate=True)
            if bytes(result[x['offset']:x['offset']+len(old)])!=old:raise Invalid('Patch old bytes mismatch')
            if len(old)!=len(new):raise Invalid('Invalid replacement length')
            result[x['offset']:x['offset']+len(old)]=new
        result.extend(base64.b64decode(p['append_base64'],validate=True))
    else:
        raise Invalid('Unsupported patch format')
    if digest(result)!=p['modified_sha256']:raise Invalid('Patch output hash mismatch')
    with out.open('xb') as f:f.write(result)
    print(json.dumps({'sha256':digest(result),'output':str(out)},sort_keys=True))


def unpack(args):
    source=args.source.resolve();out=args.out.resolve()
    if out.exists():raise Invalid('Output folder already exists; choose a NEW folder (no overwrite)')
    data=source.read_bytes()
    if len(data)>LIMIT:raise Invalid('Input exceeds 256 MiB')
    pe=PE(data);ops=opcode_table()
    baseline=summary(pe)
    recovery_error=None
    try:
        h,recovered=recovery(pe,ops)
    except Invalid as e:
        if not args.allow_partial:raise
        recovery_error=str(e);h=header(pe);recovered={}
    candidates={rid:dict(body) for rid,body in all_bodies(pe,recovered)}
    proxy_count,changed=fix_proxy_calls(pe,candidates,ops)
    image=bytearray(data)
    strings,call_count,_=decode_strings(pe,candidates,ops,image)
    changed.update(rid for rid in candidates if candidates[rid]['bytes']!=
                   (recovered[rid]['bytes'] if rid in recovered else pe.body(rid)['bytes']))
    bodies={rid:candidates[rid] for rid in set(recovered)|changed}
    # Extend the final section instead of shifting existing PE file offsets.
    # The result is an analysis image, NOT a program to execute.
    last=max(pe.sections,key=lambda x:x['rva'])
    if any(s['raw']+s['raw_size']>last['raw']+last['raw_size'] for s in pe.sections):
        raise Invalid('Unsupported PE section ordering')
    pos=align(max(len(image),last['raw']+last['raw_size']),4)
    image.extend(bytes(pos-len(image)))
    mpos,msize,_=pe.tables[6]
    for rid,body in sorted(bodies.items()):
        pos=align(len(image),4);image.extend(bytes(pos-len(image)))
        new_rva=last['rva']+pos-last['raw']
        struct.pack_into('<I',image,mpos+(rid-1)*msize,new_rva)
        image.extend(body['bytes'])
    virtual_size=len(image)-last['raw']
    raw_size=align(virtual_size,pe.file_alignment)
    image.extend(bytes(last['raw']+raw_size-len(image)))
    struct.pack_into('<I',image,last['header']+8,virtual_size)
    struct.pack_into('<I',image,last['header']+16,raw_size)
    struct.pack_into('<I',image,last['header']+36,0x60000040)
    struct.pack_into('<I',image,pe.opt+56,align(last['rva']+virtual_size,pe.section_alignment))
    struct.pack_into('<I',image,pe.opt+64,0)  # stale PE checksum
    image[pe.dirs+4*8:pe.dirs+4*8+8]=bytes(8)  # stale Authenticode directory
    modified=bytes(image);check=PE(modified)
    # Reparse and compare every recovered body, not just the entry point.
    for rid,body in bodies.items():
        actual=check.body(rid)
        if actual['bytes']!=body['bytes']:raise Invalid('Rebuilt method verification failed: %d'%rid)
    if source.read_bytes()!=data:raise Invalid('Input changed during processing; abort')
    out.mkdir(parents=True)
    (out/'baseline.bin').write_bytes(data)
    modified_path=out/'SeroXen.unpacked.bin'
    modified_path.write_bytes(modified)
    write_patch(data,modified,out/'DIFF.json')
    il_errors=dump_il(check,ops,out/'recovered.il')
    resources=extract_resources(pe,out/'resources')
    vm=vm_methods(check,ops)
    vm_records=export_vm(pe,out)
    (out/'strings.json').write_text(json.dumps(strings,indent=2,ensure_ascii=True),encoding='utf-8')
    report=dict(tool='static-agile-unpacker-v1',input=str(source),output=str(modified_path),
                baseline=baseline,modified=summary(check),attempted_method_decoder=h.get('decoder_name',h['kind']),
                known_header_constraints=h.get('known_header_constraints',0),
                validated_metadata_operands=h.get('validated_metadata_operands',0),
                status='PARTIAL' if recovery_error or vm_records else 'RECOVERED',
                method_recovery_error=recovery_error,
                restored_methods=len(recovered),rewritten_methods=len(bodies),
                resolved_proxy_calls=proxy_count,string_values=len(strings),inlined_string_calls=call_count,
                exported_vm_records=len(vm_records),
                unresolved_vm_methods=vm_records,visible_vm_dispatch_stubs=vm,
                resources=resources,il_errors=il_errors,
                limitations=['CSVM devirtualization not implemented; RunMethod stubs are listed.',
                             'Names/control-flow/proxy calls may still be obfuscated.',
                             'Analysis output only. Do not execute recovered binaries.',
                             'Agile method trailer retained; header detection alone is not recovery status.'])
    (out/'report.json').write_text(json.dumps(report,indent=2,ensure_ascii=True),encoding='utf-8')
    print(json.dumps(dict(status=report['status'],restored_methods=len(recovered),
                         resolved_proxy_calls=proxy_count,exported_vm_records=len(vm_records),
                         method_recovery_error=recovery_error,
                         entrypoint_cil_bytes=report['modified']['entrypoint']['cil_size'],
                         inlined_string_calls=call_count,unresolved_vm_methods=len(vm_records),
                         embedded_resources=len(resources),original_unchanged=digest(source.read_bytes())==digest(data),
                         output=str(modified_path)),sort_keys=True))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='action',required=True)
    inspect=sub.add_parser('inspect',help='Read-only PE/.NET inspection; never executes input')
    inspect.add_argument('source',type=Path)
    inspect.add_argument('--method',action='append',default=[],help='Also inspect this exact Type::Method identity; repeatable')
    run=sub.add_parser('unpack',help='Recover supported Agile.NET IL, strings and embedded resources')
    run.add_argument('source',type=Path);run.add_argument('--out',type=Path,required=True)
    run.add_argument('--allow-partial',action='store_true',help='Explicitly allow partial analysis if method encryption is unsupported')
    patch=sub.add_parser('apply-patch',help='Reconstruct analysis image from pristine input and DIFF.json')
    patch.add_argument('source',type=Path);patch.add_argument('patch',type=Path);patch.add_argument('output',type=Path)
    args=parser.parse_args()
    try:
        if args.action=='inspect':
            data=args.source.read_bytes()
            if len(data)>LIMIT:raise Invalid('Input exceeds 256 MiB')
            pe=PE(data);result=summary(pe)
            if args.method:
                identities=method_identities(pe);result['requested_methods']=[]
                for name in args.method:
                    matches=[rid for key,rid in identities.items() if key[0]+'::'+key[1]==name]
                    if len(matches)!=1:raise Invalid('Requested method missing or ambiguous: '+name)
                    rid=matches[0];body=pe.body(rid)
                    result['requested_methods'].append(dict(name=name,token='0x%08X'%(0x06000000|rid),
                        rva='0x%08X'%pe.row(6,rid)[0],cil_size=body['size'] if body else None,
                        first_bytes=body['code'][:16].hex() if body else None,
                        instruction_count=len(list(instructions(body['code'],opcode_table()))) if body else None))
            print(json.dumps(result,sort_keys=True))
        elif args.action=='unpack':unpack(args)
        else:apply_patch_file(args)
    except (Invalid,OSError,KeyError,struct.error,UnicodeError) as e:
        print('ERROR: '+str(e),file=sys.stderr)
        return 1
    return 0


if __name__=='__main__':
    sys.exit(main())
