// A GitHub-compatible git forge: git smart HTTP, REST v3, GraphQL v4 and MCP on one
// in-memory store. Node 22 stdlib only (node:http, node:crypto, node:zlib).
//
// Determinism: no wall clock anywhere in state. Server-made commits use a fixed
// timestamp and identity; created_at/merged_at use one fixed ISO date; ids are counters
// and content hashes. The viewer is the contest's fixed seeded scenario owner.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------------------
// constants
// ---------------------------------------------------------------------------

export const VIEWER_LOGIN = 'adaiversen';
export const VIEWER_ID = 1000;
export const VIEWER_NAME = 'ada iversen';
export const VIEWER_EMAIL = 'adaiversen@example.invalid';
const VIEWER = { login: VIEWER_LOGIN, id: VIEWER_ID, name: VIEWER_NAME, email: VIEWER_EMAIL };

const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
const ZERO_OID = '0'.repeat(40);
const FIXED_TS = 1700000000;
const FIXED_ISO = '2026-01-01T00:00:00Z';
const IDENTITY = 'Conformance <conformance@make.fun>';
const AGENT = 'git-forge/1.0';
const VERSION = '1.0.0';
const PKT_LINE_MAX = 65520;
const MAX_BODY = 64 * 1024 * 1024;

const JSON_TYPE = 'application/json; charset=utf-8';

// ---------------------------------------------------------------------------
// small utilities
// ---------------------------------------------------------------------------

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function asBuffer(v: string | Uint8Array): Buffer {
  if (typeof v === 'string') return Buffer.from(v, 'utf8');
  if (Buffer.isBuffer(v)) return v;
  return Buffer.from(v.buffer, v.byteOffset, v.byteLength);
}

function sha1Hex(data: Uint8Array): string {
  return createHash('sha1').update(asBuffer(data)).digest('hex');
}

let reqSeq = 0;
function requestId(): string {
  reqSeq += 1;
  return `req-${String(reqSeq).padStart(6, '0')}`;
}

function b64encode(data: Uint8Array | string): string {
  return asBuffer(data).toString('base64');
}

function b64decode(text: string): Buffer {
  return Buffer.from(text.replace(/[\r\n\t ]+/g, ''), 'base64');
}

function globalId(kind: string, ...parts: Array<string | number>): string {
  return b64encode(`${kind}:${parts.join(':')}`);
}

function decodeGlobalId(id: string): { kind: string; parts: string[] } | null {
  try {
    const text = b64decode(id).toString('utf8');
    const idx = text.indexOf(':');
    if (idx < 0) return null;
    return { kind: text.slice(0, idx), parts: text.slice(idx + 1).split(':') };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// git object model
// ---------------------------------------------------------------------------

type ObjType = 'commit' | 'tree' | 'blob' | 'tag';

interface GObj {
  type: ObjType;
  data: Buffer;
}

const TYPE_CODE: Record<ObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Record<number, ObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function hashObject(type: ObjType, data: Uint8Array): string {
  const body = asBuffer(data);
  const h = createHash('sha1');
  h.update(Buffer.from(`${type} ${body.length}\u0000`, 'utf8'));
  h.update(body);
  return h.digest('hex');
}

function isObjectId(v: string): boolean {
  return /^[0-9a-f]{40}$/.test(v);
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function parseTree(data: Uint8Array): TreeEntry[] {
  const buffer = asBuffer(data);
  const entries: TreeEntry[] = [];
  let offset = 0;
  while (offset < buffer.length) {
    const space = buffer.indexOf(0x20, offset);
    if (space < 0) throw new Error('tree entry has no mode separator');
    const nul = buffer.indexOf(0x00, space + 1);
    if (nul < 0) throw new Error('tree entry has no name terminator');
    if (nul + 21 > buffer.length) throw new Error('tree entry has a truncated object id');
    entries.push({
      mode: buffer.subarray(offset, space).toString('ascii'),
      name: buffer.subarray(space + 1, nul).toString('utf8'),
      oid: buffer.subarray(nul + 1, nul + 21).toString('hex'),
    });
    offset = nul + 21;
  }
  return entries;
}

function compareTreeNames(a: { name: string; mode: string }, b: { name: string; mode: string }): number {
  const left = Buffer.from(a.mode === '40000' ? `${a.name}/` : a.name, 'utf8');
  const right = Buffer.from(b.mode === '40000' ? `${b.name}/` : b.name, 'utf8');
  return Buffer.compare(left, right);
}

function buildTree(entries: readonly TreeEntry[]): Buffer {
  const sorted = [...entries].sort(compareTreeNames);
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\u0000`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

interface CommitView {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

function parseCommit(data: Uint8Array): CommitView {
  const buffer = asBuffer(data);
  const blank = buffer.indexOf('\n\n');
  const headerEnd = blank < 0 ? buffer.length : blank;
  const headerText = buffer.subarray(0, headerEnd).toString('utf8');
  const message = blank < 0 ? '' : buffer.subarray(blank + 2).toString('utf8');
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of headerText.split('\n')) {
    if (!line) continue;
    const space = line.indexOf(' ');
    const key = space < 0 ? line : line.slice(0, space);
    const value = space < 0 ? '' : line.slice(space + 1);
    if (key === 'tree') tree = value;
    else if (key === 'parent') parents.push(value);
    else if (key === 'author') author = value;
    else if (key === 'committer') committer = value;
  }
  if (!isObjectId(tree)) throw new Error('commit has no valid tree header');
  return { tree, parents, author, committer, message };
}

function buildCommit(fields: { tree: string; parents?: readonly string[]; message: string; author?: string; committer?: string; timestamp?: number }): Buffer {
  const ts = fields.timestamp ?? FIXED_TS;
  const who = `${fields.author ?? IDENTITY} ${ts} +0000`;
  const committer = `${fields.committer ?? IDENTITY} ${ts} +0000`;
  const lines = [`tree ${fields.tree}`];
  for (const parent of fields.parents ?? []) lines.push(`parent ${parent}`);
  lines.push(`author ${who}`, `committer ${committer}`, '');
  return Buffer.from(`${lines.join('\n')}\n${fields.message}`, 'utf8');
}

interface TagView {
  object: string;
  type: ObjType;
  tag: string;
  tagger: string;
  message: string;
}

function parseTag(data: Uint8Array): TagView {
  const buffer = asBuffer(data);
  const blank = buffer.indexOf('\n\n');
  const headerEnd = blank < 0 ? buffer.length : blank;
  const headers = new Map<string, string>();
  for (const line of buffer.subarray(0, headerEnd).toString('utf8').split('\n')) {
    if (!line) continue;
    const space = line.indexOf(' ');
    if (space < 0) continue;
    headers.set(line.slice(0, space), line.slice(space + 1));
  }
  return {
    object: headers.get('object') ?? '',
    type: (headers.get('type') ?? 'commit') as ObjType,
    tag: headers.get('tag') ?? '',
    tagger: headers.get('tagger') ?? '',
    message: blank < 0 ? '' : buffer.subarray(blank + 2).toString('utf8'),
  };
}

// ---------------------------------------------------------------------------
// pkt-line codec
// ---------------------------------------------------------------------------

function encodePktLine(payload: string | Uint8Array): Buffer {
  const data = asBuffer(payload);
  if (data.length > PKT_LINE_MAX - 4) throw new Error('pkt-line payload too long');
  const header = Buffer.allocUnsafe(4);
  header.write((data.length + 4).toString(16).padStart(4, '0'), 0, 4, 'ascii');
  return Buffer.concat([header, data]);
}

function pktFlush(): Buffer {
  return Buffer.from('0000', 'ascii');
}

function pktDelim(): Buffer {
  return Buffer.from('0001', 'ascii');
}

function encodePktLines(items: ReadonlyArray<string | Uint8Array | 'flush' | 'delim'>): Buffer {
  const parts: Buffer[] = [];
  for (const item of items) {
    if (item === 'flush') parts.push(pktFlush());
    else if (item === 'delim') parts.push(pktDelim());
    else parts.push(encodePktLine(item));
  }
  return Buffer.concat(parts);
}

/** Decode a complete buffer into packets. Throws on malformed framing. */
function decodePktLines(bytes: Uint8Array): Array<{ kind: 'data' | 'flush' | 'delim' | 'response-end'; payload?: Buffer }> {
  const buffer = asBuffer(bytes);
  const packets: Array<{ kind: 'data' | 'flush' | 'delim' | 'response-end'; payload?: Buffer }> = [];
  let offset = 0;
  while (offset < buffer.length) {
    if (offset + 4 > buffer.length) throw new Error('truncated pkt-line');
    const head = buffer.subarray(offset, offset + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(head)) throw new Error(`invalid pkt-line length ${JSON.stringify(head)}`);
    const length = Number.parseInt(head, 16);
    if (length === 0) {
      packets.push({ kind: 'flush' });
      offset += 4;
    } else if (length === 1) {
      packets.push({ kind: 'delim' });
      offset += 4;
    } else if (length === 2) {
      packets.push({ kind: 'response-end' });
      offset += 4;
    } else if (length === 3 || length > PKT_LINE_MAX) {
      throw new Error(`invalid pkt-line length ${length}`);
    } else {
      if (offset + length > buffer.length) throw new Error('truncated pkt-line');
      packets.push({ kind: 'data', payload: buffer.subarray(offset + 4, offset + length) });
      offset += length;
    }
  }
  return packets;
}

// ---------------------------------------------------------------------------
// packfile read/write
// ---------------------------------------------------------------------------

function readVarintSize(buffer: Buffer, start: number): { size: number; next: number; first: number } {
  if (start >= buffer.length) throw new Error('pack entry has no size header');
  let byte = buffer[start]!;
  const first = byte;
  let size = byte & 0x0f;
  let shift = 4;
  let offset = start + 1;
  while (byte & 0x80) {
    if (offset >= buffer.length) throw new Error('pack entry size varint is truncated');
    byte = buffer[offset++]!;
    size += (byte & 0x7f) * 2 ** shift;
    shift += 7;
    if (shift > 63) throw new Error('pack entry size varint is too long');
  }
  return { size, next: offset, first };
}

function readOfsDeltaBase(buffer: Buffer, start: number): { baseOffset: number; next: number } {
  if (start >= buffer.length) throw new Error('ofs-delta has no base offset');
  let byte = buffer[start]!;
  let offset = start + 1;
  let value = byte & 0x7f;
  while (byte & 0x80) {
    if (offset >= buffer.length) throw new Error('ofs-delta base offset is truncated');
    byte = buffer[offset++]!;
    value = ((value + 1) * 128) + (byte & 0x7f);
  }
  return { baseOffset: value, next: offset };
}

function inflateAt(buffer: Buffer, offset: number): { data: Buffer; next: number } {
  const view = buffer.subarray(offset);
  let result: { buffer: Buffer; engine: { bytesWritten: number } };
  try {
    result = inflateSync(view, { info: true }) as unknown as { buffer: Buffer; engine: { bytesWritten: number } };
  } catch (err) {
    throw new Error(`zlib stream at offset ${offset} did not inflate: ${(err as Error).message}`);
  }
  const written = result.engine.bytesWritten;
  if (!written || written <= 0) throw new Error(`zlib stream at offset ${offset} consumed no bytes`);
  return { data: result.buffer, next: offset + written };
}

function applyDelta(base: Uint8Array, delta: Uint8Array): Buffer {
  const baseBuffer = asBuffer(base);
  const deltaBuffer = asBuffer(delta);
  let offset = 0;
  const readSize = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      if (offset >= deltaBuffer.length) throw new Error('delta size varint is truncated');
      const byte = deltaBuffer[offset++]!;
      value += (byte & 0x7f) * 2 ** shift;
      shift += 7;
      if (!(byte & 0x80)) break;
      if (shift > 63) throw new Error('delta size varint is too long');
    }
    return value;
  };
  const sourceSize = readSize();
  const targetSize = readSize();
  if (sourceSize !== baseBuffer.length) throw new Error(`delta expects a ${sourceSize}-byte base, got ${baseBuffer.length}`);
  const out = Buffer.allocUnsafe(targetSize);
  let written = 0;
  while (offset < deltaBuffer.length) {
    const op = deltaBuffer[offset++]!;
    if (op & 0x80) {
      let copyOffset = 0;
      let copySize = 0;
      let shift = 0;
      for (let bit = 0; bit < 4; bit += 1) {
        if (op & (1 << bit)) {
          if (offset >= deltaBuffer.length) throw new Error('delta copy offset is truncated');
          copyOffset += deltaBuffer[offset++]! * 2 ** shift;
        }
        shift += 8;
      }
      shift = 0;
      for (let bit = 4; bit < 7; bit += 1) {
        if (op & (1 << bit)) {
          if (offset >= deltaBuffer.length) throw new Error('delta copy size is truncated');
          copySize += deltaBuffer[offset++]! * 2 ** shift;
        }
        shift += 8;
      }
      if (copySize === 0) copySize = 0x10000;
      if (copyOffset + copySize > baseBuffer.length) throw new Error('delta copy is out of the base');
      if (written + copySize > targetSize) throw new Error('delta writes past its target size');
      baseBuffer.copy(out, written, copyOffset, copyOffset + copySize);
      written += copySize;
    } else if (op !== 0) {
      const literal = op & 0x7f;
      if (offset + literal > deltaBuffer.length) throw new Error('delta insert is truncated');
      if (written + literal > targetSize) throw new Error('delta writes past its target size');
      deltaBuffer.copy(out, written, offset, offset + literal);
      offset += literal;
      written += literal;
    } else {
      throw new Error('delta opcode 0 is invalid');
    }
  }
  if (written !== targetSize) throw new Error(`delta produced ${written} of ${targetSize} bytes`);
  return out;
}

/** Read a packfile (version 2/3), resolving OFS_DELTA and REF_DELTA. Bases outside the pack come from `resolveBase`. */
function readPack(pack: Uint8Array, resolveBase?: (oid: string) => GObj | undefined): Map<string, GObj> {
  const buffer = asBuffer(pack);
  if (buffer.length < 32) throw new Error(`pack is ${buffer.length} bytes, too short`);
  if (buffer.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('pack does not start with PACK');
  const version = buffer.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const declaredCount = buffer.readUInt32BE(8);
  const trailerStart = buffer.length - 20;
  const trailer = buffer.subarray(trailerStart).toString('hex');
  const computedTrailer = sha1Hex(buffer.subarray(0, trailerStart));
  if (trailer !== computedTrailer) throw new Error('pack trailer checksum mismatch');

  interface RawEntry {
    offset: number;
    typeCode: number;
    size: number;
    data: Buffer;
    baseOffset?: number;
    baseOid?: string;
    resolvedType?: ObjType;
    resolved?: Buffer;
    oid?: string;
  }
  const raw: RawEntry[] = [];
  const byOffset = new Map<number, RawEntry>();
  let offset = 12;
  for (let index = 0; index < declaredCount; index += 1) {
    const entryOffset = offset;
    const header = readVarintSize(buffer, offset);
    offset = header.next;
    const typeCode = (header.first >> 4) & 0x07;
    const entry: RawEntry = { offset: entryOffset, typeCode, size: header.size, data: Buffer.alloc(0) };
    if (typeCode === 6) {
      const base = readOfsDeltaBase(buffer, offset);
      offset = base.next;
      if (base.baseOffset <= 0 || base.baseOffset > entryOffset) throw new Error(`ofs-delta at ${entryOffset} names an invalid base offset ${base.baseOffset}`);
      entry.baseOffset = entryOffset - base.baseOffset;
    } else if (typeCode === 7) {
      if (offset + 20 > trailerStart) throw new Error('ref-delta base id is truncated');
      entry.baseOid = buffer.subarray(offset, offset + 20).toString('hex');
      offset += 20;
    } else if (!CODE_TYPE[typeCode]) {
      throw new Error(`pack entry ${index} has unknown type code ${typeCode}`);
    }
    const inflated = inflateAt(buffer.subarray(0, trailerStart), offset);
    if (inflated.data.length !== header.size) throw new Error(`pack entry at ${entryOffset} declares ${header.size} bytes but inflated to ${inflated.data.length}`);
    entry.data = inflated.data;
    offset = inflated.next;
    raw.push(entry);
    byOffset.set(entryOffset, entry);
  }
  if (offset !== trailerStart) throw new Error(`pack has ${trailerStart - offset} stray bytes before its trailer`);

  const objects = new Map<string, GObj>();
  const resolvedByOid = new Map<string, RawEntry>();
  const resolving = new Set<number>();
  const resolve = (entry: RawEntry): { type: ObjType; data: Buffer; oid: string } => {
    if (entry.resolved && entry.resolvedType && entry.oid) return { type: entry.resolvedType, data: entry.resolved, oid: entry.oid };
    if (resolving.has(entry.offset)) throw new Error(`delta cycle at pack offset ${entry.offset}`);
    resolving.add(entry.offset);
    let type: ObjType;
    let data: Buffer;
    if (entry.typeCode === 6) {
      const baseEntry = byOffset.get(entry.baseOffset!);
      if (!baseEntry) throw new Error(`ofs-delta base at offset ${entry.baseOffset} is not in the pack`);
      const base = resolve(baseEntry);
      type = base.type;
      data = applyDelta(base.data, entry.data);
    } else if (entry.typeCode === 7) {
      const wanted = entry.baseOid!;
      const baseEntry = resolvedByOid.get(wanted);
      if (baseEntry) {
        const base = resolve(baseEntry);
        type = base.type;
        data = applyDelta(base.data, entry.data);
      } else {
        const external = resolveBase?.(wanted);
        if (!external) throw new Error(`ref-delta base ${wanted} is neither in the pack nor supplied`);
        type = external.type;
        data = applyDelta(external.data, entry.data);
      }
    } else {
      type = CODE_TYPE[entry.typeCode]!;
      data = entry.data;
    }
    const oid = hashObject(type, data);
    entry.resolved = data;
    entry.resolvedType = type;
    entry.oid = oid;
    resolvedByOid.set(oid, entry);
    resolving.delete(entry.offset);
    return { type, data, oid };
  };
  for (const entry of raw) {
    const resolved = resolve(entry);
    if (!objects.has(resolved.oid)) objects.set(resolved.oid, { type: resolved.type, data: resolved.data });
  }
  return objects;
}

function writePackObjectHeader(type: ObjType, size: number): Buffer {
  const code = TYPE_CODE[type];
  const bytes: number[] = [];
  let remaining = size;
  let first = (code << 4) | (remaining & 0x0f);
  remaining = Math.floor(remaining / 16);
  while (remaining > 0) {
    bytes.push(first | 0x80);
    first = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}

/** Build a packfile from plain objects (no deltas), in the caller's order. */
function writePack(objects: Iterable<GObj>): Buffer {
  const list = [...objects];
  const parts: Buffer[] = [];
  const header = Buffer.allocUnsafe(12);
  header.write('PACK', 0, 4, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(list.length, 8);
  parts.push(header);
  for (const object of list) {
    const data = asBuffer(object.data);
    parts.push(writePackObjectHeader(object.type, data.length));
    parts.push(deflateSync(data));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

// ---------------------------------------------------------------------------
// store model
// ---------------------------------------------------------------------------

interface Label {
  id: number;
  name: string;
  color: string;
  description: string;
}

interface Comment {
  id: number;
  body: string;
}

interface Issue {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: Label[];
  seq: number;
  comments: Comment[];
}

interface Pull {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  mergedAt: string | null;
  mergeSha: string | null;
  headRef: string;
  baseRef: string;
  seq: number;
}

interface Repo {
  id: number;
  name: string;
  owner: string;
  description: string;
  isPrivate: boolean;
  defaultBranch: string;
  createdSeq: number;
  refs: Map<string, string>;
  objects: Map<string, GObj>;
  commitSeq: Map<string, number>;
  labels: Map<string, Label>;
  issues: Issue[];
  pulls: Pull[];
  nextNumber: number;
}

const repos = new Map<string, Repo>();
let repoIdSeq = 1;
let repoCreateSeq = 0;
let commitSeqCounter = 0;
let commentIdSeq = 1;
let labelIdSeq = 1;

function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}

function findRepo(owner: string, name: string): Repo | undefined {
  return repos.get(repoKey(owner, name));
}

function createRepoRecord(name: string, isPrivate: boolean, description: string): Repo {
  const repo: Repo = {
    id: repoIdSeq,
    name,
    owner: VIEWER_LOGIN,
    description,
    isPrivate,
    defaultBranch: 'main',
    createdSeq: repoCreateSeq,
    refs: new Map(),
    objects: new Map(),
    commitSeq: new Map(),
    labels: new Map(),
    issues: [],
    pulls: [],
    nextNumber: 1,
  };
  repoIdSeq += 1;
  repoCreateSeq += 1;
  repos.set(repoKey(VIEWER_LOGIN, name), repo);
  return repo;
}

function putObject(repo: Repo, type: ObjType, data: Buffer): string {
  const oid = hashObject(type, data);
  if (!repo.objects.has(oid)) {
    repo.objects.set(oid, { type, data });
    if (type === 'commit') {
      commitSeqCounter += 1;
      repo.commitSeq.set(oid, commitSeqCounter);
    }
  }
  return oid;
}

function getObject(repo: Repo, oid: string): GObj | undefined {
  return repo.objects.get(oid);
}

/** Every object reachable from `roots`. With `stopAt`, a commit in that set is included but its parents are not walked. Throws on a missing object unless `allowMissing`. */
function collectReachable(
  repo: Repo,
  roots: Iterable<string>,
  options: { allowMissing?: boolean; stopAt?: ReadonlySet<string> } = {},
): Set<string> {
  const seen = new Set<string>();
  const queue: string[] = [];
  for (const root of roots) if (isObjectId(root)) queue.push(root);
  while (queue.length) {
    const oid = queue.pop()!;
    if (seen.has(oid)) continue;
    const object = repo.objects.get(oid);
    if (!object) {
      if (options.allowMissing) continue;
      throw new Error(`object ${oid} is missing from the store`);
    }
    seen.add(oid);
    if (object.type === 'commit') {
      if (options.stopAt?.has(oid)) continue;
      const commit = parseCommit(object.data);
      queue.push(commit.tree);
      for (const parent of commit.parents) queue.push(parent);
    } else if (object.type === 'tag') {
      queue.push(parseTag(object.data).object);
    } else if (object.type === 'tree') {
      for (const entry of parseTree(object.data)) {
        if (entry.mode === '160000') continue;
        queue.push(entry.oid);
      }
    }
  }
  return seen;
}

/** True when `ancestor` is reachable from `tip` (or equal), walking commit parents. */
function isAncestor(repo: Repo, ancestor: string, tip: string): boolean {
  if (ancestor === tip) return true;
  const seen = new Set<string>();
  const queue = [tip];
  while (queue.length) {
    const oid = queue.pop()!;
    if (oid === ancestor) return true;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const object = repo.objects.get(oid);
    if (!object || object.type !== 'commit') continue;
    for (const parent of parseCommit(object.data).parents) queue.push(parent);
  }
  return false;
}

/** A merge base of `a` and `b`: the common ancestor closest to `b`. Null when none. */
function mergeBase(repo: Repo, a: string, b: string): string | null {
  const ancestorsA = new Set<string>();
  const queueA = [a];
  while (queueA.length) {
    const oid = queueA.pop()!;
    if (ancestorsA.has(oid)) continue;
    ancestorsA.add(oid);
    const object = repo.objects.get(oid);
    if (!object || object.type !== 'commit') continue;
    for (const parent of parseCommit(object.data).parents) queueA.push(parent);
  }
  const seen = new Set<string>();
  const queueB = [b];
  while (queueB.length) {
    const oid = queueB.pop()!;
    if (ancestorsA.has(oid)) return oid;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const object = repo.objects.get(oid);
    if (!object || object.type !== 'commit') continue;
    for (const parent of parseCommit(object.data).parents) queueB.push(parent);
  }
  return null;
}

// ---------------------------------------------------------------------------
// trees: flatten / build / merge / diff
// ---------------------------------------------------------------------------

/** Flatten a tree into path -> {mode, oid} (files only). */
function flattenTree(repo: Repo, treeOid: string, prefix = '', out = new Map<string, { mode: string; oid: string }>()): Map<string, { mode: string; oid: string }> {
  const object = repo.objects.get(treeOid);
  if (!object || object.type !== 'tree') return out;
  for (const entry of parseTree(object.data)) {
    const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    if (entry.mode === '40000') flattenTree(repo, entry.oid, path, out);
    else if (entry.mode !== '160000') out.set(path, { mode: entry.mode, oid: entry.oid });
  }
  return out;
}

/** Build (and store) a tree from a flat path map; returns the root tree oid. */
function buildTreeFromMap(repo: Repo, flat: ReadonlyMap<string, { mode: string; oid: string }>): string {
  interface Node {
    files: Map<string, { mode: string; oid: string }>;
    dirs: Map<string, Node>;
  }
  const make = (): Node => ({ files: new Map(), dirs: new Map() });
  const root = make();
  for (const [path, entry] of flat) {
    const segments = path.split('/');
    let node = root;
    for (let i = 0; i < segments.length - 1; i += 1) {
      const name = segments[i]!;
      if (!node.dirs.has(name)) node.dirs.set(name, make());
      node = node.dirs.get(name)!;
    }
    node.files.set(segments[segments.length - 1]!, entry);
  }
  const build = (node: Node): string => {
    const entries: TreeEntry[] = [];
    for (const [name, entry] of node.files) entries.push({ mode: entry.mode, name, oid: entry.oid });
    for (const [name, child] of node.dirs) entries.push({ mode: '40000', name, oid: build(child) });
    return putObject(repo, 'tree', buildTree(entries));
  };
  return build(root);
}

/** The tree oid of a ref (or null when the ref has no commit). */
function refTree(repo: Repo, ref: string): string | null {
  const oid = repo.refs.get(ref);
  if (!oid) return null;
  const object = repo.objects.get(oid);
  if (!object || object.type !== 'commit') return null;
  return parseCommit(object.data).tree;
}

/** Three-way merge of flat trees. Returns the merged flat map and the conflicting paths. */
function threeWayMerge(
  base: ReadonlyMap<string, { mode: string; oid: string }>,
  ours: ReadonlyMap<string, { mode: string; oid: string }>,
  theirs: ReadonlyMap<string, { mode: string; oid: string }>,
): { merged: Map<string, { mode: string; oid: string }>; conflicts: string[] } {
  const merged = new Map<string, { mode: string; oid: string }>();
  const conflicts: string[] = [];
  const paths = new Set<string>([...base.keys(), ...ours.keys(), ...theirs.keys()]);
  for (const path of paths) {
    const b = base.get(path);
    const o = ours.get(path);
    const t = theirs.get(path);
    const same = (x: { oid: string } | undefined, y: { oid: string } | undefined): boolean =>
      (x === undefined && y === undefined) || (x !== undefined && y !== undefined && x.oid === y.oid);
    if (same(o, t)) {
      if (o) merged.set(path, o);
    } else if (same(t, b)) {
      if (o) merged.set(path, o);
    } else if (same(o, b)) {
      if (t) merged.set(path, t);
    } else {
      conflicts.push(path);
      if (o) merged.set(path, o);
    }
  }
  return { merged, conflicts };
}

/** Line diff counts between two blob contents. */
function lineDiff(oldText: string, newText: string): { additions: number; deletions: number } {
  const splitLines = (text: string): string[] => {
    if (text === '') return [];
    const parts = text.split('\n');
    if (parts.length > 0 && parts[parts.length - 1] === '') parts.pop();
    return parts;
  };
  const a = splitLines(oldText);
  const b = splitLines(newText);
  // LCS on lines (files here are small).
  const n = a.length;
  const m = b.length;
  const dp: number[][] = [];
  for (let i = 0; i <= n; i += 1) {
    dp.push(new Array<number>(m + 1).fill(0));
  }
  for (let i = n - 1; i >= 0; i -= 1) {
    for (let j = m - 1; j >= 0; j -= 1) {
      dp[i]![j] = a[i] === b[j] ? (dp[i + 1]![j + 1]! + 1) : Math.max(dp[i + 1]![j]!, dp[i]![j + 1]!);
    }
  }
  const lcs = dp[0]![0]!;
  return { additions: m - lcs, deletions: n - lcs };
}

interface FileChange {
  filename: string;
  status: 'added' | 'removed' | 'modified';
  additions: number;
  deletions: number;
  changes: number;
}

/** Diff two trees (flat maps) into per-file changes. */
function diffTrees(
  repo: Repo,
  base: ReadonlyMap<string, { mode: string; oid: string }>,
  head: ReadonlyMap<string, { mode: string; oid: string }>,
): FileChange[] {
  const changes: FileChange[] = [];
  const paths = new Set<string>([...base.keys(), ...head.keys()]);
  for (const path of [...paths].sort()) {
    const b = base.get(path);
    const h = head.get(path);
    if (b && !h) {
      const oldText = repo.objects.get(b.oid)?.data.toString('utf8') ?? '';
      const lines = oldText === '' ? 0 : oldText.split('\n').length - (oldText.endsWith('\n') ? 1 : 0);
      changes.push({ filename: path, status: 'removed', additions: 0, deletions: lines, changes: lines });
    } else if (!b && h) {
      const newText = repo.objects.get(h.oid)?.data.toString('utf8') ?? '';
      const lines = newText === '' ? 0 : newText.split('\n').length - (newText.endsWith('\n') ? 1 : 0);
      changes.push({ filename: path, status: 'added', additions: lines, deletions: 0, changes: lines });
    } else if (b && h && b.oid !== h.oid) {
      const oldText = repo.objects.get(b.oid)?.data.toString('utf8') ?? '';
      const newText = repo.objects.get(h.oid)?.data.toString('utf8') ?? '';
      const d = lineDiff(oldText, newText);
      changes.push({ filename: path, status: 'modified', additions: d.additions, deletions: d.deletions, changes: d.additions + d.deletions });
    }
  }
  return changes;
}

/** The file changes of a pull request: diff of merge-base tree vs head tree. */
function pullRequestFiles(repo: Repo, pr: Pull): FileChange[] {
  const headOid = repo.refs.get(`refs/heads/${pr.headRef}`);
  const baseOid = repo.refs.get(`refs/heads/${pr.baseRef}`);
  if (!headOid || !baseOid) return [];
  const base = mergeBase(repo, baseOid, headOid) ?? baseOid;
  const baseTree = refTree(repo, `refs/heads/${pr.baseRef}`) ?? '';
  const baseObj = repo.objects.get(base);
  const baseTreeOid = baseObj && baseObj.type === 'commit' ? parseCommit(baseObj.data).tree : baseTree;
  const headTreeOid = refTree(repo, `refs/heads/${pr.headRef}`) ?? '';
  const baseFlat = baseTreeOid ? flattenTree(repo, baseTreeOid) : new Map();
  const headFlat = headTreeOid ? flattenTree(repo, headTreeOid) : new Map();
  return diffTrees(repo, baseFlat, headFlat);
}

/** Whether a pull request can merge cleanly (no three-way conflict). */
function pullRequestMergeable(repo: Repo, pr: Pull): boolean {
  const headOid = repo.refs.get(`refs/heads/${pr.headRef}`);
  const baseOid = repo.refs.get(`refs/heads/${pr.baseRef}`);
  if (!headOid || !baseOid) return false;
  const base = mergeBase(repo, baseOid, headOid);
  if (base === null) return false;
  const baseObj = repo.objects.get(base);
  if (!baseObj || baseObj.type !== 'commit') return false;
  const baseFlat = flattenTree(repo, parseCommit(baseObj.data).tree);
  const oursFlat = flattenTree(repo, parseCommit(repo.objects.get(baseOid)!.data).tree);
  const theirsFlat = flattenTree(repo, parseCommit(repo.objects.get(headOid)!.data).tree);
  return threeWayMerge(baseFlat, oursFlat, theirsFlat).conflicts.length === 0;
}

/** Create a commit on a branch from a flat tree map. Returns the commit oid. */
function commitTree(repo: Repo, branch: string, flat: ReadonlyMap<string, { mode: string; oid: string }>, message: string): string {
  const treeOid = buildTreeFromMap(repo, flat);
  const parent = repo.refs.get(`refs/heads/${branch}`);
  const data = buildCommit({ tree: treeOid, parents: parent ? [parent] : [], message });
  const oid = putObject(repo, 'commit', data);
  repo.refs.set(`refs/heads/${branch}`, oid);
  return oid;
}

/** Squash-merge a pull request onto its base branch. Returns the merge commit oid, or null on conflict. */
function squashMerge(repo: Repo, pr: Pull): string | null {
  const headOid = repo.refs.get(`refs/heads/${pr.headRef}`);
  const baseOid = repo.refs.get(`refs/heads/${pr.baseRef}`);
  if (!headOid || !baseOid) return null;
  const base = mergeBase(repo, baseOid, headOid);
  if (base === null) return null;
  const baseObj = repo.objects.get(base);
  if (!baseObj || baseObj.type !== 'commit') return null;
  const baseFlat = flattenTree(repo, parseCommit(baseObj.data).tree);
  const oursFlat = flattenTree(repo, parseCommit(repo.objects.get(baseOid)!.data).tree);
  const theirsFlat = flattenTree(repo, parseCommit(repo.objects.get(headOid)!.data).tree);
  const { merged, conflicts } = threeWayMerge(baseFlat, oursFlat, theirsFlat);
  if (conflicts.length > 0) return null;
  return commitTree(repo, pr.baseRef, merged, `Merge pull request #${pr.number} from ${VIEWER_LOGIN}/${pr.headRef}`);
}

// ---------------------------------------------------------------------------
// fetch computation (upload-pack)
// ---------------------------------------------------------------------------

interface FetchPlan {
  objects: Map<string, GObj>;
  shallow: string[];
  unshallow: string[];
}

/**
 * Compute the objects a fetch must send.
 * - wants: oids the client asked for; haves: oids it already holds.
 * - oldShallow: the client's current shallow boundaries (not walked past).
 * - depth: total commit depth from the wants (undefined = full history).
 * Boundary commits (distance depth-1, with parents) are reported shallow; old boundaries
 * whose parents are now included are reported unshallow.
 */
/** Objects the client already holds: reachable from haves, but parent traversal stops at the
 * client's old shallow boundaries (the boundary commit's own tree and blobs are still held). */
function collectHaveSet(repo: Repo, haves: readonly string[], oldShallow: ReadonlySet<string>): Set<string> {
  const seen = new Set<string>();
  const queue: string[] = [...haves];
  while (queue.length) {
    const oid = queue.pop()!;
    if (seen.has(oid)) continue;
    const object = repo.objects.get(oid);
    if (!object) continue;
    seen.add(oid);
    if (object.type === 'commit') {
      const commit = parseCommit(object.data);
      queue.push(commit.tree);
      if (!oldShallow.has(oid)) {
        for (const parent of commit.parents) queue.push(parent);
      }
    } else if (object.type === 'tag') {
      queue.push(parseTag(object.data).object);
    } else if (object.type === 'tree') {
      for (const entry of parseTree(object.data)) {
        if (entry.mode === '160000') continue;
        queue.push(entry.oid);
      }
    }
  }
  return seen;
}

/** Objects reachable from the included commits (and any extra roots) without crossing the depth
 * boundary: a boundary commit contributes its tree and blobs, but its parents are not followed
 * unless they are themselves included. */
function collectShallowReachable(repo: Repo, included: ReadonlySet<string>, extraRoots: readonly string[]): Set<string> {
  const seen = new Set<string>();
  const queue: string[] = [...included, ...extraRoots];
  while (queue.length) {
    const oid = queue.pop()!;
    if (seen.has(oid)) continue;
    const object = repo.objects.get(oid);
    if (!object) continue;
    seen.add(oid);
    if (object.type === 'commit') {
      const commit = parseCommit(object.data);
      queue.push(commit.tree);
      for (const parent of commit.parents) {
        if (included.has(parent)) queue.push(parent);
      }
    } else if (object.type === 'tag') {
      queue.push(parseTag(object.data).object);
    } else if (object.type === 'tree') {
      for (const entry of parseTree(object.data)) {
        if (entry.mode === '160000') continue;
        queue.push(entry.oid);
      }
    }
  }
  return seen;
}

function computeFetch(repo: Repo, wants: readonly string[], haves: readonly string[], oldShallow: readonly string[], depth: number | undefined): FetchPlan {
  const oldShallowSet = new Set(oldShallow);
  // Objects the client already holds: reachable from haves, stopping at old shallow boundaries.
  const haveSet = collectHaveSet(repo, haves, oldShallowSet);

  // Commit distances from the wants.
  const dist = new Map<string, number>();
  const queue: string[] = [];
  const rootCommits: string[] = [];
  for (const want of wants) {
    const object = repo.objects.get(want);
    if (!object) continue;
    if (object.type === 'commit') {
      if (!dist.has(want)) {
        dist.set(want, 0);
        queue.push(want);
        rootCommits.push(want);
      }
    } else if (object.type === 'tag') {
      const target = parseTag(object.data).object;
      const targetObj = repo.objects.get(target);
      if (targetObj?.type === 'commit' && !dist.has(target)) {
        dist.set(target, 0);
        queue.push(target);
        rootCommits.push(target);
      }
    }
  }
  // BFS over commit parents. For a depth-limited fetch only distances up to depth-1 matter
  // (the boundary), so parents beyond that are never expanded: a depth-1 fetch touches the
  // tip alone instead of walking the whole history.
  for (let head = 0; head < queue.length; head += 1) {
    const oid = queue[head]!;
    const d = dist.get(oid)!;
    if (depth !== undefined && d >= depth - 1) continue;
    const object = repo.objects.get(oid);
    if (!object || object.type !== 'commit') continue;
    for (const parent of parseCommit(object.data).parents) {
      if (!dist.has(parent) && repo.objects.has(parent)) {
        dist.set(parent, d + 1);
        queue.push(parent);
      }
    }
  }

  const included = new Set<string>();
  const boundary = new Set<string>();
  if (depth === undefined) {
    for (const oid of dist.keys()) included.add(oid);
  } else {
    for (const [oid, d] of dist) {
      if (d < depth) included.add(oid);
      else if (d === depth) {
        // unreachable: BFS only adds parents, so d === depth never included; kept for clarity
      }
    }
    for (const oid of included) {
      if (dist.get(oid) === depth - 1) {
        const object = repo.objects.get(oid);
        if (object?.type === 'commit' && parseCommit(object.data).parents.length > 0) boundary.add(oid);
      }
    }
  }

  // Objects to send: everything reachable from included commits (+ non-commit wants),
  // minus what the client holds. Parent traversal stops at the depth boundary, so a
  // depth-1 fetch sends the tip, its tree and its blobs — and no history.
  const extraRoots: string[] = [];
  for (const want of wants) {
    const object = repo.objects.get(want);
    if (object && object.type !== 'commit') extraRoots.push(want);
  }
  const wantSet = collectShallowReachable(repo, included, extraRoots);
  const objects = new Map<string, GObj>();
  for (const oid of wantSet) {
    if (haveSet.has(oid)) continue;
    const object = repo.objects.get(oid);
    if (object) objects.set(oid, object);
  }

  // Unshallow: old boundaries now fully covered (included, and all parents included).
  const unshallow: string[] = [];
  for (const old of oldShallow) {
    if (!included.has(old)) continue;
    const object = repo.objects.get(old);
    if (!object || object.type !== 'commit') continue;
    const parents = parseCommit(object.data).parents;
    if (parents.every((p) => included.has(p))) unshallow.push(old);
  }

  return { objects, shallow: [...boundary].sort(), unshallow: unshallow.sort() };
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}, isHead = false): void {
  const text = `${JSON.stringify(body)}\n`;
  const all: Record<string, string> = { 'content-type': JSON_TYPE, 'x-github-request-id': requestId(), ...headers };
  if (status !== 204) all['content-length'] = String(Buffer.byteLength(text));
  res.writeHead(status, all);
  res.end(isHead || status === 204 ? undefined : text);
}

function sendRaw(res: ServerResponse, status: number, body: Buffer, contentType: string, headers: Record<string, string> = {}, isHead = false): void {
  res.writeHead(status, { 'content-type': contentType, 'content-length': String(body.length), 'x-github-request-id': requestId(), ...headers });
  res.end(isHead ? undefined : body);
}

function errJson(status: number, message: string): { status: number; body: { message: string } } {
  return { status, body: { message } };
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let done = false;
    req.on('data', (chunk: Buffer) => {
      if (done) return;
      size += chunk.length;
      if (size > MAX_BODY) {
        done = true;
        reject(new Error('request body too large'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (!done) resolve(Buffer.concat(chunks));
    });
    req.on('error', (err) => {
      if (!done) {
        done = true;
        reject(err);
      }
    });
  });
}

function authed(req: IncomingMessage): boolean {
  if (TOKEN === '') return true;
  return req.headers.authorization === `Bearer ${TOKEN}`;
}

function splitPath(pathname: string): string[] {
  const clean = pathname.replace(/\/+$/, '') || '/';
  return clean.split('/').filter((s) => s !== '').map((s) => {
    try {
      return decodeURIComponent(s);
    } catch {
      return s;
    }
  });
}

interface PageParams {
  page: number;
  perPage: number;
}

function pageParams(search: URLSearchParams): PageParams {
  const page = Math.max(1, Number.parseInt(search.get('page') ?? '1', 10) || 1);
  const perPageRaw = Number.parseInt(search.get('per_page') ?? '30', 10);
  const perPage = Number.isFinite(perPageRaw) ? Math.min(100, Math.max(1, perPageRaw)) : 30;
  return { page, perPage };
}

function paginate<T>(items: readonly T[], page: PageParams): { page: T[]; totalPages: number } {
  const totalPages = Math.max(1, Math.ceil(items.length / page.perPage));
  const start = (page.page - 1) * page.perPage;
  return { page: items.slice(start, start + page.perPage), totalPages };
}

/** Build a GitHub-style Link header for paginated lists. */
function linkHeader(baseUrl: string, path: string, search: URLSearchParams, page: PageParams, totalPages: number): string {
  const make = (p: number): string => {
    const q = new URLSearchParams(search);
    q.set('page', String(p));
    q.set('per_page', String(page.perPage));
    return `${baseUrl}${path}?${q.toString()}`;
  };
  const links: string[] = [];
  if (page.page < totalPages) links.push(`<${make(page.page + 1)}>; rel="next"`);
  if (totalPages > 1) links.push(`<${make(totalPages)}>; rel="last"`);
  if (page.page > 1) {
    links.push(`<${make(1)}>; rel="first"`);
    links.push(`<${make(page.page - 1)}>; rel="prev"`);
  }
  return links.join(', ');
}

// ---------------------------------------------------------------------------
// REST serializers
// ---------------------------------------------------------------------------

function userJson(): Record<string, unknown> {
  return { login: VIEWER_LOGIN, id: VIEWER_ID, node_id: globalId('User', VIEWER_ID), avatar_url: '', type: 'User', site_admin: false, name: VIEWER_NAME, email: VIEWER_EMAIL };
}

function repoJson(repo: Repo): Record<string, unknown> {
  const openIssues = repo.issues.filter((i) => i.state === 'open').length;
  const openPulls = repo.pulls.filter((p) => p.state === 'open').length;
  return {
    id: repo.id,
    node_id: globalId('Repository', repo.id),
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: userJson(),
    private: repo.isPrivate,
    description: repo.description,
    default_branch: repo.defaultBranch,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}`,
    created_at: FIXED_ISO,
    updated_at: FIXED_ISO,
    pushed_at: FIXED_ISO,
    has_issues: true,
    has_projects: true,
    has_downloads: true,
    has_wiki: true,
    has_pages: false,
    forks_count: 0,
    stargazers_count: 0,
    watchers_count: 0,
    open_issues_count: openIssues + openPulls,
    size: 0,
    language: null,
    topics: [],
    visibility: repo.isPrivate ? 'private' : 'public',
    fork: false,
    archived: false,
    disabled: false,
    license: null,
  };
}

function labelJson(repo: Repo, label: Label): Record<string, unknown> {
  return {
    id: label.id,
    node_id: globalId('Label', repo.id, label.name),
    name: label.name,
    color: label.color,
    description: label.description,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/labels/${encodeURIComponent(label.name)}`,
    default: false,
  };
}

function issueJson(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: issue.id,
    node_id: globalId('Issue', repo.id, issue.number),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    user: userJson(),
    labels: issue.labels.map((l) => labelJson(repo, l)),
    comments: issue.comments.length,
    created_at: FIXED_ISO,
    updated_at: FIXED_ISO,
    closed_at: issue.state === 'closed' ? FIXED_ISO : null,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/issues/${issue.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}`,
    repository_url: `/api/v3/repos/${repo.owner}/${repo.name}`,
    comments_url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}/comments`,
    assignee: null,
    assignees: [],
    milestone: null,
    locked: false,
    author_association: 'OWNER',
  };
}

function commentJson(repo: Repo, issue: Issue, comment: Comment): Record<string, unknown> {
  return {
    id: comment.id,
    node_id: globalId('IssueComment', repo.id, issue.number, comment.id),
    body: comment.body,
    user: userJson(),
    created_at: FIXED_ISO,
    updated_at: FIXED_ISO,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/issues/${issue.number}#issuecomment-${comment.id}`,
    issue_url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/comments/${comment.id}`,
    author_association: 'OWNER',
  };
}

function headSha(repo: Repo, pr: Pull): string {
  return repo.refs.get(`refs/heads/${pr.headRef}`) ?? ZERO_OID;
}

function baseSha(repo: Repo, pr: Pull): string {
  return repo.refs.get(`refs/heads/${pr.baseRef}`) ?? ZERO_OID;
}

function pullCommitsCount(repo: Repo, pr: Pull): number {
  const head = headSha(repo, pr);
  const base = baseSha(repo, pr);
  if (head === ZERO_OID || base === ZERO_OID) return 0;
  const headSet = collectReachable(repo, [head], { allowMissing: true });
  const baseSet = collectReachable(repo, [base], { allowMissing: true });
  let count = 0;
  for (const oid of headSet) {
    const obj = repo.objects.get(oid);
    if (obj?.type === 'commit' && !baseSet.has(oid)) count += 1;
  }
  return count;
}

function pullJson(repo: Repo, pr: Pull): Record<string, unknown> {
  const files = pullRequestFiles(repo, pr);
  const additions = files.reduce((s, f) => s + f.additions, 0);
  const deletions = files.reduce((s, f) => s + f.deletions, 0);
  return {
    id: pr.id,
    node_id: globalId('PullRequest', repo.id, pr.number),
    number: pr.number,
    title: pr.title,
    body: pr.body,
    state: pr.state,
    user: userJson(),
    head: {
      label: `${repo.owner}:${pr.headRef}`,
      ref: pr.headRef,
      sha: headSha(repo, pr),
      user: userJson(),
      repo: { id: repo.id, name: repo.name, full_name: `${repo.owner}/${repo.name}` },
    },
    base: {
      label: `${repo.owner}:${pr.baseRef}`,
      ref: pr.baseRef,
      sha: baseSha(repo, pr),
      user: userJson(),
      repo: { id: repo.id, name: repo.name, full_name: `${repo.owner}/${repo.name}` },
    },
    merged: pr.merged,
    mergeable: pullRequestMergeable(repo, pr),
    merge_commit_sha: pr.mergeSha,
    merged_at: pr.mergedAt,
    merged_by: pr.merged ? userJson() : null,
    created_at: FIXED_ISO,
    updated_at: FIXED_ISO,
    closed_at: pr.state === 'closed' ? FIXED_ISO : null,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/pull/${pr.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/pulls/${pr.number}`,
    diff_url: `https://example.invalid/${repo.owner}/${repo.name}/pull/${pr.number}.diff`,
    patch_url: `https://example.invalid/${repo.owner}/${repo.name}/pull/${pr.number}.patch`,
    comments: 0,
    review_comments: 0,
    commits: pullCommitsCount(repo, pr),
    additions,
    deletions,
    changed_files: files.length,
    draft: false,
    locked: false,
    author_association: 'OWNER',
  };
}

// ---------------------------------------------------------------------------
// shared domain operations (REST, GraphQL and MCP all use these)
// ---------------------------------------------------------------------------

let objectIdSeq = 1;
function nextObjectId(): number {
  const id = objectIdSeq;
  objectIdSeq += 1;
  return id;
}

function createIssueInRepo(repo: Repo, title: string, body: string, labels: Label[]): Issue {
  const number = repo.nextNumber;
  repo.nextNumber += 1;
  const issue: Issue = {
    id: nextObjectId(),
    number,
    title,
    body,
    state: 'open',
    labels: [...labels],
    seq: repo.nextNumber,
    comments: [],
  };
  repo.issues.push(issue);
  return issue;
}

function createPullInRepo(repo: Repo, title: string, body: string, head: string, base: string): Pull {
  const number = repo.nextNumber;
  repo.nextNumber += 1;
  const pr: Pull = {
    id: nextObjectId(),
    number,
    title,
    body,
    state: 'open',
    merged: false,
    mergedAt: null,
    mergeSha: null,
    headRef: head,
    baseRef: base,
    seq: repo.nextNumber,
  };
  repo.pulls.push(pr);
  return pr;
}

function findIssue(repo: Repo, number: number): Issue | undefined {
  return repo.issues.find((i) => i.number === number);
}

function findPull(repo: Repo, number: number): Pull | undefined {
  return repo.pulls.find((p) => p.number === number);
}

/** Merge a pull request. Returns the merge sha, or 'conflict' / 'closed' / 'missing'. */
function mergePullInRepo(repo: Repo, pr: Pull): { sha: string } | { error: 'conflict' | 'closed' | 'missing' } {
  if (pr.state === 'closed') return { error: 'closed' };
  const headOid = repo.refs.get(`refs/heads/${pr.headRef}`);
  const baseOid = repo.refs.get(`refs/heads/${pr.baseRef}`);
  if (!headOid || !baseOid) return { error: 'missing' };
  const sha = squashMerge(repo, pr);
  if (sha === null) return { error: 'conflict' };
  pr.state = 'closed';
  pr.merged = true;
  pr.mergedAt = FIXED_ISO;
  pr.mergeSha = sha;
  return { sha };
}

// ---------------------------------------------------------------------------
// contents helpers
// ---------------------------------------------------------------------------

/** Resolve a ref (branch name, commit oid, or undefined for the default branch) to its tip commit oid. */
function resolveRefCommit(repo: Repo, ref: string | undefined): string | null {
  if (ref === undefined || ref === '') return repo.refs.get(`refs/heads/${repo.defaultBranch}`) ?? null;
  const asBranch = repo.refs.get(`refs/heads/${ref}`);
  if (asBranch) return asBranch;
  if (isObjectId(ref)) {
    const obj = repo.objects.get(ref);
    if (obj?.type === 'commit') return ref;
  }
  const asTag = repo.refs.get(`refs/tags/${ref}`);
  if (asTag) {
    const obj = repo.objects.get(asTag);
    if (obj?.type === 'tag') return parseTag(obj.data).object;
    if (obj?.type === 'commit') return asTag;
  }
  return null;
}

interface ContentEntry {
  type: 'file' | 'dir';
  name: string;
  path: string;
  sha: string;
  size: number;
}

/** List the entries of a tree (one directory level). */
function listTreeEntries(repo: Repo, treeOid: string, dirPath: string): ContentEntry[] {
  const object = repo.objects.get(treeOid);
  if (!object || object.type !== 'tree') return [];
  const entries: ContentEntry[] = [];
  for (const entry of parseTree(object.data)) {
    const path = dirPath === '' ? entry.name : `${dirPath}/${entry.name}`;
    if (entry.mode === '40000') {
      entries.push({ type: 'dir', name: entry.name, path, sha: entry.oid, size: 0 });
    } else if (entry.mode !== '160000') {
      const blob = repo.objects.get(entry.oid);
      entries.push({ type: 'file', name: entry.name, path, sha: entry.oid, size: blob ? blob.data.length : 0 });
    }
  }
  return entries;
}

/** Split a git identity line `Name <email> ts tz` into its name and email parts. */
function parseIdentity(line: string): { name: string; email: string } {
  const match = /^([^<]*)<([^>]*)>/.exec(line.trim());
  if (!match) return { name: line.trim(), email: '' };
  return { name: match[1]!.trim(), email: match[2]!.trim() };
}

/** Find a path inside a tree: file blob oid or the tree oid of a directory. */
function lookupPath(repo: Repo, treeOid: string, path: string): { kind: 'file'; oid: string; size: number } | { kind: 'dir'; oid: string } | null {
  const segments = path.split('/').filter((s) => s !== '');
  let current = treeOid;
  for (let i = 0; i < segments.length; i += 1) {
    const object = repo.objects.get(current);
    if (!object || object.type !== 'tree') return null;
    const entry = parseTree(object.data).find((e) => e.name === segments[i]);
    if (!entry) return null;
    const last = i === segments.length - 1;
    if (entry.mode === '40000') {
      if (last) return { kind: 'dir', oid: entry.oid };
      current = entry.oid;
    } else if (entry.mode === '160000') {
      return null;
    } else {
      if (!last) return null;
      const blob = repo.objects.get(entry.oid);
      return { kind: 'file', oid: entry.oid, size: blob ? blob.data.length : 0 };
    }
  }
  return { kind: 'dir', oid: current };
}

// ---------------------------------------------------------------------------
// REST handlers
// ---------------------------------------------------------------------------

interface RestResult {
  status: number;
  body: unknown;
  headers?: Record<string, string>;
}

function notFound(message: string): RestResult {
  return { status: 404, body: { message } };
}

function badRequest(message: string): RestResult {
  return { status: 400, body: { message } };
}

function unprocessable(message: string): RestResult {
  return { status: 422, body: { message } };
}

function unauthorized(): RestResult {
  return { status: 401, body: { message: 'Requires authentication' } };
}

function requireRepo(owner: string, name: string): Repo | null {
  if (owner !== VIEWER_LOGIN) return null;
  return findRepo(owner, name) ?? null;
}

function repoOr404(owner: string, name: string): { repo: Repo } | RestResult {
  const repo = requireRepo(owner, name);
  if (!repo) return notFound(`Repository ${owner}/${name} not found`);
  return { repo };
}

/** Parse a JSON request body for a REST call. A RestResult is a record too, so the result is
 * tagged — callers must check `ok` before using the body. */
function parseJsonBody(bodyText: string): { ok: true; body: Record<string, unknown> } | { ok: false; error: RestResult } {
  if (bodyText.trim() === '') return { ok: true, body: {} };
  try {
    const parsed = JSON.parse(bodyText) as unknown;
    if (!isRecord(parsed)) return { ok: false, error: badRequest('request body must be a JSON object') };
    return { ok: true, body: parsed };
  } catch {
    return { ok: false, error: badRequest('request body is not valid JSON') };
  }
}

function asString(v: unknown): string | null {
  return typeof v === 'string' ? v : null;
}

function asStringArray(v: unknown): string[] | null {
  if (!Array.isArray(v)) return null;
  const out: string[] = [];
  for (const item of v) {
    if (typeof item === 'string') out.push(item);
    else if (isRecord(item) && typeof item.name === 'string') out.push(item.name);
    else return null;
  }
  return out;
}

async function handleRest(
  req: IncomingMessage,
  res: ServerResponse,
  method: string,
  segs: string[],
  url: URL,
  bodyText: string,
  isHead: boolean,
): Promise<boolean> {
  if (segs[0] !== 'api' || segs[1] !== 'v3') return false;
  const search = url.searchParams;
  const send = (r: RestResult): void => sendJson(res, r.status, r.body, r.headers ?? {}, isHead);

  // API root and meta: no auth.
  if (segs.length === 2) {
    if (method !== 'GET') return false;
    send({
      status: 200,
      body: { current_user_url: '/api/v3/user', current_user_repositories_url: '/api/v3/user/repos', rate_limit_url: '/api/v3/rate_limit', repository_url: '/api/v3/repos/{owner}/{repo}' },
      headers: { 'x-oauth-scopes': 'repo, read:org' },
    });
    return true;
  }
  if (segs.length === 3 && segs[2] === 'meta') {
    if (method !== 'GET') return false;
    send({ status: 200, body: { installed_version: VERSION } });
    return true;
  }

  // Everything else under /api/v3 needs the token.
  if (!authed(req)) {
    send(unauthorized());
    return true;
  }
  const scopes = { 'x-oauth-scopes': 'repo, read:org' };

  // GET /user
  if (segs.length === 3 && segs[2] === 'user') {
    if (method !== 'GET') return false;
    send({ status: 200, body: userJson(), headers: scopes });
    return true;
  }

  // /user/repos
  if (segs.length === 4 && segs[2] === 'user' && segs[3] === 'repos') {
    if (method === 'GET') {
      const all = [...repos.values()].sort((a, b) => a.createdSeq - b.createdSeq).map((r) => repoJson(r));
      const page = pageParams(search);
      const { page: items, totalPages } = paginate(all, page);
      const headers: Record<string, string> = { ...scopes };
      if (totalPages > 1) headers.link = linkHeader(`http://${req.headers.host ?? 'entry'}`, '/api/v3/user/repos', search, page, totalPages);
      send({ status: 200, body: items, headers });
      return true;
    }
    if (method === 'POST') {
      const result = parseJsonBody(bodyText);
      if (!result.ok) {
        send(result.error);
        return true;
      }
      const parsed = result.body;
      const name = asString(parsed.name);
      if (!name || name.includes('/') || name.length > 100) {
        send(unprocessable('name is required and must be a valid repository name'));
        return true;
      }
      if (findRepo(VIEWER_LOGIN, name)) {
        send(unprocessable(`name already exists on this account`));
        return true;
      }
      const repo = createRepoRecord(name, parsed.private === true, asString(parsed.description) ?? '');
      send({ status: 201, body: repoJson(repo), headers: scopes });
      return true;
    }
    return false;
  }

  // /repos/{owner}/{name}[...]
  if (segs.length >= 5 && segs[2] === 'repos') {
    const owner = segs[3]!;
    const name = segs[4]!;
    const found = repoOr404(owner, name);
    if (!('repo' in found)) {
      send(found);
      return true;
    }
    const repo = found.repo;
    const rest = segs.slice(5);

    // /repos/{o}/{r}
    if (rest.length === 0) {
      if (method === 'GET') {
        send({ status: 200, body: repoJson(repo), headers: scopes });
        return true;
      }
      if (method === 'PATCH') {
        const result = parseJsonBody(bodyText);
        if (!result.ok) {
          send(result.error);
          return true;
        }
        const parsed = result.body;
        if (typeof parsed.description === 'string') repo.description = parsed.description;
        if (typeof parsed.private === 'boolean') repo.isPrivate = parsed.private;
        send({ status: 200, body: repoJson(repo), headers: scopes });
        return true;
      }
      if (method === 'DELETE') {
        repos.delete(repoKey(owner, name));
        res.writeHead(204, { 'content-type': JSON_TYPE, 'x-github-request-id': requestId(), ...scopes });
        res.end();
        return true;
      }
      return false;
    }

    // /branches
    if (rest[0] === 'branches') {
      if (rest.length === 1 && method === 'GET') {
        const branches = [...repo.refs.keys()]
          .filter((r) => r.startsWith('refs/heads/'))
          .map((r) => r.slice('refs/heads/'.length))
          .sort((a, b) => (a === repo.defaultBranch ? -1 : b === repo.defaultBranch ? 1 : a < b ? -1 : 1));
        send({
          status: 200,
          body: branches.map((b) => ({ name: b, commit: { sha: repo.refs.get(`refs/heads/${b}`) ?? '' }, protected: false })),
          headers: scopes,
        });
        return true;
      }
      if (rest.length > 1 && method === 'GET') {
        const branch = rest.slice(1).join('/');
        const sha = repo.refs.get(`refs/heads/${branch}`);
        if (!sha) {
          send(notFound(`Branch ${branch} not found`));
          return true;
        }
        const commit = repo.objects.get(sha);
        const view = commit?.type === 'commit' ? parseCommit(commit.data) : null;
        send({
          status: 200,
          body: {
            name: branch,
            commit: { sha, commit: view ? { message: view.message, author: { name: parseIdentity(view.author).name }, committer: { name: parseIdentity(view.committer).name } } : undefined },
            protected: false,
          },
          headers: scopes,
        });
        return true;
      }
      return false;
    }

    // /commits
    if (rest[0] === 'commits' && rest.length === 1 && method === 'GET') {
      const shaParam = search.get('sha') ?? undefined;
      const tip = resolveRefCommit(repo, shaParam);
      if (shaParam !== undefined && tip === null) {
        send(notFound(`No commit found for ${shaParam}`));
        return true;
      }
      let commits: Array<{ sha: string; seq: number; message: string; author: string; committer: string; parents: string[] }> = [];
      if (tip !== null) {
        const reachable = collectReachable(repo, [tip], { allowMissing: true });
        for (const oid of reachable) {
          const obj = repo.objects.get(oid);
          if (!obj || obj.type !== 'commit') continue;
          const view = parseCommit(obj.data);
          commits.push({ sha: oid, seq: repo.commitSeq.get(oid) ?? 0, message: view.message, author: parseIdentity(view.author).name, committer: parseIdentity(view.committer).name, parents: view.parents });
        }
        commits.sort((a, b) => b.seq - a.seq);
      }
      send({
        status: 200,
        body: commits.map((c) => ({
          sha: c.sha,
          node_id: globalId('Commit', c.sha),
          commit: { message: c.message, author: { name: c.author }, committer: { name: c.committer } },
          parents: c.parents.map((p) => ({ sha: p })),
          url: `/api/v3/repos/${owner}/${name}/commits/${c.sha}`,
        })),
        headers: scopes,
      });
      return true;
    }

    // /git/refs
    if (rest[0] === 'git' && rest[1] === 'refs') {
      if (rest.length === 2 && method === 'POST') {
        const result = parseJsonBody(bodyText);
        if (!result.ok) {
          send(result.error);
          return true;
        }
        const parsed = result.body;
        const ref = asString(parsed.ref);
        const sha = asString(parsed.sha);
        if (!ref || !ref.startsWith('refs/')) {
          send(unprocessable('ref must start with refs/'));
          return true;
        }
        if (!sha || !isObjectId(sha) || !repo.objects.has(sha)) {
          send(unprocessable('sha does not name an object in this repository'));
          return true;
        }
        if (repo.refs.has(ref)) {
          send(unprocessable('Reference already exists'));
          return true;
        }
        if (ref.startsWith('refs/heads/')) {
          const obj = repo.objects.get(sha);
          if (obj?.type !== 'commit') {
            send(unprocessable('sha does not name a commit'));
            return true;
          }
        }
        repo.refs.set(ref, sha);
        const obj = repo.objects.get(sha)!;
        send({ status: 201, body: { ref, node_id: globalId('Ref', repo.id, ref), url: `/api/v3/repos/${owner}/${name}/git/refs/${ref.slice(5)}`, object: { sha, type: obj.type, url: '' } }, headers: scopes });
        return true;
      }
      if (rest.length === 2 && method === 'GET') {
        const all = [...repo.refs.entries()].sort(([a], [b]) => (a < b ? -1 : 1));
        send({
          status: 200,
          body: all.map(([ref, sha]) => ({ ref, object: { sha, type: repo.objects.get(sha)?.type ?? 'commit' } })),
          headers: scopes,
        });
        return true;
      }
      if (rest.length > 2 && (method === 'GET' || method === 'DELETE')) {
        const ref = `refs/${rest.slice(2).join('/')}`;
        const sha = repo.refs.get(ref);
        if (!sha) {
          send(notFound(`Reference ${ref} not found`));
          return true;
        }
        if (method === 'DELETE') {
          repo.refs.delete(ref);
          res.writeHead(204, { 'content-type': JSON_TYPE, 'x-github-request-id': requestId(), ...scopes });
          res.end();
          return true;
        }
        send({ status: 200, body: { ref, object: { sha, type: repo.objects.get(sha)?.type ?? 'commit' } }, headers: scopes });
        return true;
      }
      return false;
    }

    // /contents
    if (rest[0] === 'contents') {
      const contentPath = rest.slice(1).join('/');
      if (method === 'GET') {
        const refParam = search.get('ref') ?? undefined;
        const tip = resolveRefCommit(repo, refParam);
        if (tip === null) {
          send(notFound('Not Found'));
          return true;
        }
        const treeOid = parseCommit(repo.objects.get(tip)!.data).tree;
        if (contentPath === '') {
          send({ status: 200, body: listTreeEntries(repo, treeOid, ''), headers: scopes });
          return true;
        }
        const found = lookupPath(repo, treeOid, contentPath);
        if (!found) {
          send(notFound('Not Found'));
          return true;
        }
        if (found.kind === 'dir') {
          send({ status: 200, body: listTreeEntries(repo, found.oid, contentPath), headers: scopes });
          return true;
        }
        const blob = repo.objects.get(found.oid)!;
        const baseName = contentPath.split('/').pop() ?? contentPath;
        send({
          status: 200,
          body: {
            type: 'file',
            encoding: 'base64',
            size: found.size,
            name: baseName,
            path: contentPath,
            content: b64encode(blob.data),
            sha: found.oid,
            url: `/api/v3/repos/${owner}/${name}/contents/${contentPath}`,
          },
          headers: scopes,
        });
        return true;
      }
      if (method === 'PUT') {
        const result = parseJsonBody(bodyText);
        if (!result.ok) {
          send(result.error);
          return true;
        }
        const parsed = result.body;
        const contentB64 = asString(parsed.content);
        if (contentB64 === null) {
          send(unprocessable('content is required'));
          return true;
        }
        const message = asString(parsed.message) ?? `Update ${contentPath}`;
        const branch = asString(parsed.branch) ?? undefined;
        const shaParam = asString(parsed.sha) ?? undefined;
        const branchName = branch ?? repo.defaultBranch;
        const refName = `refs/heads/${branchName}`;
        if (!repo.refs.has(refName)) {
          const defaultTip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
          if (defaultTip) repo.refs.set(refName, defaultTip);
        }
        const tip = repo.refs.get(refName) ?? null;
        const flat = tip ? flattenTree(repo, parseCommit(repo.objects.get(tip)!.data).tree) : new Map<string, { mode: string; oid: string }>();
        const existing = flat.get(contentPath);
        const content = b64decode(contentB64);
        const blobOid = putObject(repo, 'blob', content);
        if (existing) {
          if (!shaParam) {
            send(unprocessable('sha is required to update a file'));
            return true;
          }
          if (shaParam !== existing.oid) {
            send({ status: 409, body: { message: 'sha does not match the current file' } });
            return true;
          }
          flat.set(contentPath, { mode: '100644', oid: blobOid });
          const commitSha = commitTree(repo, branchName, flat, message);
          const baseName = contentPath.split('/').pop() ?? contentPath;
          send({
            status: 200,
            body: { content: { name: baseName, path: contentPath, sha: blobOid, size: content.length, encoding: 'base64' }, commit: { sha: commitSha, message } },
            headers: scopes,
          });
          return true;
        }
        if (shaParam) {
          send(unprocessable('sha must not be given when creating a file'));
          return true;
        }
        flat.set(contentPath, { mode: '100644', oid: blobOid });
        const commitSha = commitTree(repo, branchName, flat, message);
        const baseName = contentPath.split('/').pop() ?? contentPath;
        send({
          status: 201,
          body: { content: { name: baseName, path: contentPath, sha: blobOid, size: content.length, encoding: 'base64' }, commit: { sha: commitSha, message } },
          headers: scopes,
        });
        return true;
      }
      if (method === 'DELETE') {
        const result = parseJsonBody(bodyText);
        if (!result.ok) {
          send(result.error);
          return true;
        }
        const parsed = result.body;
        const message = asString(parsed.message) ?? `Delete ${contentPath}`;
        const branch = asString(parsed.branch) ?? undefined;
        const shaParam = asString(parsed.sha) ?? undefined;
        const branchName = branch ?? repo.defaultBranch;
        const tip = repo.refs.get(`refs/heads/${branchName}`) ?? null;
        if (tip === null) {
          send(notFound('Not Found'));
          return true;
        }
        const flat = flattenTree(repo, parseCommit(repo.objects.get(tip)!.data).tree);
        const existing = flat.get(contentPath);
        if (!existing) {
          send(notFound('Not Found'));
          return true;
        }
        if (shaParam && shaParam !== existing.oid) {
          send({ status: 409, body: { message: 'sha does not match the current file' } });
          return true;
        }
        flat.delete(contentPath);
        const commitSha = commitTree(repo, branchName, flat, message);
        send({ status: 200, body: { commit: { sha: commitSha, message } }, headers: scopes });
        return true;
      }
      return false;
    }

    // /labels
    if (rest[0] === 'labels') {
      if (rest.length === 1 && method === 'GET') {
        send({ status: 200, body: [...repo.labels.values()].map((l) => labelJson(repo, l)), headers: scopes });
        return true;
      }
      if (rest.length === 1 && method === 'POST') {
        const result = parseJsonBody(bodyText);
        if (!result.ok) {
          send(result.error);
          return true;
        }
        const parsed = result.body;
        const name = asString(parsed.name);
        if (!name) {
          send(unprocessable('name is required'));
          return true;
        }
        if (repo.labels.has(name)) {
          send(unprocessable(`Label '${name}' already exists`));
          return true;
        }
        const label: Label = { id: labelIdSeq, name, color: asString(parsed.color) ?? 'ededed', description: asString(parsed.description) ?? '' };
        labelIdSeq += 1;
        repo.labels.set(name, label);
        send({ status: 201, body: labelJson(repo, label), headers: scopes });
        return true;
      }
      return false;
    }

    // /issues
    if (rest[0] === 'issues') {
      if (rest.length === 1 && method === 'POST') {
        const result = parseJsonBody(bodyText);
        if (!result.ok) {
          send(result.error);
          return true;
        }
        const parsed = result.body;
        const title = asString(parsed.title);
        if (!title) {
          send(unprocessable('title is required'));
          return true;
        }
        const labelNames = parsed.labels === undefined ? [] : asStringArray(parsed.labels);
        if (labelNames === null) {
          send(unprocessable('labels must be an array of names'));
          return true;
        }
        const labels: Label[] = [];
        for (const ln of labelNames) {
          const foundLabel = repo.labels.get(ln);
          if (!foundLabel) {
            send(unprocessable(`Label '${ln}' does not exist`));
            return true;
          }
          labels.push(foundLabel);
        }
        const issue = createIssueInRepo(repo, title, asString(parsed.body) ?? '', labels);
        send({ status: 201, body: issueJson(repo, issue), headers: scopes });
        return true;
      }
      if (rest.length === 1 && method === 'GET') {
        const state = search.get('state') ?? 'open';
        const sort = search.get('sort') ?? 'created';
        const direction = search.get('direction') ?? 'desc';
        let list = repo.issues.filter((i) => (state === 'all' ? true : i.state === state));
        if (sort === 'created') list = [...list].sort((a, b) => (direction === 'asc' ? a.seq - b.seq : b.seq - a.seq));
        const page = pageParams(search);
        const { page: items, totalPages } = paginate(list, page);
        const headers: Record<string, string> = { ...scopes };
        if (totalPages > 1) headers.link = linkHeader(`http://${req.headers.host ?? 'entry'}`, `/api/v3/repos/${owner}/${name}/issues`, search, page, totalPages);
        send({ status: 200, body: items.map((i) => issueJson(repo, i)), headers });
        return true;
      }
      if (rest.length >= 2) {
        const number = Number.parseInt(rest[1]!, 10);
        if (!Number.isInteger(number)) {
          send(notFound('Not Found'));
          return true;
        }
        const issue = findIssue(repo, number);
        if (rest.length === 2 && method === 'GET') {
          if (!issue) {
            send(notFound('Not Found'));
            return true;
          }
          send({ status: 200, body: issueJson(repo, issue), headers: scopes });
          return true;
        }
        if (rest.length === 2 && method === 'PATCH') {
          if (!issue) {
            send(notFound('Not Found'));
            return true;
          }
          const result = parseJsonBody(bodyText);
          if (!result.ok) {
            send(result.error);
            return true;
          }
          const parsed = result.body;
          if (parsed.state === 'open' || parsed.state === 'closed') issue.state = parsed.state;
          if (typeof parsed.title === 'string') issue.title = parsed.title;
          if (typeof parsed.body === 'string') issue.body = parsed.body;
          if (parsed.labels !== undefined) {
            const labelNames = asStringArray(parsed.labels);
            if (labelNames === null) {
              send(unprocessable('labels must be an array of names'));
              return true;
            }
            const labels: Label[] = [];
            for (const ln of labelNames) {
              const foundLabel = repo.labels.get(ln);
              if (!foundLabel) {
                send(unprocessable(`Label '${ln}' does not exist`));
                return true;
              }
              labels.push(foundLabel);
            }
            issue.labels = labels;
          }
          send({ status: 200, body: issueJson(repo, issue), headers: scopes });
          return true;
        }
        if (rest.length === 3 && rest[2] === 'comments') {
          if (!issue) {
            send(notFound('Not Found'));
            return true;
          }
          if (method === 'POST') {
            const result = parseJsonBody(bodyText);
            if (!result.ok) {
              send(result.error);
              return true;
            }
            const parsed = result.body;
            const body = asString(parsed.body);
            if (body === null) {
              send(unprocessable('body is required'));
              return true;
            }
            const comment: Comment = { id: commentIdSeq, body };
            commentIdSeq += 1;
            issue.comments.push(comment);
            send({ status: 201, body: commentJson(repo, issue, comment), headers: scopes });
            return true;
          }
          if (method === 'GET') {
            send({ status: 200, body: issue.comments.map((c) => commentJson(repo, issue, c)), headers: scopes });
            return true;
          }
          return false;
        }
        return false;
      }
      return false;
    }

    // /pulls
    if (rest[0] === 'pulls') {
      if (rest.length === 1 && method === 'POST') {
        const result = parseJsonBody(bodyText);
        if (!result.ok) {
          send(result.error);
          return true;
        }
        const parsed = result.body;
        const title = asString(parsed.title);
        const headRaw = parsed.head;
        const baseRaw = parsed.base;
        const head = typeof headRaw === 'string' ? headRaw : isRecord(headRaw) ? asString(headRaw.ref) : null;
        const base = typeof baseRaw === 'string' ? baseRaw : isRecord(baseRaw) ? asString(baseRaw.ref) : null;
        if (!title) {
          send(unprocessable('title is required'));
          return true;
        }
        if (!head || !base) {
          send(unprocessable('head and base are required'));
          return true;
        }
        if (!repo.refs.has(`refs/heads/${head}`)) {
          send(unprocessable(`Head branch '${head}' does not exist`));
          return true;
        }
        if (!repo.refs.has(`refs/heads/${base}`)) {
          send(unprocessable(`Base branch '${base}' does not exist`));
          return true;
        }
        if (head === base) {
          send(unprocessable('head and base must be different branches'));
          return true;
        }
        const existing = repo.pulls.find((p) => p.state === 'open' && p.headRef === head && p.baseRef === base);
        if (existing) {
          send(unprocessable('A pull request already exists for this head and base'));
          return true;
        }
        const pr = createPullInRepo(repo, title, asString(parsed.body) ?? '', head, base);
        send({ status: 201, body: pullJson(repo, pr), headers: scopes });
        return true;
      }
      if (rest.length === 1 && method === 'GET') {
        const state = search.get('state') ?? 'open';
        let list = repo.pulls.filter((p) => (state === 'all' ? true : p.state === state));
        list = [...list].sort((a, b) => b.seq - a.seq);
        const page = pageParams(search);
        const { page: items, totalPages } = paginate(list, page);
        const headers: Record<string, string> = { ...scopes };
        if (totalPages > 1) headers.link = linkHeader(`http://${req.headers.host ?? 'entry'}`, `/api/v3/repos/${owner}/${name}/pulls`, search, page, totalPages);
        send({ status: 200, body: items.map((p) => pullJson(repo, p)), headers });
        return true;
      }
      if (rest.length >= 2) {
        const number = Number.parseInt(rest[1]!, 10);
        if (!Number.isInteger(number)) {
          send(notFound('Not Found'));
          return true;
        }
        const pr = findPull(repo, number);
        if (rest.length === 2 && method === 'GET') {
          if (!pr) {
            send(notFound('Not Found'));
            return true;
          }
          send({ status: 200, body: pullJson(repo, pr), headers: scopes });
          return true;
        }
        if (rest.length === 3 && rest[2] === 'files' && method === 'GET') {
          if (!pr) {
            send(notFound('Not Found'));
            return true;
          }
          send({
            status: 200,
            body: pullRequestFiles(repo, pr).map((f) => ({ filename: f.filename, status: f.status, additions: f.additions, deletions: f.deletions, changes: f.changes })),
            headers: scopes,
          });
          return true;
        }
        if (rest.length === 3 && rest[2] === 'merge' && method === 'PUT') {
          if (!pr) {
            send(notFound('Not Found'));
            return true;
          }
          const result = mergePullInRepo(repo, pr);
          if ('error' in result) {
            if (result.error === 'conflict') {
              send({ status: 405, body: { message: 'Merge conflict: the pull request cannot be merged cleanly' } });
              return true;
            }
            if (result.error === 'closed') {
              send({ status: 405, body: { message: 'Pull request is already closed' } });
              return true;
            }
            send(notFound('Head or base branch not found'));
            return true;
          }
          send({ status: 200, body: { sha: result.sha, merged: true, message: `Pull request #${pr.number} merged` }, headers: scopes });
          return true;
        }
        return false;
      }
      return false;
    }

    // Unknown route under this repo.
    send(notFound('Not Found'));
    return true;
  }

  // Unknown /api/v3 route.
  send(notFound('Not Found'));
  return true;
}

// ---------------------------------------------------------------------------
// GraphQL parser (tokenizer + recursive descent; no dependencies)
// ---------------------------------------------------------------------------

type GqlValueNode =
  | { kind: 'variable'; name: string }
  | { kind: 'string'; value: string }
  | { kind: 'int'; value: number }
  | { kind: 'float'; value: number }
  | { kind: 'boolean'; value: boolean }
  | { kind: 'null' }
  | { kind: 'enum'; value: string }
  | { kind: 'list'; items: GqlValueNode[] }
  | { kind: 'object'; fields: Record<string, GqlValueNode> };

interface GqlField {
  kind: 'field';
  alias: string | null;
  name: string;
  args: Record<string, GqlValueNode>;
  selections: GqlSelection[] | null;
}

interface GqlInlineFragment {
  kind: 'inline';
  typeCondition: string | null;
  selections: GqlSelection[];
}

interface GqlFragmentSpread {
  kind: 'spread';
  name: string;
}

type GqlSelection = GqlField | GqlInlineFragment | GqlFragmentSpread;

interface GqlVarDef {
  name: string;
  typeName: string;
  defaultValue: GqlValueNode | null;
}

interface GqlOperation {
  kind: 'operation';
  operation: 'query' | 'mutation';
  name: string | null;
  varDefs: GqlVarDef[];
  selections: GqlSelection[];
}

interface GqlFragmentDef {
  kind: 'fragment';
  name: string;
  typeCondition: string;
  selections: GqlSelection[];
}

type GqlDefinition = GqlOperation | GqlFragmentDef;

interface GqlToken {
  type: 'name' | 'int' | 'float' | 'string' | 'punct' | 'spread' | 'eof';
  value: string;
}

class GqlParseError extends Error {}

function tokenizeGql(source: string): GqlToken[] {
  const tokens: GqlToken[] = [];
  let i = 0;
  while (i < source.length) {
    const ch = source[i]!;
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === ',') {
      i += 1;
      continue;
    }
    if (ch === '#') {
      while (i < source.length && source[i] !== '\n') i += 1;
      continue;
    }
    if (ch === '.' && source[i + 1] === '.' && source[i + 2] === '.') {
      tokens.push({ type: 'spread', value: '...' });
      i += 3;
      continue;
    }
    if ('{}()[]:$!=@|&'.includes(ch)) {
      tokens.push({ type: 'punct', value: ch });
      i += 1;
      continue;
    }
    if (ch === '"') {
      let j = i + 1;
      let out = '';
      while (j < source.length && source[j] !== '"') {
        if (source[j] === '\\' && j + 1 < source.length) {
          const esc = source[j + 1]!;
          if (esc === 'n') out += '\n';
          else if (esc === 't') out += '\t';
          else if (esc === 'r') out += '\r';
          else if (esc === 'b') out += '\b';
          else if (esc === 'f') out += '\f';
          else if (esc === 'u') {
            out += String.fromCharCode(Number.parseInt(source.slice(j + 2, j + 6), 16) || 0);
            j += 4;
          } else out += esc;
          j += 2;
          continue;
        }
        out += source[j];
        j += 1;
      }
      if (j >= source.length) throw new GqlParseError('unterminated string');
      tokens.push({ type: 'string', value: out });
      i = j + 1;
      continue;
    }
    if (ch === '-' || (ch >= '0' && ch <= '9')) {
      let j = i;
      if (source[j] === '-') j += 1;
      while (j < source.length && /[0-9]/.test(source[j]!)) j += 1;
      let isFloat = false;
      if (source[j] === '.') {
        isFloat = true;
        j += 1;
        while (j < source.length && /[0-9]/.test(source[j]!)) j += 1;
      }
      if (source[j] === 'e' || source[j] === 'E') {
        isFloat = true;
        j += 1;
        if (source[j] === '+' || source[j] === '-') j += 1;
        while (j < source.length && /[0-9]/.test(source[j]!)) j += 1;
      }
      tokens.push({ type: isFloat ? 'float' : 'int', value: source.slice(i, j) });
      i = j;
      continue;
    }
    if (/[_A-Za-z]/.test(ch)) {
      let j = i;
      while (j < source.length && /[_A-Za-z0-9]/.test(source[j]!)) j += 1;
      tokens.push({ type: 'name', value: source.slice(i, j) });
      i = j;
      continue;
    }
    throw new GqlParseError(`unexpected character ${JSON.stringify(ch)}`);
  }
  tokens.push({ type: 'eof', value: '' });
  return tokens;
}

class GqlParser {
  private pos = 0;
  private readonly tokens: GqlToken[];

  constructor(tokens: GqlToken[]) {
    this.tokens = tokens;
  }

  private peek(): GqlToken {
    return this.tokens[this.pos]!;
  }

  private next(): GqlToken {
    const tok = this.tokens[this.pos]!;
    this.pos += 1;
    return tok;
  }

  private expectPunct(value: string): void {
    const tok = this.next();
    if (tok.type !== 'punct' || tok.value !== value) throw new GqlParseError(`expected ${value}, got ${tok.value}`);
  }

  private expectName(value?: string): string {
    const tok = this.next();
    if (tok.type !== 'name') throw new GqlParseError(`expected name, got ${tok.value}`);
    if (value !== undefined && tok.value !== value) throw new GqlParseError(`expected ${value}, got ${tok.value}`);
    return tok.value;
  }

  private skipDirectives(): void {
    while (this.peek().type === 'punct' && this.peek().value === '@') {
      this.next();
      this.expectName();
      if (this.peek().type === 'punct' && this.peek().value === '(') this.parseArguments();
    }
  }

  parseDocument(): GqlDefinition[] {
    const defs: GqlDefinition[] = [];
    while (this.peek().type !== 'eof') {
      defs.push(this.parseDefinition());
    }
    return defs;
  }

  private parseDefinition(): GqlDefinition {
    const tok = this.peek();
    if (tok.type === 'punct' && tok.value === '{') {
      return { kind: 'operation', operation: 'query', name: null, varDefs: [], selections: this.parseSelectionSet() };
    }
    if (tok.type === 'name' && (tok.value === 'query' || tok.value === 'mutation' || tok.value === 'subscription')) {
      const operation = this.next().value as 'query' | 'mutation' | 'subscription';
      let name: string | null = null;
      if (this.peek().type === 'name') name = this.next().value;
      let varDefs: GqlVarDef[] = [];
      if (this.peek().type === 'punct' && this.peek().value === '(') varDefs = this.parseVariableDefinitions();
      this.skipDirectives();
      const selections = this.parseSelectionSet();
      return { kind: 'operation', operation: operation === 'subscription' ? 'query' : operation, name, varDefs, selections };
    }
    if (tok.type === 'name' && tok.value === 'fragment') {
      this.next();
      const name = this.expectName();
      this.expectName('on');
      const typeCondition = this.expectName();
      this.skipDirectives();
      return { kind: 'fragment', name, typeCondition, selections: this.parseSelectionSet() };
    }
    throw new GqlParseError(`unexpected token ${tok.value}`);
  }

  private parseVariableDefinitions(): GqlVarDef[] {
    this.expectPunct('(');
    const defs: GqlVarDef[] = [];
    while (!(this.peek().type === 'punct' && this.peek().value === ')')) {
      this.expectPunct('$');
      const name = this.expectName();
      this.expectPunct(':');
      // Read the type: Name, brackets and '!' tokens.
      let typeName = '';
      for (;;) {
        const tok = this.next();
        if (tok.type === 'name') typeName += tok.value;
        else if (tok.type === 'punct' && (tok.value === '[' || tok.value === ']' || tok.value === '!')) typeName += tok.value;
        else throw new GqlParseError(`unexpected token in variable type ${tok.value}`);
        if (this.peek().type === 'name' || (this.peek().type === 'punct' && (this.peek().value === '[' || this.peek().value === ']' || this.peek().value === '!'))) continue;
        break;
      }
      let defaultValue: GqlValueNode | null = null;
      if (this.peek().type === 'punct' && this.peek().value === '=') {
        this.next();
        defaultValue = this.parseValue();
      }
      this.skipDirectives();
      defs.push({ name, typeName, defaultValue });
    }
    this.expectPunct(')');
    return defs;
  }

  private parseSelectionSet(): GqlSelection[] {
    this.expectPunct('{');
    const selections: GqlSelection[] = [];
    while (!(this.peek().type === 'punct' && this.peek().value === '}')) {
      selections.push(this.parseSelection());
    }
    this.expectPunct('}');
    return selections;
  }

  private parseSelection(): GqlSelection {
    if (this.peek().type === 'spread') {
      this.next();
      if (this.peek().type === 'name' && this.peek().value === 'on') {
        this.next();
        const typeCondition = this.expectName();
        this.skipDirectives();
        return { kind: 'inline', typeCondition, selections: this.parseSelectionSet() };
      }
      if (this.peek().type === 'name') {
        const name = this.next().value;
        this.skipDirectives();
        return { kind: 'spread', name };
      }
      this.skipDirectives();
      return { kind: 'inline', typeCondition: null, selections: this.parseSelectionSet() };
    }
    const first = this.expectName();
    let alias: string | null = null;
    let name = first;
    if (this.peek().type === 'punct' && this.peek().value === ':') {
      this.next();
      alias = first;
      name = this.expectName();
    }
    let args: Record<string, GqlValueNode> = {};
    if (this.peek().type === 'punct' && this.peek().value === '(') args = this.parseArguments();
    this.skipDirectives();
    let selections: GqlSelection[] | null = null;
    if (this.peek().type === 'punct' && this.peek().value === '{') selections = this.parseSelectionSet();
    return { kind: 'field', alias, name, args, selections };
  }

  private parseArguments(): Record<string, GqlValueNode> {
    this.expectPunct('(');
    const args: Record<string, GqlValueNode> = {};
    while (!(this.peek().type === 'punct' && this.peek().value === ')')) {
      const name = this.expectName();
      this.expectPunct(':');
      args[name] = this.parseValue();
    }
    this.expectPunct(')');
    return args;
  }

  private parseValue(): GqlValueNode {
    const tok = this.next();
    if (tok.type === 'punct' && tok.value === '$') return { kind: 'variable', name: this.expectName() };
    if (tok.type === 'string') return { kind: 'string', value: tok.value };
    if (tok.type === 'int') return { kind: 'int', value: Number.parseInt(tok.value, 10) };
    if (tok.type === 'float') return { kind: 'float', value: Number.parseFloat(tok.value) };
    if (tok.type === 'punct' && tok.value === '[') {
      const items: GqlValueNode[] = [];
      while (!(this.peek().type === 'punct' && this.peek().value === ']')) items.push(this.parseValue());
      this.expectPunct(']');
      return { kind: 'list', items };
    }
    if (tok.type === 'punct' && tok.value === '{') {
      const fields: Record<string, GqlValueNode> = {};
      while (!(this.peek().type === 'punct' && this.peek().value === '}')) {
        const name = this.expectName();
        this.expectPunct(':');
        fields[name] = this.parseValue();
      }
      this.expectPunct('}');
      return { kind: 'object', fields };
    }
    if (tok.type === 'name') {
      if (tok.value === 'true') return { kind: 'boolean', value: true };
      if (tok.value === 'false') return { kind: 'boolean', value: false };
      if (tok.value === 'null') return { kind: 'null' };
      return { kind: 'enum', value: tok.value };
    }
    throw new GqlParseError(`unexpected value token ${tok.value}`);
  }
}

function parseGqlDocument(source: string): GqlDefinition[] {
  return new GqlParser(tokenizeGql(source)).parseDocument();
}

// ---------------------------------------------------------------------------
// GraphQL executor
// ---------------------------------------------------------------------------

class GqlError extends Error {}

type GqlObj = { __typename: string; [key: string]: unknown };

function isGqlObj(value: unknown): value is GqlObj {
  return isRecord(value) && typeof value.__typename === 'string';
}

function resolveGqlValue(node: GqlValueNode, vars: Record<string, unknown>): unknown {
  switch (node.kind) {
    case 'variable':
      return vars[node.name] ?? null;
    case 'string':
    case 'int':
    case 'float':
    case 'boolean':
      return node.value;
    case 'null':
      return null;
    case 'enum':
      return node.value;
    case 'list':
      return node.items.map((i) => resolveGqlValue(i, vars));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(node.fields)) out[k] = resolveGqlValue(v, vars);
      return out;
    }
  }
}

function resolveGqlArgs(field: GqlField, vars: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(field.args)) out[k] = resolveGqlValue(v, vars);
  return out;
}

function makeCursor(n: number): string {
  return Buffer.from(`cursor:${n}`, 'utf8').toString('base64');
}

function parseCursor(cursor: string): number | null {
  try {
    const decoded = Buffer.from(cursor, 'base64').toString('utf8');
    const match = /^cursor:(\d+)$/.exec(decoded);
    if (!match) return null;
    return Number.parseInt(match[1]!, 10);
  } catch {
    return null;
  }
}

interface PageSlice<T> {
  nodes: T[];
  hasNextPage: boolean;
  hasPreviousPage: boolean;
  startCursor: string | null;
  endCursor: string | null;
}

function pageByCursor<T>(items: readonly T[], key: (item: T) => number, args: Record<string, unknown>): PageSlice<T> {
  let start = 0;
  const after = args.after;
  if (typeof after === 'string') {
    const n = parseCursor(after);
    if (n !== null) {
      const idx = items.findIndex((it) => key(it) === n);
      if (idx >= 0) start = idx + 1;
    }
  }
  const first = typeof args.first === 'number' ? Math.max(0, args.first) : items.length;
  const nodes = items.slice(start, start + first);
  const hasNextPage = start + nodes.length < items.length;
  return {
    nodes,
    hasNextPage,
    hasPreviousPage: start > 0,
    startCursor: nodes.length > 0 ? makeCursor(key(nodes[0]!)) : null,
    endCursor: nodes.length > 0 ? makeCursor(key(nodes[nodes.length - 1]!)) : null,
  };
}

function pageInfoObj(slice: PageSlice<unknown>): GqlObj {
  return { __typename: 'PageInfo', hasNextPage: slice.hasNextPage, hasPreviousPage: slice.hasPreviousPage, startCursor: slice.startCursor, endCursor: slice.endCursor };
}

function repoWrapper(repo: Repo): GqlObj {
  return { __typename: 'Repository', repo };
}

function issueWrapper(repo: Repo, issue: Issue): GqlObj {
  return { __typename: 'Issue', repo, issue };
}

function pullWrapper(repo: Repo, pr: Pull): GqlObj {
  return { __typename: 'PullRequest', repo, pr };
}

function userWrapper(): GqlObj {
  return { __typename: 'User' };
}

function commentWrapper(repo: Repo, issue: Issue, comment: Comment): GqlObj {
  return { __typename: 'IssueComment', repo, issue, comment };
}

function orderDirection(args: Record<string, unknown>): 'asc' | 'desc' {
  const orderBy = isRecord(args.orderBy) ? args.orderBy : null;
  return orderBy?.direction === 'DESC' ? 'desc' : 'asc';
}

function issueConnection(repo: Repo, args: Record<string, unknown>): GqlObj {
  let list = [...repo.issues];
  const states = args.states;
  if (Array.isArray(states) && states.length > 0) {
    const wanted = new Set(states.map((s) => String(s).toLowerCase()));
    list = list.filter((i) => wanted.has(i.state));
  }
  const direction = orderDirection(args);
  list.sort((a, b) => (direction === 'desc' ? b.seq - a.seq : a.seq - b.seq));
  const slice = pageByCursor(list, (i) => i.number, args);
  return {
    __typename: 'IssueConnection',
    totalCount: list.length,
    nodes: slice.nodes.map((i) => issueWrapper(repo, i)),
    edges: slice.nodes.map((i) => ({ __typename: 'IssueEdge', node: issueWrapper(repo, i), cursor: makeCursor(i.number) })),
    pageInfo: pageInfoObj(slice),
  };
}

function pullStateGql(pr: Pull): 'OPEN' | 'CLOSED' | 'MERGED' {
  if (pr.merged) return 'MERGED';
  return pr.state === 'closed' ? 'CLOSED' : 'OPEN';
}

function pullRequestConnection(repo: Repo, args: Record<string, unknown>): GqlObj {
  let list = [...repo.pulls];
  const states = args.states;
  if (Array.isArray(states) && states.length > 0) {
    const wanted = new Set(states.map((s) => String(s).toUpperCase()));
    list = list.filter((p) => wanted.has(pullStateGql(p)));
  }
  // Default PR order is newest first.
  const hasOrderBy = isRecord(args.orderBy);
  const direction = hasOrderBy ? orderDirection(args) : 'desc';
  list.sort((a, b) => (direction === 'desc' ? b.seq - a.seq : a.seq - b.seq));
  const slice = pageByCursor(list, (p) => p.number, args);
  return {
    __typename: 'PullRequestConnection',
    totalCount: list.length,
    nodes: slice.nodes.map((p) => pullWrapper(repo, p)),
    edges: slice.nodes.map((p) => ({ __typename: 'PullRequestEdge', node: pullWrapper(repo, p), cursor: makeCursor(p.number) })),
    pageInfo: pageInfoObj(slice),
  };
}

function commentConnection(repo: Repo, issue: Issue, args: Record<string, unknown>): GqlObj {
  const slice = pageByCursor(issue.comments, (c) => c.id, args);
  return {
    __typename: 'IssueCommentConnection',
    totalCount: issue.comments.length,
    nodes: slice.nodes.map((c) => commentWrapper(repo, issue, c)),
    edges: slice.nodes.map((c) => ({ __typename: 'IssueCommentEdge', node: commentWrapper(repo, issue, c), cursor: makeCursor(c.id) })),
    pageInfo: pageInfoObj(slice),
  };
}

function fileConnection(repo: Repo, pr: Pull, args: Record<string, unknown>): GqlObj {
  const files = pullRequestFiles(repo, pr);
  // Page by index, since FileDiff carries no stable id of its own.
  const indexed = files.map((f, i) => ({ f, i }));
  const sliced = pageByCursor(indexed, (x) => x.i, args);
  return {
    __typename: 'FileConnection',
    totalCount: files.length,
    nodes: sliced.nodes.map((x) => ({ __typename: 'File', file: x.f })),
    edges: sliced.nodes.map((x) => ({ __typename: 'FileEdge', node: { __typename: 'File', file: x.f }, cursor: makeCursor(x.i) })),
    pageInfo: pageInfoObj(sliced),
  };
}

// Introspection tables.
const GQL_TYPE_INFO: Record<string, { kind: string; fields: string[]; enumValues: string[] | null }> = {
  Query: { kind: 'OBJECT', fields: ['viewer', 'repository', 'node', '__typename', '__type', '__schema'], enumValues: null },
  Mutation: { kind: 'OBJECT', fields: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment'], enumValues: null },
  Repository: { kind: 'OBJECT', fields: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequest', 'pullRequests', 'url', 'description', 'createdAt', 'updatedAt', 'isPrivate'], enumValues: null },
  Issue: { kind: 'OBJECT', fields: ['id', 'databaseId', 'number', 'title', 'body', 'state', 'createdAt', 'updatedAt', 'closedAt', 'author', 'comments', 'url', 'repository'], enumValues: null },
  PullRequest: { kind: 'OBJECT', fields: ['id', 'databaseId', 'number', 'title', 'body', 'state', 'headRefName', 'baseRefName', 'mergeable', 'merged', 'mergedAt', 'files', 'author', 'url', 'repository', 'createdAt', 'updatedAt', 'closedAt', 'mergeCommit'], enumValues: null },
  User: { kind: 'OBJECT', fields: ['id', 'databaseId', 'login', 'name', 'avatarUrl'], enumValues: null },
  IssueComment: { kind: 'OBJECT', fields: ['id', 'databaseId', 'body', 'author', 'createdAt', 'updatedAt', 'url'], enumValues: null },
  Ref: { kind: 'OBJECT', fields: ['name', 'target', 'prefix'], enumValues: null },
  Commit: { kind: 'OBJECT', fields: ['oid', 'message', 'abbreviatedOid'], enumValues: null },
  IssueConnection: { kind: 'OBJECT', fields: ['nodes', 'edges', 'totalCount', 'pageInfo'], enumValues: null },
  PullRequestConnection: { kind: 'OBJECT', fields: ['nodes', 'edges', 'totalCount', 'pageInfo'], enumValues: null },
  IssueCommentConnection: { kind: 'OBJECT', fields: ['nodes', 'edges', 'totalCount', 'pageInfo'], enumValues: null },
  FileConnection: { kind: 'OBJECT', fields: ['nodes', 'edges', 'totalCount', 'pageInfo'], enumValues: null },
  IssueEdge: { kind: 'OBJECT', fields: ['node', 'cursor'], enumValues: null },
  PullRequestEdge: { kind: 'OBJECT', fields: ['node', 'cursor'], enumValues: null },
  IssueCommentEdge: { kind: 'OBJECT', fields: ['node', 'cursor'], enumValues: null },
  FileEdge: { kind: 'OBJECT', fields: ['node', 'cursor'], enumValues: null },
  PageInfo: { kind: 'OBJECT', fields: ['hasNextPage', 'hasPreviousPage', 'startCursor', 'endCursor'], enumValues: null },
  CreateIssuePayload: { kind: 'OBJECT', fields: ['issue', 'clientMutationId'], enumValues: null },
  CloseIssuePayload: { kind: 'OBJECT', fields: ['issue', 'clientMutationId'], enumValues: null },
  CreatePullRequestPayload: { kind: 'OBJECT', fields: ['pullRequest', 'clientMutationId'], enumValues: null },
  MergePullRequestPayload: { kind: 'OBJECT', fields: ['pullRequest', 'clientMutationId'], enumValues: null },
  AddCommentPayload: { kind: 'OBJECT', fields: ['commentEdge', 'subject', 'clientMutationId'], enumValues: null },
  SearchType: { kind: 'ENUM', fields: [], enumValues: ['ISSUE', 'PULL_REQUEST', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT', 'MILESTONE', 'ORGANIZATION', 'PROJECT', 'TEAM', 'LABEL'] },
  IssueState: { kind: 'ENUM', fields: [], enumValues: ['OPEN', 'CLOSED'] },
  PullRequestState: { kind: 'ENUM', fields: [], enumValues: ['OPEN', 'CLOSED', 'MERGED'] },
  MergeableState: { kind: 'ENUM', fields: [], enumValues: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'] },
  MergeMethod: { kind: 'ENUM', fields: [], enumValues: ['MERGE', 'SQUASH', 'REBASE'] },
  RepositoryPermission: { kind: 'ENUM', fields: [], enumValues: ['ADMIN', 'MAINTAIN', 'WRITE', 'TRIAGE', 'READ'] },
  IssueOrderField: { kind: 'ENUM', fields: [], enumValues: ['CREATED_AT', 'UPDATED_AT', 'COMMENTS'] },
  OrderDirection: { kind: 'ENUM', fields: [], enumValues: ['ASC', 'DESC'] },
};

function typeWrapper(name: string): GqlObj | null {
  const info = GQL_TYPE_INFO[name];
  if (!info) return null;
  return {
    __typename: '__Type',
    name,
    kind: info.kind,
    description: '',
    fields: info.kind === 'OBJECT' ? info.fields.map((f) => ({ __typename: '__Field', name: f, description: '', args: [], type: { __typename: '__Type', name: 'String', kind: 'SCALAR' } })) : null,
    enumValues: info.enumValues ? info.enumValues.map((v) => ({ __typename: '__EnumValue', name: v, description: '' })) : null,
  };
}

function findRepoById(id: number): Repo | undefined {
  for (const repo of repos.values()) if (repo.id === id) return repo;
  return undefined;
}

function resolveGqlField(parent: GqlObj, parentType: string, field: GqlField, vars: Record<string, unknown>): unknown {
  const args = resolveGqlArgs(field, vars);
  const name = field.name;

  if (parentType === 'Query') {
    if (name === 'viewer') return userWrapper();
    if (name === 'repository') {
      const owner = args.owner;
      const repoName = args.name;
      if (typeof owner !== 'string' || typeof repoName !== 'string') return null;
      if (owner !== VIEWER_LOGIN) return null;
      const repo = findRepo(owner, repoName);
      return repo ? repoWrapper(repo) : null;
    }
    if (name === 'node') {
      if (typeof args.id !== 'string') return null;
      const decoded = decodeGlobalId(args.id);
      if (!decoded) return null;
      if (decoded.kind === 'Repository' && decoded.parts.length === 1) {
        const repo = findRepoById(Number.parseInt(decoded.parts[0]!, 10));
        return repo ? repoWrapper(repo) : null;
      }
      if (decoded.kind === 'Issue' && decoded.parts.length === 2) {
        const repo = findRepoById(Number.parseInt(decoded.parts[0]!, 10));
        const issue = repo ? findIssue(repo, Number.parseInt(decoded.parts[1]!, 10)) : undefined;
        return repo && issue ? issueWrapper(repo, issue) : null;
      }
      if (decoded.kind === 'PullRequest' && decoded.parts.length === 2) {
        const repo = findRepoById(Number.parseInt(decoded.parts[0]!, 10));
        const pr = repo ? findPull(repo, Number.parseInt(decoded.parts[1]!, 10)) : undefined;
        return repo && pr ? pullWrapper(repo, pr) : null;
      }
      if (decoded.kind === 'IssueComment' && decoded.parts.length === 3) {
        const repo = findRepoById(Number.parseInt(decoded.parts[0]!, 10));
        const issue = repo ? findIssue(repo, Number.parseInt(decoded.parts[1]!, 10)) : undefined;
        const comment = issue?.comments.find((c) => c.id === Number.parseInt(decoded.parts[2]!, 10));
        return repo && issue && comment ? commentWrapper(repo, issue, comment) : null;
      }
      return null;
    }
    if (name === '__type') {
      if (typeof args.name !== 'string') return null;
      return typeWrapper(args.name);
    }
    if (name === '__schema') return { __typename: '__Schema' };
    throw new GqlError(`Cannot query field "${name}" on type "Query".`);
  }

  if (parentType === 'Mutation') {
    if (name === 'createIssue') {
      const input = isRecord(args.input) ? args.input : {};
      const repoId = decodeGlobalId(typeof input.repositoryId === 'string' ? input.repositoryId : '');
      const repo = repoId?.kind === 'Repository' ? findRepoById(Number.parseInt(repoId.parts[0]!, 10)) : undefined;
      if (!repo) throw new GqlError('Repository not found');
      if (typeof input.title !== 'string' || input.title === '') throw new GqlError('title is required');
      const issue = createIssueInRepo(repo, input.title, typeof input.body === 'string' ? input.body : '', []);
      return { __typename: 'CreateIssuePayload', issue: issueWrapper(repo, issue), clientMutationId: typeof input.clientMutationId === 'string' ? input.clientMutationId : null };
    }
    if (name === 'closeIssue') {
      const input = isRecord(args.input) ? args.input : {};
      const issueId = decodeGlobalId(typeof input.issueId === 'string' ? input.issueId : '');
      const repo = issueId?.kind === 'Issue' ? findRepoById(Number.parseInt(issueId.parts[0]!, 10)) : undefined;
      const issue = repo ? findIssue(repo, Number.parseInt(issueId?.parts[1] ?? '', 10)) : undefined;
      if (!repo || !issue) throw new GqlError('Issue not found');
      issue.state = 'closed';
      return { __typename: 'CloseIssuePayload', issue: issueWrapper(repo, issue), clientMutationId: typeof input.clientMutationId === 'string' ? input.clientMutationId : null };
    }
    if (name === 'createPullRequest') {
      const input = isRecord(args.input) ? args.input : {};
      const repoId = decodeGlobalId(typeof input.repositoryId === 'string' ? input.repositoryId : '');
      const repo = repoId?.kind === 'Repository' ? findRepoById(Number.parseInt(repoId.parts[0]!, 10)) : undefined;
      if (!repo) throw new GqlError('Repository not found');
      const head = typeof input.headRefName === 'string' ? input.headRefName : '';
      const base = typeof input.baseRefName === 'string' ? input.baseRefName : '';
      if (!repo.refs.has(`refs/heads/${head}`)) throw new GqlError(`Head branch '${head}' does not exist`);
      if (!repo.refs.has(`refs/heads/${base}`)) throw new GqlError(`Base branch '${base}' does not exist`);
      const existing = repo.pulls.find((p) => p.state === 'open' && p.headRef === head && p.baseRef === base);
      if (existing) throw new GqlError('A pull request already exists for this head and base');
      const pr = createPullInRepo(repo, typeof input.title === 'string' ? input.title : '', typeof input.body === 'string' ? input.body : '', head, base);
      return { __typename: 'CreatePullRequestPayload', pullRequest: pullWrapper(repo, pr), clientMutationId: typeof input.clientMutationId === 'string' ? input.clientMutationId : null };
    }
    if (name === 'mergePullRequest') {
      const input = isRecord(args.input) ? args.input : {};
      const prId = decodeGlobalId(typeof input.pullRequestId === 'string' ? input.pullRequestId : '');
      const repo = prId?.kind === 'PullRequest' ? findRepoById(Number.parseInt(prId.parts[0]!, 10)) : undefined;
      const pr = repo ? findPull(repo, Number.parseInt(prId?.parts[1] ?? '', 10)) : undefined;
      if (!repo || !pr) throw new GqlError('Pull request not found');
      const result = mergePullInRepo(repo, pr);
      if ('error' in result) throw new GqlError(result.error === 'conflict' ? 'Merge conflict' : 'Pull request is already closed');
      return { __typename: 'MergePullRequestPayload', pullRequest: pullWrapper(repo, pr), clientMutationId: typeof input.clientMutationId === 'string' ? input.clientMutationId : null };
    }
    if (name === 'addComment') {
      const input = isRecord(args.input) ? args.input : {};
      const subjectId = decodeGlobalId(typeof input.subjectId === 'string' ? input.subjectId : '');
      const repo = subjectId?.kind === 'Issue' ? findRepoById(Number.parseInt(subjectId.parts[0]!, 10)) : undefined;
      const issue = repo ? findIssue(repo, Number.parseInt(subjectId?.parts[1] ?? '', 10)) : undefined;
      if (!repo || !issue) throw new GqlError('Issue not found');
      if (typeof input.body !== 'string') throw new GqlError('body is required');
      const comment: Comment = { id: commentIdSeq, body: input.body };
      commentIdSeq += 1;
      issue.comments.push(comment);
      const node = commentWrapper(repo, issue, comment);
      return { __typename: 'AddCommentPayload', commentEdge: { __typename: 'IssueCommentEdge', node, cursor: makeCursor(comment.id) }, subject: issueWrapper(repo, issue), clientMutationId: typeof input.clientMutationId === 'string' ? input.clientMutationId : null };
    }
    throw new GqlError(`Cannot query field "${name}" on type "Mutation".`);
  }

  if (parentType === 'Repository') {
    const repo = parent.repo as Repo;
    if (name === 'id') return globalId('Repository', repo.id);
    if (name === 'databaseId') return repo.id;
    if (name === 'name') return repo.name;
    if (name === 'nameWithOwner') return `${repo.owner}/${repo.name}`;
    if (name === 'owner') return userWrapper();
    if (name === 'defaultBranchRef') {
      const tip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
      return tip ? { __typename: 'Ref', name: repo.defaultBranch, oid: tip, repo } : null;
    }
    if (name === 'viewerPermission') return 'ADMIN';
    if (name === 'hasIssuesEnabled') return true;
    if (name === 'isPrivate') return repo.isPrivate;
    if (name === 'description') return repo.description;
    if (name === 'url') return `https://example.invalid/${repo.owner}/${repo.name}`;
    if (name === 'createdAt' || name === 'updatedAt') return FIXED_ISO;
    if (name === 'issue') {
      const issue = typeof args.number === 'number' ? findIssue(repo, args.number) : undefined;
      return issue ? issueWrapper(repo, issue) : null;
    }
    if (name === 'issues') return issueConnection(repo, args);
    if (name === 'pullRequest') {
      const pr = typeof args.number === 'number' ? findPull(repo, args.number) : undefined;
      return pr ? pullWrapper(repo, pr) : null;
    }
    if (name === 'pullRequests') return pullRequestConnection(repo, args);
    throw new GqlError(`Cannot query field "${name}" on type "Repository".`);
  }

  if (parentType === 'Issue') {
    const repo = parent.repo as Repo;
    const issue = parent.issue as Issue;
    if (name === 'id') return globalId('Issue', repo.id, issue.number);
    if (name === 'databaseId') return issue.id;
    if (name === 'number') return issue.number;
    if (name === 'title') return issue.title;
    if (name === 'body') return issue.body;
    if (name === 'state') return issue.state === 'open' ? 'OPEN' : 'CLOSED';
    if (name === 'createdAt' || name === 'updatedAt') return FIXED_ISO;
    if (name === 'closedAt') return issue.state === 'closed' ? FIXED_ISO : null;
    if (name === 'author') return userWrapper();
    if (name === 'url') return `https://example.invalid/${repo.owner}/${repo.name}/issues/${issue.number}`;
    if (name === 'repository') return repoWrapper(repo);
    if (name === 'comments') return commentConnection(repo, issue, args);
    throw new GqlError(`Cannot query field "${name}" on type "Issue".`);
  }

  if (parentType === 'PullRequest') {
    const repo = parent.repo as Repo;
    const pr = parent.pr as Pull;
    if (name === 'id') return globalId('PullRequest', repo.id, pr.number);
    if (name === 'databaseId') return pr.id;
    if (name === 'number') return pr.number;
    if (name === 'title') return pr.title;
    if (name === 'body') return pr.body;
    if (name === 'state') return pullStateGql(pr);
    if (name === 'headRefName') return pr.headRef;
    if (name === 'baseRefName') return pr.baseRef;
    if (name === 'mergeable') {
      const headOid = repo.refs.get(`refs/heads/${pr.headRef}`);
      const baseOid = repo.refs.get(`refs/heads/${pr.baseRef}`);
      if (!headOid || !baseOid) return 'UNKNOWN';
      return pullRequestMergeable(repo, pr) ? 'MERGEABLE' : 'CONFLICTING';
    }
    if (name === 'merged') return pr.merged;
    if (name === 'mergedAt') return pr.mergedAt;
    if (name === 'mergeCommit') return pr.mergeSha ? { __typename: 'Commit', oid: pr.mergeSha } : null;
    if (name === 'createdAt' || name === 'updatedAt') return FIXED_ISO;
    if (name === 'closedAt') return pr.state === 'closed' ? FIXED_ISO : null;
    if (name === 'author') return userWrapper();
    if (name === 'url') return `https://example.invalid/${repo.owner}/${repo.name}/pull/${pr.number}`;
    if (name === 'repository') return repoWrapper(repo);
    if (name === 'files') return fileConnection(repo, pr, args);
    throw new GqlError(`Cannot query field "${name}" on type "PullRequest".`);
  }

  if (parentType === 'User') {
    if (name === 'id') return globalId('User', VIEWER_ID);
    if (name === 'databaseId') return VIEWER_ID;
    if (name === 'login') return VIEWER_LOGIN;
    if (name === 'name') return VIEWER_NAME;
    if (name === 'avatarUrl') return '';
    throw new GqlError(`Cannot query field "${name}" on type "User".`);
  }

  if (parentType === 'IssueComment') {
    const repo = parent.repo as Repo;
    const issue = parent.issue as Issue;
    const comment = parent.comment as Comment;
    if (name === 'id') return globalId('IssueComment', repo.id, issue.number, comment.id);
    if (name === 'databaseId') return comment.id;
    if (name === 'body') return comment.body;
    if (name === 'author') return userWrapper();
    if (name === 'createdAt' || name === 'updatedAt') return FIXED_ISO;
    if (name === 'url') return `https://example.invalid/${repo.owner}/${repo.name}/issues/${issue.number}#issuecomment-${comment.id}`;
    throw new GqlError(`Cannot query field "${name}" on type "IssueComment".`);
  }

  if (parentType === 'Ref') {
    if (name === 'name') return parent.name as string;
    if (name === 'prefix') return 'refs/heads/';
    if (name === 'target') return { __typename: 'Commit', oid: parent.oid as string };
    throw new GqlError(`Cannot query field "${name}" on type "Ref".`);
  }

  if (parentType === 'Commit') {
    const oid = parent.oid as string;
    if (name === 'oid') return oid;
    if (name === 'abbreviatedOid') return oid.slice(0, 7);
    if (name === 'message') {
      for (const repo of repos.values()) {
        const obj = repo.objects.get(oid);
        if (obj?.type === 'commit') return parseCommit(obj.data).message;
      }
      return '';
    }
    throw new GqlError(`Cannot query field "${name}" on type "Commit".`);
  }

  if (parentType === 'IssueConnection' || parentType === 'PullRequestConnection' || parentType === 'IssueCommentConnection' || parentType === 'FileConnection') {
    if (name === 'nodes') return parent.nodes as unknown[];
    if (name === 'edges') return parent.edges as unknown[];
    if (name === 'totalCount') return parent.totalCount as number;
    if (name === 'pageInfo') return parent.pageInfo as GqlObj;
    throw new GqlError(`Cannot query field "${name}" on type "${parentType}".`);
  }

  if (parentType === 'IssueEdge' || parentType === 'PullRequestEdge' || parentType === 'IssueCommentEdge' || parentType === 'FileEdge') {
    if (name === 'node') return parent.node as GqlObj;
    if (name === 'cursor') return parent.cursor as string;
    throw new GqlError(`Cannot query field "${name}" on type "${parentType}".`);
  }

  if (parentType === 'PageInfo') {
    if (name === 'hasNextPage') return parent.hasNextPage as boolean;
    if (name === 'hasPreviousPage') return parent.hasPreviousPage as boolean;
    if (name === 'startCursor') return parent.startCursor as string | null;
    if (name === 'endCursor') return parent.endCursor as string | null;
    throw new GqlError(`Cannot query field "${name}" on type "PageInfo".`);
  }

  if (parentType === 'File') {
    const file = parent.file as FileDiff;
    if (name === 'path') return file.filename;
    if (name === 'additions') return file.additions;
    if (name === 'deletions') return file.deletions;
    if (name === 'changeType') return file.status === 'added' ? 'ADDED' : file.status === 'removed' ? 'REMOVED' : 'MODIFIED';
    throw new GqlError(`Cannot query field "${name}" on type "File".`);
  }

  if (parentType === 'CreateIssuePayload' || parentType === 'CloseIssuePayload') {
    if (name === 'issue') return parent.issue as GqlObj;
    if (name === 'clientMutationId') return parent.clientMutationId as string | null;
    throw new GqlError(`Cannot query field "${name}" on type "${parentType}".`);
  }

  if (parentType === 'CreatePullRequestPayload' || parentType === 'MergePullRequestPayload') {
    if (name === 'pullRequest') return parent.pullRequest as GqlObj;
    if (name === 'clientMutationId') return parent.clientMutationId as string | null;
    throw new GqlError(`Cannot query field "${name}" on type "${parentType}".`);
  }

  if (parentType === 'AddCommentPayload') {
    if (name === 'commentEdge') return parent.commentEdge as GqlObj;
    if (name === 'subject') return parent.subject as GqlObj;
    if (name === 'clientMutationId') return parent.clientMutationId as string | null;
    throw new GqlError(`Cannot query field "${name}" on type "AddCommentPayload".`);
  }

  if (parentType === '__Type') {
    if (name === 'name') return parent.name as string;
    if (name === 'kind') return parent.kind as string;
    if (name === 'description') return parent.description as string;
    if (name === 'fields') return parent.fields as unknown[] | null;
    if (name === 'enumValues') return parent.enumValues as unknown[] | null;
    throw new GqlError(`Cannot query field "${name}" on type "__Type".`);
  }

  if (parentType === '__Field') {
    if (name === 'name') return parent.name as string;
    if (name === 'description') return parent.description as string;
    if (name === 'args') return parent.args as unknown[];
    if (name === 'type') return parent.type as GqlObj;
    throw new GqlError(`Cannot query field "${name}" on type "__Field".`);
  }

  if (parentType === '__EnumValue') {
    if (name === 'name') return parent.name as string;
    if (name === 'description') return parent.description as string;
    throw new GqlError(`Cannot query field "${name}" on type "__EnumValue".`);
  }

  if (parentType === '__Schema') {
    if (name === 'queryType') return typeWrapper('Query');
    if (name === 'mutationType') return typeWrapper('Mutation');
    if (name === 'types') return Object.keys(GQL_TYPE_INFO).map((t) => typeWrapper(t));
    if (name === 'description') return null;
    throw new GqlError(`Cannot query field "${name}" on type "__Schema".`);
  }

  throw new GqlError(`Cannot query field "${name}" on type "${parentType}".`);
}

function executeSelections(parent: GqlObj, parentType: string, selections: GqlSelection[], vars: Record<string, unknown>, fragments: Map<string, GqlFragmentDef>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const sel of selections) {
    if (sel.kind === 'field') {
      const key = sel.alias ?? sel.name;
      let value: unknown;
      if (sel.name === '__typename') value = parentType;
      else value = resolveGqlField(parent, parentType, sel, vars);
      if (sel.selections !== null && sel.selections.length > 0) {
        if (value === null || value === undefined) {
          out[key] = null;
          continue;
        }
        if (isGqlObj(value)) {
          out[key] = executeSelections(value, value.__typename, sel.selections, vars, fragments);
        } else if (Array.isArray(value)) {
          out[key] = value.map((item) => (isGqlObj(item) ? executeSelections(item, item.__typename, sel.selections, vars, fragments) : item));
        } else {
          out[key] = value;
        }
      } else {
        out[key] = value;
      }
    } else if (sel.kind === 'inline') {
      if (sel.typeCondition === null || sel.typeCondition === parentType) {
        Object.assign(out, executeSelections(parent, parentType, sel.selections, vars, fragments));
      }
    } else {
      const def = fragments.get(sel.name);
      if (def && def.typeCondition === parentType) {
        Object.assign(out, executeSelections(parent, parentType, def.selections, vars, fragments));
      }
    }
  }
  return out;
}

function executeGqlOperation(op: GqlOperation, vars: Record<string, unknown>, fragments: Map<string, GqlFragmentDef>): Record<string, unknown> {
  const allVars: Record<string, unknown> = { ...vars };
  for (const def of op.varDefs) {
    if (!(def.name in allVars) && def.defaultValue) allVars[def.name] = resolveGqlValue(def.defaultValue, allVars);
  }
  const rootType = op.operation === 'mutation' ? 'Mutation' : 'Query';
  const root: GqlObj = { __typename: rootType };
  return executeSelections(root, rootType, op.selections, allVars, fragments);
}

function executeGqlRequest(body: unknown): Record<string, unknown> {
  if (!isRecord(body) || typeof body.query !== 'string') {
    return { data: null, errors: [{ message: 'query is required' }] };
  }
  const variables = isRecord(body.variables) ? (body.variables as Record<string, unknown>) : {};
  let defs: GqlDefinition[];
  try {
    defs = parseGqlDocument(body.query);
  } catch (e) {
    return { data: null, errors: [{ message: e instanceof Error ? e.message : 'parse error' }] };
  }
  const fragments = new Map<string, GqlFragmentDef>();
  const operations: GqlOperation[] = [];
  for (const def of defs) {
    if (def.kind === 'fragment') fragments.set(def.name, def);
    else operations.push(def);
  }
  if (operations.length === 0) return { data: null, errors: [{ message: 'no operation found' }] };
  let op = operations[0]!;
  if (typeof body.operationName === 'string') {
    const named = operations.find((o) => o.name === body.operationName);
    if (named) op = named;
  }
  try {
    const data = executeGqlOperation(op, variables, fragments);
    return { data };
  } catch (e) {
    return { data: null, errors: [{ message: e instanceof Error ? e.message : 'execution error' }] };
  }
}

async function handleGraphQL(req: IncomingMessage, res: ServerResponse, bodyText: string): Promise<boolean> {
  if (!authed(req)) {
    sendJson(res, 401, { message: 'Requires authentication' });
    return true;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(bodyText);
  } catch {
    sendJson(res, 200, { data: null, errors: [{ message: 'request body is not valid JSON' }] });
    return true;
  }
  if (Array.isArray(parsed)) {
    sendJson(res, 200, parsed.map((el) => executeGqlRequest(el)));
    return true;
  }
  sendJson(res, 200, executeGqlRequest(parsed));
  return true;
}

// ---------------------------------------------------------------------------
// MCP (JSON-RPC 2.0 Streamable HTTP, revision 2026-07-28)
// ---------------------------------------------------------------------------

const MCP_REVISION = '2026-07-28';
const MCP_KNOWN_REVISIONS = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];

const MCP_TOOLS: Array<Record<string, unknown>> = [
  {
    name: 'create_repo',
    description: 'Create a new repository for the viewer.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Repository name' },
        description: { type: 'string', description: 'Repository description' },
        private: { type: 'boolean', description: 'Whether the repository is private' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Issue title' },
        body: { type: 'string', description: 'Issue body' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        state: { type: 'string', description: 'Issue state filter', enum: ['open', 'closed', 'all'] },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Pull request title' },
        head: { type: 'string', description: 'Head branch name' },
        base: { type: 'string', description: 'Base branch name' },
        body: { type: 'string', description: 'Pull request body' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request with the squash method.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        pull_number: { type: 'number', description: 'Pull request number' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

function mcpResult(id: unknown, result: unknown): Record<string, unknown> {
  return { jsonrpc: '2.0', id: id ?? null, result };
}

function mcpError(id: unknown, code: number, message: string, data?: unknown): Record<string, unknown> {
  const error: Record<string, unknown> = { code, message };
  if (data !== undefined) error.data = data;
  return { jsonrpc: '2.0', id: id ?? null, error };
}

function mcpToolResult(payload: unknown): Record<string, unknown> {
  return { content: [{ type: 'text', text: JSON.stringify(payload) }], structuredContent: payload };
}

function mcpToolError(message: string): Record<string, unknown> {
  return { content: [{ type: 'text', text: message }], isError: true };
}

/** Run one tool. Returns a tool result object, or { error: string } for a tool failure. */
function runMcpTool(name: string, args: Record<string, unknown>): Record<string, unknown> | { error: string } {
  const missing = (field: string): { error: string } => ({ error: `Missing required argument: ${field}` });
  const needRepo = (argsObj: Record<string, unknown>): Repo | { error: string } => {
    const owner = argsObj.owner;
    const repoName = argsObj.repo;
    if (typeof owner !== 'string' || typeof repoName !== 'string') return { error: 'owner and repo are required' };
    const repo = requireRepo(owner, repoName);
    if (!repo) return { error: `Repository ${owner}/${repoName} not found` };
    return repo;
  };

  if (name === 'create_repo') {
    if (typeof args.name !== 'string' || args.name === '') return missing('name');
    if (findRepo(VIEWER_LOGIN, args.name)) return { error: `name already exists on this account` };
    const repo = createRepoRecord(args.name, args.private === true, typeof args.description === 'string' ? args.description : '');
    return mcpToolResult(repoJson(repo));
  }
  if (name === 'get_repo') {
    const repo = needRepo(args);
    if ('error' in repo) return repo;
    return mcpToolResult(repoJson(repo));
  }
  if (name === 'create_issue') {
    const repo = needRepo(args);
    if ('error' in repo) return repo;
    if (typeof args.title !== 'string' || args.title === '') return missing('title');
    const issue = createIssueInRepo(repo, args.title, typeof args.body === 'string' ? args.body : '', []);
    return mcpToolResult(issueJson(repo, issue));
  }
  if (name === 'list_issues') {
    const repo = needRepo(args);
    if ('error' in repo) return repo;
    const state = typeof args.state === 'string' ? args.state : 'open';
    const list = repo.issues.filter((i) => (state === 'all' ? true : i.state === state));
    return mcpToolResult(list.map((i) => issueJson(repo, i)));
  }
  if (name === 'create_pull_request') {
    const repo = needRepo(args);
    if ('error' in repo) return repo;
    if (typeof args.title !== 'string' || args.title === '') return missing('title');
    const head = typeof args.head === 'string' ? args.head : '';
    const base = typeof args.base === 'string' ? args.base : '';
    if (!head) return missing('head');
    if (!base) return missing('base');
    if (!repo.refs.has(`refs/heads/${head}`)) return { error: `Head branch '${head}' does not exist` };
    if (!repo.refs.has(`refs/heads/${base}`)) return { error: `Base branch '${base}' does not exist` };
    if (head === base) return { error: 'head and base must be different branches' };
    const existing = repo.pulls.find((p) => p.state === 'open' && p.headRef === head && p.baseRef === base);
    if (existing) return { error: 'A pull request already exists for this head and base' };
    const pr = createPullInRepo(repo, args.title, typeof args.body === 'string' ? args.body : '', head, base);
    return mcpToolResult(pullJson(repo, pr));
  }
  if (name === 'merge_pull_request') {
    const repo = needRepo(args);
    if ('error' in repo) return repo;
    const raw = args.pull_number;
    const number = typeof raw === 'number' ? raw : typeof raw === 'string' ? Number.parseInt(raw, 10) : Number.NaN;
    if (!Number.isInteger(number)) return missing('pull_number');
    const pr = findPull(repo, number);
    if (!pr) return { error: `Pull request #${number} not found` };
    const result = mergePullInRepo(repo, pr);
    if ('error' in result) {
      return { error: result.error === 'conflict' ? 'Merge conflict: the pull request cannot be merged cleanly' : 'Pull request is already closed' };
    }
    return mcpToolResult({ ...pullJson(repo, pr), sha: result.sha, merged: true });
  }
  return { error: `Unknown tool: ${name}` };
}

function handleMcpRequest(req: IncomingMessage, body: unknown): { status: number; payload: unknown } | { status: 202 } {
  if (!isRecord(body)) return { status: 200, payload: mcpError(null, -32600, 'Invalid Request') };
  const id: unknown = 'id' in body ? body.id : null;
  const method = body.method;
  const isNotification = id === undefined || id === null;

  // Notifications get a 202 with an empty body.
  if (isNotification) return { status: 202 };

  if (typeof method !== 'string') return { status: 200, payload: mcpError(id, -32600, 'Invalid Request') };

  // Transport header checks (2026-07-28): Mcp-Method must mirror the body method.
  const methodHeader = req.headers['mcp-method'];
  if (typeof methodHeader === 'string' && methodHeader !== '' && methodHeader !== method) {
    return { status: 200, payload: mcpError(id, -32020, 'Mcp-Method header does not match the request method') };
  }
  const params = isRecord(body.params) ? body.params : {};
  const nameHeader = req.headers['mcp-name'];
  if (method === 'tools/call' && typeof nameHeader === 'string' && nameHeader !== '' && typeof params.name === 'string' && nameHeader !== params.name) {
    return { status: 200, payload: mcpError(id, -32020, 'Mcp-Name header does not match the tool name') };
  }

  // Protocol version declared in _meta must be one the server speaks.
  const meta = isRecord(params._meta) ? params._meta : null;
  const declared = meta !== null ? (meta['io.modelcontextprotocol/protocolVersion'] ?? meta.protocolVersion) : undefined;
  if (typeof declared === 'string' && !MCP_KNOWN_REVISIONS.includes(declared)) {
    return { status: 200, payload: mcpError(id, -32022, `Unsupported protocol version: ${declared}`, { supported: [MCP_REVISION] }) };
  }

  if (method === 'server/discover') {
    return {
      status: 200,
      payload: mcpResult(id, {
        supportedVersions: [MCP_REVISION],
        capabilities: { tools: {} },
        serverInfo: { name: 'git-forge', version: '1.0.0' },
        _meta: { 'io.modelcontextprotocol/serverInfo': { name: 'git-forge', version: '1.0.0' } },
      }),
    };
  }

  if (method === 'initialize') {
    const offered = typeof params.protocolVersion === 'string' ? params.protocolVersion : '';
    if (!MCP_KNOWN_REVISIONS.includes(offered)) {
      return { status: 200, payload: mcpError(id, -32602, `Unsupported protocol version: ${offered}`) };
    }
    return {
      status: 200,
      payload: mcpResult(id, {
        protocolVersion: offered,
        capabilities: { tools: {} },
        serverInfo: { name: 'git-forge', version: '1.0.0' },
      }),
    };
  }

  if (method === 'ping') {
    return { status: 200, payload: mcpResult(id, {}) };
  }

  if (method === 'tools/list') {
    return { status: 200, payload: mcpResult(id, { tools: MCP_TOOLS }) };
  }

  if (method === 'tools/call') {
    if (typeof params.name !== 'string' || params.name === '') {
      return { status: 200, payload: mcpError(id, -32602, 'Tool name is required') };
    }
    const known = MCP_TOOLS.some((t) => t.name === params.name);
    if (!known) {
      return { status: 200, payload: mcpError(id, -32602, `Unknown tool: ${params.name}`) };
    }
    const args = isRecord(params.arguments) ? (params.arguments as Record<string, unknown>) : {};
    const result = runMcpTool(params.name, args);
    if ('error' in result) {
      return { status: 200, payload: mcpResult(id, mcpToolError(result.error)) };
    }
    return { status: 200, payload: mcpResult(id, result) };
  }

  return { status: 200, payload: mcpError(id, -32601, `Method not found: ${method}`) };
}

async function handleMcp(req: IncomingMessage, res: ServerResponse, bodyText: string): Promise<boolean> {
  if (!authed(req)) {
    sendJson(res, 401, mcpError(null, -32001, 'Requires authentication'));
    return true;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(bodyText);
  } catch {
    sendJson(res, 400, mcpError(null, -32700, 'Parse error'));
    return true;
  }
  if (Array.isArray(parsed)) {
    const answers: unknown[] = [];
    for (const item of parsed) {
      const outcome = handleMcpRequest(req, item);
      if (outcome.status === 202) continue;
      answers.push(outcome.payload);
    }
    sendJson(res, 200, answers);
    return true;
  }
  const outcome = handleMcpRequest(req, parsed);
  if (outcome.status === 202) {
    res.writeHead(202, { 'x-github-request-id': requestId() });
    res.end();
    return true;
  }
  sendJson(res, 200, outcome.payload);
  return true;
}

// ---------------------------------------------------------------------------
// Git smart HTTP (upload-pack v2/v0, receive-pack v0)
// ---------------------------------------------------------------------------

/** Walk pkt-lines until the first flush; return the text lines and the bytes after the flush. */
function readPktLinesUntilFlush(buf: Buffer): { lines: string[]; rest: Buffer } {
  const lines: string[] = [];
  let offset = 0;
  while (offset < buf.length) {
    if (offset + 4 > buf.length) throw new Error('truncated pkt-line');
    const head = buf.subarray(offset, offset + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(head)) throw new Error(`invalid pkt-line length ${JSON.stringify(head)}`);
    const length = Number.parseInt(head, 16);
    if (length === 0) {
      return { lines, rest: buf.subarray(offset + 4) };
    }
    if (length === 1) {
      offset += 4;
      continue;
    }
    if (length < 4 || length > PKT_LINE_MAX) throw new Error(`invalid pkt-line length ${length}`);
    if (offset + length > buf.length) throw new Error('truncated pkt-line');
    lines.push(buf.subarray(offset + 4, offset + length).toString('utf8'));
    offset += length;
  }
  throw new Error('pkt-line stream ended without a flush');
}

/** Split decoded packets into sections (flush/delim are separators). */
function splitPktSections(packets: Array<{ kind: string; payload?: Buffer }>): string[][] {
  const sections: string[][] = [];
  let current: string[] = [];
  for (const packet of packets) {
    if (packet.kind === 'delim' || packet.kind === 'flush') {
      sections.push(current);
      current = [];
    } else if (packet.kind === 'data' && packet.payload) {
      current.push(packet.payload.toString('utf8'));
    }
  }
  if (current.length > 0) sections.push(current);
  return sections;
}

/** Split a buffer into sideband pkt-lines for one band (max 65520 bytes each). */
function sidebandPackets(band: number, data: Buffer): Buffer[] {
  const out: Buffer[] = [];
  const maxPayload = PKT_LINE_MAX - 4 - 1;
  let offset = 0;
  if (data.length === 0) return out;
  while (offset < data.length) {
    const slice = data.subarray(offset, offset + maxPayload);
    const len = 4 + 1 + slice.length;
    out.push(Buffer.concat([Buffer.from(len.toString(16).padStart(4, '0'), 'ascii'), Buffer.from([band]), slice]));
    offset += slice.length;
  }
  return out;
}

function peelTagTarget(repo: Repo, oid: string): string {
  let current = oid;
  for (let i = 0; i < 10; i += 1) {
    const obj = repo.objects.get(current);
    if (!obj || obj.type !== 'tag') return current;
    current = parseTag(obj.data).object;
  }
  return current;
}

const UPLOAD_PACK_V0_CAPS = 'symref=HEAD:refs/heads/main agent=git-forge/1.0 side-band-64k thin-pack ofs-delta shallow multi_ack_detailed';
const RECEIVE_PACK_V0_CAPS = 'symref=HEAD:refs/heads/main agent=git-forge/1.0 report-status side-band-64k delete-refs ofs-delta';

function advertisementV0(repo: Repo, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  const caps = service === 'git-upload-pack' ? UPLOAD_PACK_V0_CAPS : RECEIVE_PACK_V0_CAPS;
  const parts: Buffer[] = [encodePktLine(`# service=${service}\n`), pktFlush()];
  const tip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
  const refs = [...repo.refs.keys()].sort();
  if (refs.length === 0 || !tip) {
    parts.push(encodePktLine(`${ZERO_OID} capabilities^{}\u0000${caps}\n`), pktFlush());
    return Buffer.concat(parts);
  }
  const firstLine = `${tip} HEAD\u0000${caps}\n`;
  parts.push(encodePktLine(firstLine));
  for (const ref of refs) {
    const oid = repo.refs.get(ref)!;
    parts.push(encodePktLine(`${oid} ${ref}\n`));
    const obj = repo.objects.get(oid);
    if (obj?.type === 'tag') {
      parts.push(encodePktLine(`${peelTagTarget(repo, oid)} ${ref}^{}\n`));
    }
  }
  parts.push(pktFlush());
  return Buffer.concat(parts);
}

function advertisementV2(repo: Repo): Buffer {
  void repo;
  return Buffer.concat([
    encodePktLine('# service=git-upload-pack\n'),
    pktFlush(),
    encodePktLine('version 2\n'),
    encodePktLine('agent=git-forge/1.0\n'),
    encodePktLine('ls-refs=unborn\n'),
    encodePktLine('fetch=shallow filter\n'),
    encodePktLine('object-format=sha1\n'),
    pktFlush(),
  ]);
}

interface LsRefsArgs {
  peel: boolean;
  symrefs: boolean;
  unborn: boolean;
  prefixes: string[];
}

function lsRefsLines(repo: Repo, args: LsRefsArgs): string[] {
  const lines: string[] = [];
  const keep = (name: string): boolean => args.prefixes.length === 0 || args.prefixes.some((p) => name.startsWith(p));
  const tip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
  if (keep('HEAD')) {
    if (tip) {
      lines.push(`${tip} HEAD${args.symrefs ? ` symref-target:refs/heads/${repo.defaultBranch}` : ''}\n`);
    } else if (args.unborn) {
      lines.push(`unborn HEAD${args.symrefs ? ` symref-target:refs/heads/${repo.defaultBranch}` : ''}\n`);
    }
  }
  for (const ref of [...repo.refs.keys()].sort()) {
    if (!keep(ref)) continue;
    const oid = repo.refs.get(ref)!;
    let line = `${oid} ${ref}`;
    if (args.peel) {
      const obj = repo.objects.get(oid);
      if (obj?.type === 'tag') line += ` peeled:${peelTagTarget(repo, oid)}`;
    }
    lines.push(`${line}\n`);
  }
  return lines;
}

interface FetchArgs {
  wants: string[];
  haves: string[];
  shallow: string[];
  depth: number | undefined;
}

function parseFetchArgs(lines: readonly string[]): FetchArgs {
  const args: FetchArgs = { wants: [], haves: [], shallow: [], depth: undefined };
  for (const raw of lines) {
    const line = raw.replace(/\n$/, '');
    if (line.startsWith('want ')) {
      const oid = line.slice(5).split(' ')[0]!;
      if (isObjectId(oid)) args.wants.push(oid);
    } else if (line.startsWith('have ')) {
      const oid = line.slice(5).trim();
      if (isObjectId(oid)) args.haves.push(oid);
    } else if (line.startsWith('shallow ')) {
      const oid = line.slice(8).trim();
      if (isObjectId(oid)) args.shallow.push(oid);
    } else if (line.startsWith('deepen ')) {
      const n = Number.parseInt(line.slice(7).trim(), 10);
      if (Number.isInteger(n) && n > 0) args.depth = n;
    }
  }
  return args;
}

function buildFetchV2Response(repo: Repo, args: FetchArgs): Buffer {
  const plan = computeFetch(repo, args.wants, args.haves, args.shallow, args.depth);
  const parts: Buffer[] = [encodePktLines(['acknowledgments\n', 'NAK\n', 'delim'])];
  if (plan.shallow.length > 0 || plan.unshallow.length > 0) {
    const lines: Array<string | 'delim'> = ['shallow-info\n'];
    for (const oid of plan.shallow) lines.push(`shallow ${oid}\n`);
    for (const oid of plan.unshallow) lines.push(`unshallow ${oid}\n`);
    lines.push('delim');
    parts.push(encodePktLines(lines));
  }
  parts.push(encodePktLine('packfile\n'));
  if (plan.objects.size > 0) {
    const pack = writePack(plan.objects.values());
    for (const packet of sidebandPackets(1, pack)) parts.push(packet);
  }
  parts.push(pktFlush());
  return Buffer.concat(parts);
}

function buildFetchV0Response(repo: Repo, args: FetchArgs): Buffer {
  const plan = computeFetch(repo, args.wants, args.haves, args.shallow, args.depth);
  const parts: Buffer[] = [encodePktLine('NAK\n')];
  for (const oid of plan.shallow) parts.push(encodePktLine(`shallow ${oid}\n`));
  for (const oid of plan.unshallow) parts.push(encodePktLine(`unshallow ${oid}\n`));
  if (plan.objects.size > 0) {
    const pack = writePack(plan.objects.values());
    for (const packet of sidebandPackets(1, pack)) parts.push(packet);
  }
  parts.push(pktFlush());
  return Buffer.concat(parts);
}

interface PushCommand {
  oldOid: string;
  newOid: string;
  ref: string;
}

/** Evaluate one receive-pack command against the store. Returns null when accepted. */
function evaluatePushCommand(repo: Repo, command: PushCommand): string | null {
  const current = repo.refs.get(command.ref);
  if (command.newOid === ZERO_OID) {
    // Delete.
    if (current === undefined) return 'remote ref does not exist';
    if (command.oldOid !== ZERO_OID && command.oldOid !== current) return 'non-fast-forward';
    return null;
  }
  if (command.oldOid === ZERO_OID) {
    // Create.
    if (current !== undefined) return 'already exists';
  } else {
    if (current === undefined) return 'non-fast-forward';
    if (current !== command.oldOid) return 'non-fast-forward';
    if (command.newOid === command.oldOid) return null;
    if (!repo.objects.has(command.newOid)) return 'non-fast-forward';
    if (!isAncestor(repo, command.oldOid, command.newOid)) return 'non-fast-forward';
  }
  // Tag refs may only be created or re-pointed to the same object.
  if (command.ref.startsWith('refs/tags/') && command.oldOid !== ZERO_OID && current !== undefined && command.newOid !== current) {
    return 'non-fast-forward';
  }
  if (!repo.objects.has(command.newOid)) return 'non-fast-forward';
  return null;
}

function handleReceivePack(repo: Repo, body: Buffer): Buffer {
  const { lines, rest } = readPktLinesUntilFlush(body);
  const commands: PushCommand[] = [];
  for (const raw of lines) {
    const line = raw.replace(/\n$/, '');
    if (!line) continue;
    const withoutCaps = line.split('\u0000')[0]!;
    const parts = withoutCaps.split(' ');
    if (parts.length < 3) continue;
    const [oldOid, newOid, ref] = parts as [string, string, string];
    if (!isObjectId(oldOid) || !isObjectId(newOid) || !ref.startsWith('refs/')) continue;
    commands.push({ oldOid, newOid, ref });
  }

  // Unpack first: a refused push still unpacks its objects.
  let unpackOk = true;
  let unpackDetail = 'ok';
  if (rest.length > 0) {
    try {
      const objects = readPack(rest, (oid) => repo.objects.get(oid));
      for (const [oid, obj] of objects) {
        if (!repo.objects.has(oid)) {
          repo.objects.set(oid, obj);
          if (obj.type === 'commit') {
            commitSeqCounter += 1;
            repo.commitSeq.set(oid, commitSeqCounter);
          }
        }
      }
    } catch (err) {
      unpackOk = false;
      unpackDetail = err instanceof Error ? err.message : 'unpack error';
    }
  }

  const reportLines: string[] = [`unpack ${unpackOk ? 'ok' : unpackDetail}\n`];
  if (unpackOk) {
    for (const command of commands) {
      const reason = evaluatePushCommand(repo, command);
      if (reason === null) {
        if (command.newOid === ZERO_OID) repo.refs.delete(command.ref);
        else repo.refs.set(command.ref, command.newOid);
        reportLines.push(`ok ${command.ref}\n`);
      } else {
        reportLines.push(`ng ${command.ref} ${reason}\n`);
      }
    }
  } else {
    for (const command of commands) {
      reportLines.push(`ng ${command.ref} unpack failed\n`);
    }
  }

  // Report as pkt-lines inside sideband band 1, then a flush.
  const inner = encodePktLines(reportLines);
  const parts: Buffer[] = [...sidebandPackets(1, inner), pktFlush()];
  return Buffer.concat(parts);
}

async function handleGit(
  req: IncomingMessage,
  res: ServerResponse,
  method: string,
  segs: string[],
  url: URL,
  body: Buffer,
): Promise<boolean> {
  // /{owner}/{repo}.git/info/refs | /{owner}/{repo}.git/{git-upload-pack,git-receive-pack}
  if (segs.length < 2 || !segs[1]!.endsWith('.git')) return false;
  const owner = segs[0]!;
  const repoName = segs[1]!.slice(0, -'.git'.length);
  const rest = segs.slice(2);
  if (rest.length === 0) return false;
  const isInfoRefs = rest.length === 2 && rest[0] === 'info' && rest[1] === 'refs';
  const isUploadPack = rest.length === 1 && rest[0] === 'git-upload-pack';
  const isReceivePack = rest.length === 1 && rest[0] === 'git-receive-pack';
  if (!isInfoRefs && !isUploadPack && !isReceivePack) return false;

  const repo = owner === VIEWER_LOGIN ? findRepo(owner, repoName) : undefined;
  if (!repo) {
    sendJson(res, 404, { message: `Repository ${owner}/${repoName} not found` });
    return true;
  }

  try {
    if (method === 'GET' && isInfoRefs) {
      const service = url.searchParams.get('service');
      if (service === 'git-upload-pack') {
        const wantsV2 = req.headers['git-protocol'] === 'version=2';
        const ad = wantsV2 ? advertisementV2(repo) : advertisementV0(repo, 'git-upload-pack');
        sendRaw(res, 200, ad, 'application/x-git-upload-pack-advertisement');
        return true;
      }
      if (service === 'git-receive-pack') {
        sendRaw(res, 200, advertisementV0(repo, 'git-receive-pack'), 'application/x-git-receive-pack-advertisement');
        return true;
      }
      sendJson(res, 400, { message: 'service parameter is required' });
      return true;
    }

    if (method === 'POST' && isUploadPack) {
      const wantsV2 = req.headers['git-protocol'] === 'version=2';
      const packets = decodePktLines(body);
      const sections = splitPktSections(packets);
      if (wantsV2) {
        const commandLine = (sections[0]?.[0] ?? '').replace(/\n$/, '');
        if (commandLine === 'command=ls-refs') {
          const args: LsRefsArgs = { peel: false, symrefs: false, unborn: false, prefixes: [] };
          for (const raw of sections[1] ?? []) {
            const line = raw.replace(/\n$/, '');
            if (line === 'peel') args.peel = true;
            else if (line === 'symrefs') args.symrefs = true;
            else if (line === 'unborn') args.unborn = true;
            else if (line.startsWith('ref-prefix ')) args.prefixes.push(line.slice('ref-prefix '.length));
          }
          const lines = lsRefsLines(repo, args);
          sendRaw(res, 200, Buffer.concat([encodePktLines(lines), pktFlush()]), 'application/x-git-upload-pack-result');
          return true;
        }
        if (commandLine === 'command=fetch') {
          const args = parseFetchArgs(sections[1] ?? []);
          sendRaw(res, 200, buildFetchV2Response(repo, args), 'application/x-git-upload-pack-result');
          return true;
        }
        sendJson(res, 400, { message: `unknown upload-pack command: ${commandLine}` });
        return true;
      }
      // v0 fetch: wants section, then haves section.
      const args = parseFetchArgs([...(sections[0] ?? []), ...(sections[1] ?? [])]);
      sendRaw(res, 200, buildFetchV0Response(repo, args), 'application/x-git-upload-pack-result');
      return true;
    }

    if (method === 'POST' && isReceivePack) {
      sendRaw(res, 200, handleReceivePack(repo, body), 'application/x-git-receive-pack-result');
      return true;
    }

    sendJson(res, 404, { message: 'Not Found' });
    return true;
  } catch (err) {
    sendJson(res, 400, { message: err instanceof Error ? err.message : 'malformed request' });
    return true;
  }
}

// ---------------------------------------------------------------------------
// Router + server
// ---------------------------------------------------------------------------

export function createApp(): Server {
  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    try {
      const method = req.method ?? 'GET';
      const isHead = method === 'HEAD';
      const effectiveMethod = isHead ? 'GET' : method;
      const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
      const pathname = url.pathname;
      const segs = splitPath(pathname);

      let body = Buffer.alloc(0);
      if (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE') {
        try {
          body = await readBody(req);
        } catch {
          sendJson(res, 400, { message: 'request body is too large or unreadable' });
          return;
        }
      }

      if (pathname === '/healthz' && effectiveMethod === 'GET') {
        sendJson(res, 200, { ok: true }, {}, isHead);
        return;
      }

      if (pathname === '/api/graphql' && method === 'POST') {
        await handleGraphQL(req, res, body.toString('utf8'));
        return;
      }

      if (pathname === '/mcp' && method === 'POST') {
        await handleMcp(req, res, body.toString('utf8'));
        return;
      }
      if (pathname === '/mcp' && method === 'DELETE') {
        res.writeHead(200, { 'x-github-request-id': requestId() });
        res.end();
        return;
      }

      if (segs[0] === 'api' && segs[1] === 'v3') {
        const handled = await handleRest(req, res, effectiveMethod, segs, url, body.toString('utf8'), isHead);
        if (handled) return;
      }

      if (await handleGit(req, res, effectiveMethod, segs, url, body)) return;

      sendJson(res, 404, { message: 'Not Found' });
    } catch (err) {
      if (!res.headersSent) {
        sendJson(res, 500, { message: err instanceof Error ? err.message : 'internal server error' });
      } else {
        res.end();
      }
    }
  });
  return server;
}
