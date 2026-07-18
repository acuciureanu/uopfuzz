import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { logger } from '../utils/logger.js';

/**
 * Tiny on-disk key/value cache with a TTL, shared across processes.
 *
 * Why this exists: the OSV and cdnjs clients only cached in-process (a module
 * Map). But the default single-target run and every mass/version target run in
 * a FRESH forked subprocess, so that Map is empty each time — meaning one live
 * OSV network POST (behind a 500 ms rate-gate, and leaking the analyzed
 * package@version to a third party) and every cdnjs metadata fetch re-ran for
 * every target, every version, every invocation. Persisting responses to disk
 * lets a repeat scan of the same package/library read locally instead.
 *
 * Design constraints:
 * - NEVER throws. This is an optional acceleration layer; any I/O problem
 *   degrades to a cache miss (callers then hit the network as before).
 * - One file per key (hashed), written atomically (temp + rename) so concurrent
 *   mass scans can't observe a half-written entry.
 * - Only callers persist what is safe to reuse (e.g. successful lookups); this
 *   module does not decide policy, it just stores what it is given.
 *
 * Location: $UOPFUZZ_CACHE_DIR, else ~/.cache/uopfuzz, else os.tmpdir(). It is
 * outside the repo, so it never pollutes the working tree.
 */

const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000; // 24h

function cacheRoot() {
  if (process.env.UOPFUZZ_CACHE_DIR) return process.env.UOPFUZZ_CACHE_DIR;
  try {
    const home = os.homedir();
    if (home) return path.join(home, '.cache', 'uopfuzz');
  } catch { /* fall through */ }
  return path.join(os.tmpdir(), 'uopfuzz-cache');
}

function entryPath(namespace, key) {
  const hash = crypto.createHash('sha256').update(key).digest('hex');
  return path.join(cacheRoot(), namespace, `${hash}.json`);
}

/**
 * Return the cached value for (namespace, key) if present and younger than
 * ttlMs; otherwise null. Never throws.
 */
export function readCache(namespace, key, ttlMs = DEFAULT_TTL_MS) {
  try {
    const file = entryPath(namespace, key);
    const raw = fs.readFileSync(file, 'utf8');
    const entry = JSON.parse(raw);
    if (!entry || typeof entry.ts !== 'number') return null;
    if (Date.now() - entry.ts > ttlMs) return null; // stale
    return entry.value;
  } catch {
    return null; // miss / unreadable / malformed
  }
}

/**
 * Persist `value` for (namespace, key). Never throws; a write failure is logged
 * at debug and swallowed (the caller already has the value in hand).
 */
export function writeCache(namespace, key, value) {
  try {
    const file = entryPath(namespace, key);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify({ ts: Date.now(), value }), 'utf8');
    fs.renameSync(tmp, file); // atomic on the same filesystem
  } catch (err) {
    logger.debug(`http-cache write failed for ${namespace}/${key}: ${err.message}`);
  }
}

/**
 * Remove every entry in a namespace. Used by the source clients' test-only
 * cache-reset helpers so the on-disk tier can't make tests order-dependent or
 * non-hermetic. Never throws.
 */
export function clearNamespace(namespace) {
  try {
    fs.rmSync(path.join(cacheRoot(), namespace), { recursive: true, force: true });
  } catch { /* nothing to clear */ }
}
