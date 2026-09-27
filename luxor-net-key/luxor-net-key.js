/*!
 * Luxor Net Key - a secret picture is your encryption key.
 * ------------------------------------------------------------------
 * Invented by Christian Rivera (DJ BrightFuture).
 * Open source under the MIT License. (c) 2026 Christian Rivera.
 *
 * THE IDEA (in Christian's words): a hard password can be a picture you
 * captured that only you know is "the one" - and it's even stronger if that
 * picture is a random pencil drawing or piece of art you made, because a
 * unique hand-drawn scribble is a high-entropy secret that exists nowhere
 * else in the world.
 *
 * HOW IT WORKS (zero-knowledge):
 *   1. A random 256-bit Data Encryption Key (DEK) encrypts your data (AES-256-GCM).
 *   2. The DEK is stored only as a WRAP: the DEK encrypted under a key derived
 *      from the EXACT bytes of your secret picture (PBKDF2, 250k iterations).
 *   3. To unlock, you provide the same picture -> same derived key -> the DEK
 *      unwraps -> your data decrypts. A wrong picture fails the AES-GCM auth tag.
 *   4. The picture itself is NEVER stored or transmitted. Only the wrap
 *      (salt + iv + ciphertext) is. So a server or thief who holds the wrap
 *      learns nothing about your picture and cannot open your data.
 *
 * HONEST SECURITY NOTES (read these - a security tool that hides its limits is lying):
 *   - EXACT BYTES. The key is the exact file, not "what the picture looks like."
 *     Photograph your random drawing ONCE; that file is your key. A fresh
 *     re-photograph produces different bytes and will NOT unlock. Keep the one
 *     file safe and secret, like a physical key. (This is a deliberate, tested
 *     property, not a bug - it is what makes a stolen re-photograph useless.)
 *   - Anyone who obtains a COPY of your secret picture file can unlock your data,
 *     exactly like anyone holding a physical key. Its power is that it is secret
 *     and unique. A public photo (your face, a famous image) is a weak choice;
 *     a private, one-of-a-kind drawing is a strong one.
 *   - Entropy = the picture. A real photo or hand drawing carries far more
 *     entropy than a typed password. A tiny, plain, or widely-shared image is weak.
 *   - This is client-side crypto. Run it from a page you trust; the whole point
 *     is that the key material never leaves the device.
 *   - Some phones/share sheets RE-ENCODE an image (HEIC -> JPEG) on select/share, changing
 *     its bytes, so the "same photo" from a camera roll can fail to unlock. Use a saved key
 *     file you control, select that same file, and keep a stable backed-up copy.
 *
 * No dependencies. Uses the Web Crypto API (browsers, Node 18+, Cloudflare Workers, Deno).
 */

const _crypto = (typeof globalThis !== "undefined" && globalThis.crypto) ? globalThis.crypto : null;
if (!_crypto || !_crypto.subtle) throw new Error("Luxor Net Key requires the Web Crypto API (crypto.subtle).");
const _subtle = _crypto.subtle;
const _enc = new TextEncoder();
const _dec = new TextDecoder();

const PBKDF2_ITERATIONS = 250000;   // deliberate cost: makes each offline guess of a weak picture expensive
const CRED_PREFIX = "luxornet-pic-v1:";

// ---- small base64 helpers (work in browser and Node) ----
function _b64encode(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  if (typeof btoa === "function") return btoa(bin);
  return Buffer.from(bin, "binary").toString("base64");
}
function _b64decode(str) {
  let bin;
  if (typeof atob === "function") bin = atob(str);
  else bin = Buffer.from(str, "base64").toString("binary");
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function _sha256hex(bytes) {
  const d = new Uint8Array(await _subtle.digest("SHA-256", bytes));
  let hex = "";
  for (let i = 0; i < d.length; i++) hex += d[i].toString(16).padStart(2, "0");
  return hex;
}

/**
 * Turn a secret picture's exact bytes into a stable, opaque credential string.
 * @param {ArrayBuffer|Uint8Array} fileBytes - the raw bytes of the image file.
 * @returns {Promise<string>} e.g. "luxornet-pic-v1:<64 hex>"
 */
export async function pictureCredential(fileBytes) {
  const bytes = fileBytes instanceof Uint8Array ? fileBytes : new Uint8Array(fileBytes);
  return CRED_PREFIX + (await _sha256hex(bytes));
}

async function _deriveKey(cred, salt) {
  const base = await _subtle.importKey("raw", _enc.encode(cred), "PBKDF2", false, ["deriveKey"]);
  return _subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Wrap (encrypt) a raw secret (e.g. a 32-byte DEK) under a picture credential.
 * @returns {Promise<{v:number,salt:string,iv:string,ct:string}>} a JSON-safe wrap.
 */
export async function wrapSecret(secretBytes, cred) {
  const salt = _crypto.getRandomValues(new Uint8Array(16));
  const iv = _crypto.getRandomValues(new Uint8Array(12));
  const key = await _deriveKey(cred, salt);
  const raw = secretBytes instanceof Uint8Array ? secretBytes : new Uint8Array(secretBytes);
  const ct = await _subtle.encrypt({ name: "AES-GCM", iv }, key, raw);
  return { v: 1, salt: _b64encode(salt), iv: _b64encode(iv), ct: _b64encode(ct) };
}

/**
 * Unwrap (decrypt) a secret using a picture credential. Throws if the credential is wrong.
 * @returns {Promise<Uint8Array>} the original secret bytes.
 */
export async function unwrapSecret(wrap, cred) {
  const key = await _deriveKey(cred, _b64decode(wrap.salt));
  const pt = await _subtle.decrypt({ name: "AES-GCM", iv: _b64decode(wrap.iv) }, key, _b64decode(wrap.ct));
  return new Uint8Array(pt);
}

/**
 * HIGH-LEVEL: lock arbitrary data with a secret picture.
 * Generates a fresh DEK, encrypts the data with it, and wraps the DEK under the picture.
 * The returned envelope is safe to store anywhere (it is pure ciphertext).
 *
 * @param {string|Uint8Array|ArrayBuffer} data - what to protect.
 * @param {ArrayBuffer|Uint8Array} pictureBytes - the exact bytes of the secret picture.
 * @returns {Promise<object>} envelope { fmt, wraps:{pic}, blob }.
 */
export async function lockWithPicture(data, pictureBytes) {
  const cred = await pictureCredential(pictureBytes);
  const dekRaw = _crypto.getRandomValues(new Uint8Array(32));
  const dekKey = await _subtle.importKey("raw", dekRaw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  const iv = _crypto.getRandomValues(new Uint8Array(12));
  const bytes = typeof data === "string" ? _enc.encode(data) : (data instanceof Uint8Array ? data : new Uint8Array(data));
  const ct = await _subtle.encrypt({ name: "AES-GCM", iv }, dekKey, bytes);
  const blob = new Uint8Array(12 + ct.byteLength);
  blob.set(iv, 0);
  blob.set(new Uint8Array(ct), 12);
  return { fmt: "luxornet-1", wraps: { pic: await wrapSecret(dekRaw, cred) }, blob: _b64encode(blob) };
}

/**
 * HIGH-LEVEL: unlock an envelope with the same secret picture. Throws if the picture is wrong.
 * @param {object} envelope - from lockWithPicture (or with an added wrap).
 * @param {ArrayBuffer|Uint8Array} pictureBytes - the exact bytes of the secret picture.
 * @param {boolean} [asText=true] - return a string (true) or Uint8Array (false).
 * @returns {Promise<string|Uint8Array>} the original data.
 */
export async function unlockWithPicture(envelope, pictureBytes, asText = true) {
  const cred = await pictureCredential(pictureBytes);
  const dekRaw = await unwrapSecret(envelope.wraps.pic, cred);
  const dekKey = await _subtle.importKey("raw", dekRaw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  const e = _b64decode(envelope.blob);
  const pt = await _subtle.decrypt({ name: "AES-GCM", iv: e.slice(0, 12) }, dekKey, e.slice(12));
  return asText ? _dec.decode(pt) : new Uint8Array(pt);
}

/**
 * Add a SECOND way to open an existing envelope without re-encrypting the data.
 * Unwrap the DEK with a picture you already have, then wrap it under a NEW credential
 * (another picture, or a passphrase string). Enables multi-key access & recovery.
 * @param {object} envelope - existing envelope (mutated: a new wrap is added).
 * @param {ArrayBuffer|Uint8Array} existingPictureBytes - a picture that currently opens it.
 * @param {string} wrapName - key under envelope.wraps to store the new wrap (e.g. "pic2","pass").
 * @param {ArrayBuffer|Uint8Array|string} newCredential - bytes of another picture, or a passphrase string.
 * @returns {Promise<object>} the same envelope with the new wrap added.
 */
export async function addKey(envelope, existingPictureBytes, wrapName, newCredential) {
  const dekRaw = await unwrapSecret(envelope.wraps.pic, await pictureCredential(existingPictureBytes));
  const cred = typeof newCredential === "string" ? newCredential : await pictureCredential(newCredential);
  envelope.wraps[wrapName] = await wrapSecret(dekRaw, cred);
  return envelope;
}

/**
 * Browser convenience: read a File/Blob (from an <input type="file"> or camera capture) into bytes.
 * @param {File|Blob} file
 * @returns {Promise<Uint8Array>}
 */
export function readFileBytes(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(new Uint8Array(r.result));
    r.onerror = () => reject(r.error || new Error("could not read file"));
    r.readAsArrayBuffer(file);
  });
}

export const LUXOR_NET_KEY_VERSION = "1.0.0";
export const INVENTOR = "Christian Rivera (DJ BrightFuture)";
