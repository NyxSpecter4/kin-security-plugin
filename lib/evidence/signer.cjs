/**
 * Ed25519 key management for KIN Receipt v1 (local keys, V1 trust model).
 *
 * - generateKeyPair(name, dir)  -> writes <dir>/<name> (private, 0600)
 *                                  and <dir>/<name>.pub (public, 0644),
 *                                  both PEM. Returns key metadata.
 * - loadPrivateKey(file)       -> crypto KeyObject
 * - loadPublicKeys(dir)        -> [ { key_id, path, publicKey } ]
 * - keyIdFor(publicKeyObj)     -> "ed25519:" + sha256(SPKI DER).slice(0, 16)
 *
 * Key directory resolution order:
 *   explicit --keys argument  >  KIN_ATTEST_KEYS env  >  .attest/keys
 *
 * Multiple public keys are supported from day one (captain-kiran.pub,
 * ci.pub, ...) — but this is NOT a PKI; V1 is local/developer keys only.
 */

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { sha256Hex } = require("./hash.cjs");

const DEFAULT_KEYS_DIR = ".attest/keys";

function resolveKeysDir(explicit) {
  if (explicit) return explicit;
  if (process.env.KIN_ATTEST_KEYS) return process.env.KIN_ATTEST_KEYS;
  return DEFAULT_KEYS_DIR;
}

function keyIdFor(publicKeyObj) {
  const der = publicKeyObj.export({ type: "spki", format: "der" });
  return "ed25519:" + sha256Hex(der).slice(0, 16);
}

function generateKeyPair(name, dir) {
  if (!name || !/^[A-Za-z0-9._-]+$/.test(name)) {
    throw new Error("keygen: --name must match [A-Za-z0-9._-]+");
  }
  const keysDir = resolveKeysDir(dir);
  fs.mkdirSync(keysDir, { recursive: true });
  const privPath = path.join(keysDir, name);
  const pubPath = privPath + ".pub";
  if (fs.existsSync(privPath)) {
    throw new Error(`keygen: refusing to overwrite existing key ${privPath}`);
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const privPem = privateKey.export({ type: "pkcs8", format: "pem" });
  const pubPem = publicKey.export({ type: "spki", format: "pem" });
  fs.writeFileSync(privPath, privPem, { mode: 0o600 });
  fs.writeFileSync(pubPath, pubPem, { mode: 0o644 });
  return { name, private_path: privPath, public_path: pubPath, key_id: keyIdFor(publicKey) };
}

function loadPrivateKey(file) {
  const pem = fs.readFileSync(file, "utf8");
  const key = crypto.createPrivateKey({ key: pem, format: "pem" });
  if (key.asymmetricKeyType !== "ed25519") {
    throw new Error(`signer: ${file} is not an ed25519 private key`);
  }
  return key;
}

function loadPrivateForName(name, dir) {
  const keysDir = resolveKeysDir(dir);
  const privPath = path.join(keysDir, name);
  if (!fs.existsSync(privPath)) {
    throw new Error(`signer: private key not found: ${privPath} (run: kin-security keygen --name ${name})`);
  }
  return loadPrivateKey(privPath);
}

function loadPublicKeys(dir) {
  const keysDir = resolveKeysDir(dir);
  if (!fs.existsSync(keysDir)) {
    throw new Error(`verifier: keys directory not found: ${keysDir}`);
  }
  const keys = [];
  for (const entry of fs.readdirSync(keysDir).sort()) {
    if (!entry.endsWith(".pub")) continue;
    const pubPath = path.join(keysDir, entry);
    try {
      const key = crypto.createPublicKey({ key: fs.readFileSync(pubPath, "utf8"), format: "pem" });
      if (key.asymmetricKeyType !== "ed25519") continue;
      keys.push({ key_id: keyIdFor(key), name: entry.replace(/\.pub$/, ""), path: pubPath, publicKey: key });
    } catch (err) {
      // skip unreadable files — verification only trusts parseable ed25519 keys
    }
  }
  return keys;
}

module.exports = {
  DEFAULT_KEYS_DIR,
  resolveKeysDir,
  keyIdFor,
  generateKeyPair,
  loadPrivateKey,
  loadPrivateForName,
  loadPublicKeys,
};
