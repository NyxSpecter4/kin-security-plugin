/**
 * Canonicalization tests — the determinism foundation.
 * Every other guarantee sits on top of this.
 */

const test = require("node:test");
const assert = require("node:assert");
const { canonicalSerialize } = require("../lib/evidence/canonicalize.cjs");
const { sha256Hex } = require("../lib/evidence/hash.cjs");

test("canonical: key order does not matter", () => {
  const a = canonicalSerialize({ x: 1, y: { b: 2, a: 3 }, z: [1, 2, 3] });
  const b = canonicalSerialize({ z: [1, 2, 3], y: { a: 3, b: 2 }, x: 1 });
  assert.strictEqual(a, b);
});

test("canonical: array order DOES matter (order is meaning)", () => {
  const a = canonicalSerialize({ list: [1, 2] });
  const b = canonicalSerialize({ list: [2, 1] });
  assert.notStrictEqual(a, b);
});

test("canonical: deterministic across 10 runs", () => {
  const value = { findings: [{ cwe: "CWE-89", line: 2 }], policy: "default" };
  let first = null;
  for (let i = 0; i < 10; i++) {
    const serialized = canonicalSerialize(value);
    if (first === null) first = serialized;
    assert.strictEqual(serialized, first);
  }
  assert.strictEqual(first, '{"findings":[{"cwe":"CWE-89","line":2}],"policy":"default"}');
});

test("canonical: rejects undefined (fail-closed, no silent drop)", () => {
  assert.throws(() => canonicalSerialize({ a: undefined }), /undefined/);
  assert.throws(() => canonicalSerialize([undefined]), /undefined/);
});

test("canonical: rejects functions and non-finite numbers", () => {
  assert.throws(() => canonicalSerialize({ f: () => 1 }), /unsupported/);
  assert.throws(() => canonicalSerialize({ n: Number.NaN }), /non-finite/);
  assert.throws(() => canonicalSerialize(Infinity), /non-finite/);
});

test("canonical: strings escaped like JSON", () => {
  assert.strictEqual(canonicalSerialize("a\"b\\c\n"), JSON.stringify("a\"b\\c\n"));
});

test("sha256: stable and hex", () => {
  assert.strictEqual(sha256Hex("kin"), sha256Hex("kin"));
  assert.match(sha256Hex("kin"), /^[0-9a-f]{64}$/);
  assert.notStrictEqual(sha256Hex("kin"), sha256Hex("kni"));
});
