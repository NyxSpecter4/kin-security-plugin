/**
 * Deterministic canonical JSON serialization for the KIN Receipt v1.
 *
 * Rules (deterministic, dependency-free):
 *  - Object keys are sorted lexicographically (UTF-16 code-unit order).
 *  - Arrays preserve order (order is meaning).
 *  - Strings/numbers serialized via JSON.stringify single-value rules.
 *  - null / true / false as in JSON.
 *  - undefined and functions are REJECTED (fail-closed: an undefined value
 *    would silently drop from JSON.stringify and break reproducibility).
 *
 * canonicalSerialize(value) -> string
 * Throws Error("canonicalize: unsupported value") on undefined/function.
 */

function canonicalizeValue(value) {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  const t = typeof value;
  if (t === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("canonicalize: non-finite numbers are not allowed");
    }
    return JSON.stringify(value);
  }
  if (t === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    const parts = value.map((v) => canonicalizeValue(v));
    return "[" + parts.join(",") + "]";
  }
  if (t === "object") {
    const keys = Object.keys(value).sort();
    const parts = [];
    for (const key of keys) {
      const v = value[key];
      if (v === undefined) {
        throw new Error(`canonicalize: property "${key}" is undefined (fail-closed)`);
      }
      parts.push(JSON.stringify(key) + ":" + canonicalizeValue(v));
    }
    return "{" + parts.join(",") + "}";
  }
  if (t === "function" || t === "undefined" || t === "bigint" || t === "symbol") {
    throw new Error(`canonicalize: unsupported value type (${t})`);
  }
  throw new Error("canonicalize: unsupported value");
}

function canonicalSerialize(value) {
  return canonicalizeValue(value);
}

module.exports = { canonicalSerialize };
