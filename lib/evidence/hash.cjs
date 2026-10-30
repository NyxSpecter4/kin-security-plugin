/**
 * Content hashing for evidence. sha256 over UTF-8 bytes (node:crypto).
 */

const crypto = require("crypto");

function sha256Hex(input) {
  const data = typeof input === "string" ? Buffer.from(input, "utf8") : Buffer.from(input);
  return crypto.createHash("sha256").update(data).digest("hex");
}

module.exports = { sha256Hex };
