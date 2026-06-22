import { test } from "node:test";
import assert from "node:assert";
import { shannonEntropy, carveSections } from "./index.js";

test("entropy of empty buffer is 0", () => {
  assert.strictEqual(shannonEntropy(Buffer.alloc(0)), 0.0);
});

test("entropy of uniform buffer is 0", () => {
  assert.strictEqual(shannonEntropy(Buffer.from([5, 5, 5, 5])), 0.0);
});

test("entropy of two equiprobable symbols is 1.0", () => {
  assert.ok(Math.abs(shannonEntropy(Buffer.from([0, 1])) - 1.0) < 0.001);
});

test("entropy of all 256 bytes is 8.0", () => {
  const buf = Buffer.from(Array.from({ length: 256 }, (_, i) => i));
  assert.ok(Math.abs(shannonEntropy(buf) - 8.0) < 0.001);
});

test("carve detects elf magic", () => {
  const buf = Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), Buffer.alloc(300)]);
  const secs = carveSections(buf);
  assert.strictEqual(secs.length, 1);
  assert.strictEqual(secs[0].label, "elf");
});

test("carve detects gzip magic", () => {
  const buf = Buffer.concat([Buffer.from([0x1f, 0x8b, 0x08]), Buffer.alloc(300)]);
  assert.strictEqual(carveSections(buf)[0].label, "gzip");
});

test("carve of empty image yields no sections", () => {
  assert.strictEqual(carveSections(Buffer.alloc(0)).length, 0);
});

test("carve collapses magics within 256 bytes", () => {
  const buf = Buffer.alloc(400);
  Buffer.from([0x7f, 0x45, 0x4c, 0x46]).copy(buf, 0);
  Buffer.from([0x7f, 0x45, 0x4c, 0x46]).copy(buf, 10);
  assert.strictEqual(carveSections(buf).length, 1);
});
