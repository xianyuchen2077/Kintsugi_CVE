import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { inspectSample } from '../app/sample-inspection.mjs';

test('recognizes bundled files by bytes even when the malicious sample is renamed', () => {
  const normal = readFileSync(new URL('../public/case-samples/CVE-2018-16509/normal.jpg', import.meta.url));
  const attack = readFileSync(new URL('../public/case-samples/CVE-2018-16509/rce.jpg', import.meta.url));
  assert.equal(inspectSample(normal, 'rce.jpg').classification, 'normal');
  const result = inspectSample(attack, 'holiday.jpg');
  assert.equal(result.classification, 'malicious');
  assert.equal(result.mismatch, true);
  assert.match(result.header, /%!PS/);
  assert.match(result.tokenLine, /%pipe%/);
});

test('does not label benign EPS or unknown content as a successful attack', () => {
  assert.equal(inspectSample(Buffer.from('%!PS-Adobe-3.0\nshowpage'), 'normal.eps').classification, 'normal');
  assert.equal(inspectSample(Buffer.from('not an image'), 'normal.jpg').classification, 'unknown');
  assert.equal(inspectSample(Buffer.from('%!PS-Adobe-3.0'), 'large.eps', false).classification, 'unknown');
});
