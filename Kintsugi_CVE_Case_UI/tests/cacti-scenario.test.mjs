import test from 'node:test';
import assert from 'node:assert/strict';
import { cactiSnapshot } from '../app/cacti-scenario.mjs';

test('Cacti never shows a marker verdict before the evidence step', () => {
  for (const mode of ['normal', 'attack', 'protected']) {
    for (let phase = 0; phase < 4; phase++) assert.equal(cactiSnapshot(mode, phase).marker, 'pending');
    assert.equal(cactiSnapshot(mode, 4).measured, false);
  }
});

test('Cacti separates expected side effects, runtime boundary and normal coverage', () => {
  assert.equal(cactiSnapshot('attack', 4).marker, 'present');
  assert.equal(cactiSnapshot('normal', 4).marker, 'absent');
  assert.equal(cactiSnapshot('protected', 4).marker, 'absent');
  assert.equal(cactiSnapshot('protected', 2).blocked, false);
  assert.equal(cactiSnapshot('protected', 3).blocked, true);
  assert.equal(cactiSnapshot('normal', 4).branch, 'action=1');
  assert.equal(cactiSnapshot('attack', 4).branch, 'action=2');
  assert.equal(cactiSnapshot('normal', 2).logs.length, 2);
});
