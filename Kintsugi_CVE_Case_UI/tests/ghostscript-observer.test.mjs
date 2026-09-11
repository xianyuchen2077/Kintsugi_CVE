import test from 'node:test';
import assert from 'node:assert/strict';
import { getGhostscriptObservation } from '../app/ghostscript-observation.mjs';

test('the observer waits for evidence and keeps inferred file presence distinct from report evidence', () => {
  for (const mode of ['normal', 'attack', 'protected']) {
    assert.equal(getGhostscriptObservation(mode, 3).marker, 'pending');
  }
  assert.equal(getGhostscriptObservation('attack', 4).marker, 'present');
  assert.equal(getGhostscriptObservation('attack', 4).markerSource, 'mechanism');
  assert.equal(getGhostscriptObservation('protected', 4).marker, 'absent');
  assert.equal(getGhostscriptObservation('protected', 4).markerSource, 'report');
  assert.equal(getGhostscriptObservation('normal', 4).markerSource, 'mechanism');
});

test('a normal EPS can use Ghostscript without triggering the malicious branch', () => {
  const normal = getGhostscriptObservation('normal', 4, true);
  assert.equal(normal.parser, 'Ghostscript');
  assert.equal(normal.extraCommand, false);
  assert.equal(getGhostscriptObservation('attack', 3).extraCommand, true);
  assert.equal(getGhostscriptObservation('protected', 4).extraCommand, false);
  assert.equal(getGhostscriptObservation('protected', 4).parserState, 'stopped');
});

test('saved response facts only appear after the response step and never imply a live connection', () => {
  assert.equal(getGhostscriptObservation('normal', 2).response, null);
  assert.equal(getGhostscriptObservation('normal', 3).response, 200);
  assert.equal(getGhostscriptObservation('protected', 3).response, 500);
  assert.equal(getGhostscriptObservation('attack', 4).response, null);
  assert.equal(getGhostscriptObservation('normal', 4).live, false);
});
