import test from 'node:test';
import assert from 'node:assert/strict';

import {
  CHAPTER_FRAME_RANGES,
  PLAYBACK_CHAPTERS,
  PLAYBACK_SPEEDS,
  createPlaybackState,
  getPlaybackSnapshot,
  resolvePlaybackView,
  transitionPlayback,
} from '../app/presentation-state.mjs';

test('resumes a paused page at its current frame and replays a completed page from the start', () => {
  let state = transitionPlayback(createPlaybackState(), { type: 'PLAY_CHAPTER', chapter: 'comparison' });
  state = transitionPlayback(state, { type: 'TICK' });
  state = transitionPlayback(state, { type: 'PAUSE' });
  state = transitionPlayback(state, { type: 'PLAY_CHAPTER', chapter: 'comparison' });
  assert.equal(state.frame, 9);
  assert.equal(state.status, 'playing');
  for (let i = 0; i < 3; i++) state = transitionPlayback(state, { type: 'TICK' });
  state = transitionPlayback(state, { type: 'PLAY_CHAPTER', chapter: 'comparison' });
  assert.equal(state.frame, 8);
});

test('runs each page demo only inside its own frame range', () => {
  for (const [chapter, range] of Object.entries(CHAPTER_FRAME_RANGES)) {
    let state = transitionPlayback(createPlaybackState(), { type: 'PLAY_CHAPTER', chapter });

    assert.equal(state.activeChapter, chapter);
    assert.equal(state.frame, range.start);
    assert.equal(state.status, 'playing');

    for (let index = 0; index < 20; index += 1) {
      state = transitionPlayback(state, { type: 'TICK' });
    }

    assert.equal(state.frame, range.end);
    assert.equal(state.status, 'complete');
  }
});

test('defines four concise presentation chapters in narrative order', () => {
  assert.deepEqual(PLAYBACK_CHAPTERS.map((chapter) => chapter.id), [
    'flow',
    'location',
    'patch',
    'comparison',
  ]);
  assert.deepEqual(PLAYBACK_CHAPTERS.map((chapter) => chapter.label), [
    '演示流程',
    '漏洞定位',
    '修补解析',
    '结果对比',
  ]);
});

test('starts with loaded prerecorded data and no visible run output', () => {
  const state = createPlaybackState('CVE-2018-16509');
  const snapshot = getPlaybackSnapshot(state);

  assert.equal(state.cve, 'CVE-2018-16509');
  assert.equal(state.status, 'idle');
  assert.equal(state.frame, 0);
  assert.equal(snapshot.chapter, 'flow');
  assert.equal(snapshot.beforeVisible, false);
  assert.equal(snapshot.afterBlocked, false);
  assert.deepEqual(snapshot.logs, []);
});

test('advances deterministically through attack patch and validation frames', () => {
  let state = transitionPlayback(createPlaybackState(), { type: 'PLAY' });

  for (let index = 0; index < 4; index += 1) {
    state = transitionPlayback(state, { type: 'TICK' });
  }
  let snapshot = getPlaybackSnapshot(state);
  assert.equal(snapshot.chapter, 'location');
  assert.equal(snapshot.beforeVisible, true);
  assert.equal(snapshot.patchStep, 0);

  for (let index = 0; index < 4; index += 1) {
    state = transitionPlayback(state, { type: 'TICK' });
  }
  snapshot = getPlaybackSnapshot(state);
  assert.equal(snapshot.chapter, 'patch');
  assert.equal(snapshot.patchStep, 4);

  for (let index = 0; index < 4; index += 1) {
    state = transitionPlayback(state, { type: 'TICK' });
  }
  snapshot = getPlaybackSnapshot(state);
  assert.equal(snapshot.chapter, 'comparison');
  assert.equal(snapshot.afterBlocked, true);
  assert.equal(snapshot.normalVerified, true);
  assert.equal(state.status, 'complete');
});

test('pause freezes frame and play resumes from the same position', () => {
  const playing = transitionPlayback(createPlaybackState(), { type: 'PLAY' });
  const advanced = transitionPlayback(playing, { type: 'TICK' });
  const paused = transitionPlayback(advanced, { type: 'PAUSE' });
  const ignored = transitionPlayback(paused, { type: 'TICK' });
  const resumed = transitionPlayback(ignored, { type: 'PLAY' });

  assert.equal(paused.status, 'paused');
  assert.equal(ignored.frame, advanced.frame);
  assert.equal(resumed.status, 'playing');
});

test('restart keeps the selected case and speed but clears playback evidence', () => {
  let state = createPlaybackState('CVE-2024-25737');
  state = transitionPlayback(state, { type: 'SET_SPEED', speed: 1.5 });
  state = transitionPlayback(state, { type: 'PLAY' });
  state = transitionPlayback(state, { type: 'TICK' });
  state = transitionPlayback(state, { type: 'RESTART' });

  assert.equal(state.cve, 'CVE-2024-25737');
  assert.equal(state.speed, 1.5);
  assert.equal(state.status, 'idle');
  assert.equal(state.frame, 0);
});

test('supports only the presentation speed choices', () => {
  assert.deepEqual(PLAYBACK_SPEEDS, [0.75, 1, 1.5]);
  const initial = createPlaybackState();
  const accepted = transitionPlayback(initial, { type: 'SET_SPEED', speed: 0.75 });
  const rejected = transitionPlayback(accepted, { type: 'SET_SPEED', speed: 4 });

  assert.equal(accepted.speed, 0.75);
  assert.deepEqual(rejected, accepted);
});

test('switching case creates a clean loaded playback session', () => {
  let state = transitionPlayback(createPlaybackState(), { type: 'PLAY' });
  state = transitionPlayback(state, { type: 'TICK' });
  state = transitionPlayback(state, { type: 'SELECT_CVE', cve: 'CVE-2018-16509' });

  assert.equal(state.cve, 'CVE-2018-16509');
  assert.equal(state.status, 'idle');
  assert.equal(state.frame, 0);
});

test('keeps the completed playback on comparison until the presenter chooses another tab', () => {
  let state = transitionPlayback(createPlaybackState('CVE-2018-16509'), { type: 'PLAY' });
  for (let index = 0; index < 12; index += 1) {
    state = transitionPlayback(state, { type: 'TICK' });
  }

  assert.equal(state.status, 'complete');
  assert.equal(resolvePlaybackView(state, 'flow', true), 'comparison');
  assert.equal(resolvePlaybackView(state, 'patch', false), 'patch');
});
