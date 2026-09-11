import { CVE_PROFILES } from './case-state.mjs';

export const PLAYBACK_CHAPTERS = Object.freeze([
  Object.freeze({ id: 'flow', label: '演示流程', detail: '完整过程' }),
  Object.freeze({ id: 'location', label: '漏洞定位', detail: '路径证据' }),
  Object.freeze({ id: 'patch', label: '修补解析', detail: '代码变化' }),
  Object.freeze({ id: 'comparison', label: '结果对比', detail: '前后验证' }),
]);

export const PLAYBACK_SPEEDS = Object.freeze([0.75, 1, 1.5]);
export const PLAYBACK_FRAME_COUNT = 12;
export const CHAPTER_FRAME_RANGES = Object.freeze({
  flow: Object.freeze({ start: 0, end: 3 }),
  location: Object.freeze({ start: 0, end: 4 }),
  patch: Object.freeze({ start: 4, end: 8 }),
  comparison: Object.freeze({ start: 8, end: 12 }),
});

export function createPlaybackState(cve = 'CVE-2022-46169', speed = 1) {
  if (!CVE_PROFILES[cve]) throw new Error(`Unknown CVE profile: ${cve}`);
  return {
    cve,
    status: 'idle',
    frame: 0,
    speed: PLAYBACK_SPEEDS.includes(speed) ? speed : 1,
    activeChapter: null,
    segmentStart: 0,
    segmentEnd: PLAYBACK_FRAME_COUNT,
  };
}

export function transitionPlayback(state, event) {
  switch (event.type) {
    case 'PLAY':
      if (state.status === 'complete') return { ...state, status: 'playing', frame: state.segmentStart ?? 0 };
      return { ...state, status: 'playing' };
    case 'PLAY_CHAPTER': {
      const range = CHAPTER_FRAME_RANGES[event.chapter];
      if (!range) return state;
      if (state.status === 'paused' && state.activeChapter === event.chapter) {
        return { ...state, status: 'playing' };
      }
      return {
        ...state,
        status: 'playing',
        frame: range.start,
        activeChapter: event.chapter,
        segmentStart: range.start,
        segmentEnd: range.end,
      };
    }
    case 'PAUSE':
      return state.status === 'playing' ? { ...state, status: 'paused' } : state;
    case 'TICK': {
      if (state.status !== 'playing') return state;
      const segmentEnd = state.segmentEnd ?? PLAYBACK_FRAME_COUNT;
      const frame = Math.min(segmentEnd, state.frame + 1);
      return {
        ...state,
        frame,
        status: frame === segmentEnd ? 'complete' : 'playing',
      };
    }
    case 'RESTART':
      return createPlaybackState(state.cve, state.speed);
    case 'SET_SPEED':
      return PLAYBACK_SPEEDS.includes(event.speed) ? { ...state, speed: event.speed } : state;
    case 'SELECT_CVE':
      return createPlaybackState(event.cve, state.speed);
    default:
      return state;
  }
}

export function getPlaybackSnapshot(state) {
  const profile = CVE_PROFILES[state.cve];
  const logs = [...profile.attackLogs, ...profile.repairLogs, ...profile.blockedLogs];
  const frame = Math.max(0, Math.min(PLAYBACK_FRAME_COUNT, state.frame));
  const segmentStart = Math.max(0, Math.min(frame, state.segmentStart ?? 0));
  const segmentEnd = Math.max(segmentStart + 1, Math.min(PLAYBACK_FRAME_COUNT, state.segmentEnd ?? PLAYBACK_FRAME_COUNT));
  const segmentFrame = Math.max(0, frame - segmentStart);
  const segmentLength = segmentEnd - segmentStart;
  const chapter = frame >= 12
    ? 'comparison'
    : frame >= 8
      ? 'patch'
      : frame >= 4
        ? 'location'
        : 'flow';

  return {
    chapter,
    frame,
    progress: Math.round((segmentFrame / segmentLength) * 100),
    elapsedSeconds: segmentFrame * 2,
    totalSeconds: segmentLength * 2,
    logs: logs.slice(0, frame),
    beforeVisible: frame >= 4,
    patchStep: Math.max(0, Math.min(4, frame - 4)),
    afterBlocked: frame >= 12,
    normalVerified: frame >= 12,
    currentFinding: frame >= 12
      ? `${profile.targetFunction} · 相同输入已被拦截，正常业务保持可用`
      : frame >= 8
        ? `${profile.repairLocation} · 修补代码与策略边界已加载`
        : frame >= 4
          ? `${profile.targetFunction} · ${profile.dangerCall}`
          : '等待开始案例演示',
  };
}

export function resolvePlaybackView(state, selectedView, followingPlayback = true) {
  if (followingPlayback && state.status !== 'idle') {
    return getPlaybackSnapshot(state).chapter;
  }
  return selectedView;
}
