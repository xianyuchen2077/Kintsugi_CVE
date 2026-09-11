import { CVE_2018_16509_REPORT_DATA as report } from './cve-2018-report-data.mjs';

// Saved evidence and mechanism illustrations intentionally have separate provenance.
export function getGhostscriptObservation(mode, phase, eps = false) {
  const step = Number.isFinite(phase) ? Math.min(4, Math.max(0, Math.floor(phase))) : 0;
  const attack = mode === 'attack';
  const protectedInput = mode === 'protected';
  const parsedAsEps = attack || protectedInput || eps;
  return {
    step, live: false,
    parser: parsedAsEps ? 'Ghostscript' : '图片解码器',
    parserState: protectedInput && step >= 2 ? 'stopped' : step >= 3 ? 'reached' : 'pending',
    extraCommand: attack && step >= 3,
    marker: step < 4 ? 'pending' : attack ? 'present' : 'absent',
    markerSource: protectedInput ? 'report' : 'mechanism',
    response: step < 3 || attack ? null : protectedInput ? report.validation.malicious.status : report.validation.normal.status,
    responseBytes: step >= 3 && mode === 'normal' ? report.validation.normal.responseBytes : null,
    guard: protectedInput && step >= 2,
    headline: step === 0 ? '等待样本进入' : step === 1 ? '文件进入图片接口' : step === 2 ? protectedInput ? '在解释器前识别危险内容' : parsedAsEps ? '真实内容被识别为 EPS' : '按图片格式读取内容' : step === 3 ? attack ? '图片处理引出了额外命令' : protectedInput ? '拒绝处理，解释器未启动' : '图片响应已返回' : attack ? '业务之外，多了一个文件' : protectedInput ? '相同样本，没有产生文件副作用' : '正常图片仍能处理',
  };
}
