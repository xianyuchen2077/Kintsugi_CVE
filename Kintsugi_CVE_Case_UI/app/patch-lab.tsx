'use client';
import { useState } from 'react';
const changes = [
  { code: "with open(infile, 'rb') as eps_file:", title: '读取输入', detail: '读取 EPS 原始字节，不依赖文件名判断内容。' },
  { code: "    if b'%pipe%' in eps_file.read():", title: '检查危险操作符', detail: '这里匹配 %pipe%，它是本案例需要阻止的危险输入。' },
  { code: "        raise IOError('unsafe EPS file')", title: '拒绝危险输入', detail: '命中时抛出异常，后面的 Ghostscript 启动调用不会执行。' },
  { code: 'subprocess.check_call(command, …)', title: '保留原有调用', detail: '通过检查的 EPS 继续交给 Ghostscript；普通 JPG 通常走图片解码路径。' },
];
export default function PatchLab({ frame, playing, onPause }: { frame: number; playing: boolean; onPause: () => void }) {
  const [choice, setChoice] = useState<number | null>(null);
  const [version, setVersion] = useState<'before' | 'after'>('after');
  const [input, setInput] = useState<'normal' | 'attack'>('attack');
  const selected = playing ? Math.max(0, Math.min(3, frame - 1)) : choice ?? Math.max(0, Math.min(3, frame - 1));
  function select(index: number) { onPause(); setChoice(index); }
  return <section className="patch-lab" aria-label="修补代码与阻断位置联动">
    <header><div><h3>这几行代码，改变了哪条路径？</h3><p>点击代码，查看右侧对应的处理位置。代码为报告中的关键逻辑节选。</p></div><div className="sample-actions"><button aria-pressed={version === 'before'} onClick={() => { onPause(); setVersion('before'); }}>修补前</button><button aria-pressed={version === 'after'} onClick={() => { onPause(); setVersion('after'); }}>修补后</button></div></header>
    <div className="patch-lab-grid">
      <div className="patch-lab-code"><div className="patch-lab-file">PIL / EpsImagePlugin.py · Ghostscript()</div>{changes.map((line, index) => <button type="button" key={line.title} disabled={version === 'before' && index < 3} aria-label={`解析代码：${line.title}`} aria-pressed={selected === index} onClick={() => select(index)} className={`${selected === index ? 'is-selected' : ''} ${version === 'before' && index < 3 ? 'is-missing' : ''}`}><span>{index < 3 ? '+' : ' '}</span><code>{version === 'before' && index < 3 ? ['# 尚未加入输入检查', '#', '#'][index] : line.code}</code></button>)}<p>{version === 'before' ? '原有调用直接将 EPS 交给 Ghostscript。' : changes[selected].detail}</p><small>省略号表示其余调用参数。</small></div>
      <div className="patch-lab-route"><div className="sample-actions"><button aria-pressed={input === 'normal'} onClick={() => { onPause(); setInput('normal'); }}>正常 EPS</button><button aria-pressed={input === 'attack'} onClick={() => { onPause(); setInput('attack'); }}>恶意 EPS</button></div>
        <ol>{changes.map((line, index) => <li key={line.title} className={`${selected === index ? 'is-selected' : ''} ${version === 'before' && index < 3 ? 'is-skipped' : ''}`}><span>{index + 1}</span><div><strong>{index === 2 && input === 'normal' ? '未命中，继续处理' : line.title}</strong><small>{version === 'before' && index < 3 ? '无此检查' : index === 1 ? input === 'attack' ? '发现 %pipe%' : '未发现 %pipe%' : index === 3 && version === 'after' && input === 'attack' ? '此调用不会到达' : line.detail}</small></div></li>)}</ol>
        <div className={`patch-lab-outcome ${input === 'attack' && version === 'before' ? 'is-danger' : ''}`}><strong>{input === 'normal' ? '继续原有 EPS 渲染流程' : version === 'before' ? '危险内容可进入解释器' : '在 Ghostscript 启动前拒绝'}</strong><p>{input === 'normal' ? '这是正常 EPS 的分支逻辑示意，不冒充一次新的业务测试。' : version === 'before' ? '额外命令可能创建 /tmp/got_rce。' : '报告中同一恶意样本复测：HTTP 500，标记文件未创建。'}</p></div>
      </div>
    </div>
  </section>;
}
