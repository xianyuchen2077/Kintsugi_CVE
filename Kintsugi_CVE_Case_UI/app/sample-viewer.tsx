'use client';
import { useEffect, useState } from 'react';
import { inspectFile } from './sample-inspection.mjs';

type Identity = Awaited<ReturnType<typeof inspectFile>>;
export default function SampleViewer({ file, onSelect, onChooseFile }: { file: File | null; onSelect: (file: File, repaired?: boolean) => void; onChooseFile: () => void }) {
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [preview, setPreview] = useState('');
  const [inside, setInside] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  useEffect(() => {
    let cancelled = false;
    let url = '';
    if (file) void inspectFile(file).then((result) => {
      if (cancelled) return;
      setIdentity(result);
      setError('');
      if (['JPEG', 'PNG', 'GIF', 'BMP'].includes(result.format)) url = URL.createObjectURL(file);
      setPreview(url);
    }).catch(() => { if (!cancelled) setError('无法读取这个文件，请重新选择。'); });
    return () => { cancelled = true; if (url) URL.revokeObjectURL(url); };
  }, [file]);
  async function select(name: string, repaired = false) {
    setLoading(true);
    setError('');
    try {
      const response = await fetch(`/case-samples/CVE-2018-16509/${name}`);
      if (!response.ok) throw new Error('sample missing');
      onSelect(new File([await response.blob()], name), repaired);
    } catch { setError('样本加载失败，请通过上传按钮选择本地文件。'); }
    finally { setLoading(false); }
  }
  return <section className="sample-viewer" aria-label="文件外观与内容查看器">
    <header><div><h3>一张“图片”，两种截然不同的内容</h3><p>选一个场景，左侧检查输入，右侧观察容器中的变化。</p></div><div className="sample-actions"><button type="button" disabled={loading} onClick={() => void select('normal.jpg')}>正常样本</button><button type="button" disabled={loading} onClick={() => void select('rce.jpg')}>恶意样本</button><button type="button" className="sample-protected" disabled={loading} onClick={() => void select('rce.jpg', true)}>修补后恶意样本</button><button type="button" onClick={onChooseFile}>选择文件</button></div></header>
    {error ? <p role="alert">{error}</p> : null}
    {!file ? <p className="sample-empty">选择上方样本，或上传自己的文件。内容只在本地浏览器读取。</p> : <>
      <div className="sample-identity"><strong>{file.name}</strong><span>{file.size.toLocaleString()} bytes</span><b>{identity?.format ?? '识别中'}</b>{identity?.mismatch ? <em>扩展名与内容不一致</em> : null}</div>
      <div className="sample-tabs" role="tablist" aria-label="文件查看方式"><button role="tab" aria-selected={!inside} onClick={() => setInside(false)}>文件外观</button><button role="tab" aria-selected={inside} onClick={() => setInside(true)}>查看文件内部</button></div>
      <div className="sample-view-body" role="tabpanel">
        {inside ? <><label>真实文件头</label><pre>{identity?.header || '读取中…'}</pre>{identity?.hasPipe ? <><label>样本内命中的危险操作符</label><pre className="sample-token">{identity.tokenLine?.split(/(%pipe%)/).map((part, index) => part === '%pipe%' ? <mark key={index}>{part}</mark> : part)}</pre><p>扩展名不会改变内容。EPS 进入解释器后，这个操作符可将处理引向命令执行路径。</p></> : <p>{identity?.eps ? '这是 EPS 内容，未在已读取内容中发现 %pipe%。EPS 格式本身不等于攻击。' : '图片签名与识别结果对应；本模块只用于本案例的格式与操作符演示。'}</p>}</>
          : preview ? <figure><img src={preview} alt="当前选中的原始图片" onError={() => setError('文件头可识别，但浏览器无法解码预览。')} /><figcaption>当前输入图片 · 不是服务器返回结果</figcaption></figure> : <div className="sample-file-object"><strong>{file.name.split('.').pop()?.toUpperCase()}</strong><span>{identity?.eps ? '包含 PostScript 文本，不能作为普通 JPG 预览' : '此文件没有可用图片预览'}</span><button onClick={() => setInside(true)}>查看实际内容 →</button></div>}
      </div>
    </>}
  </section>;
}
