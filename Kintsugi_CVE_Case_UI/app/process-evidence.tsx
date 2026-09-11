export default function ProcessEvidence({ step, malicious, repaired, eps = false }: { step: number; malicious: boolean; repaired: boolean; eps?: boolean }) {
  const blocked = malicious && repaired;
  const chain = [
    { title: '图片上传接口', detail: '接收文件，交给 Pillow', reached: step >= 1 },
    { title: blocked ? '输入检查' : '识别真实内容', detail: blocked ? '命中 %pipe%，终止处理' : malicious || eps ? '识别为 EPS / PostScript' : '按图片格式解码', reached: step >= 2 },
    { title: malicious || eps ? 'Ghostscript' : '图片转换', detail: blocked ? '未启动' : malicious || eps ? '解释 EPS 内容' : '生成图片响应', reached: step >= 3 && !blocked },
  ];
  return <section className={`process-evidence ${malicious ? 'is-malicious' : ''} ${blocked ? 'is-protected' : ''}`} aria-label="处理程序与文件副作用关系">
    <header><h3>请求经过了哪些程序</h3><p>调用关系示意 · 不代表实测进程数量或时间</p></header>
    <ol>{chain.map((node, index) => <li className={`${node.reached ? 'is-reached' : ''} ${blocked && index === 2 ? 'is-stopped' : ''}`} key={node.title}><span>{index + 1}</span><div><strong>{node.title}</strong><p>{node.detail}</p></div></li>)}</ol>
    <div className={`process-side-effect ${step >= 3 && malicious && !repaired ? 'is-visible' : ''}`}><span>业务之外的分支</span><strong>{blocked ? '额外命令没有执行机会' : malicious ? '额外 shell 命令' : '没有需要演示的额外命令'}</strong><p>{blocked ? '危险输入在解释器启动前被拒绝' : malicious ? '由解释器中的危险操作符引出' : '正常 EPS 渲染也可能启动 Ghostscript，不能把所有子进程视为攻击'}</p></div>
    <div className={`process-file-result ${step >= 4 ? 'is-reached' : ''}`}><span>{step >= 4 ? malicious && !repaired ? '新增目标文件' : blocked ? '目标文件未出现' : '业务响应' : '等待最终结果'}</span><strong>{malicious ? '/tmp/got_rce' : '图片处理结果'}</strong><p>{step < 4 ? '完成处理后展示结果' : malicious && !repaired ? '命令的副作用落在容器目录中' : blocked ? 'Stage 10 对该恶意样本的验证记录为 absent' : '输入图可预览；本地资料未提供转换后的返回图像'}</p></div>
  </section>;
}
