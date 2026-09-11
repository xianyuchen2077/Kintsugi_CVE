import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'KINTSUGI · CVE Case Interface',
  description: 'KINTSUGI 三个真实漏洞案例的攻击、修补与拦截闭环界面。',
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="zh-CN">
      <body>{children}</body>
    </html>
  );
}
