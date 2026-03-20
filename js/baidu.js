/**
 * 百度首页劫持 - 极限精简版
 * 1. 移除冗余标签，仅保留核心搜索逻辑
 * 2. 极致压缩 CSS，提升渲染速度
 * 3. 优化视觉比例，上移至黄金操作区
 */

const html = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no"><title>百度一下</title><style>
:root{--bg:#f5f5f7;--c:#fff;--t:#1d1d1f;--a:#007aff}
@media(prefers-color-scheme:dark){:root{--bg:#000;--c:#1c1c1e;--t:#f5f5f7;--a:#0a84ff}}
body{margin:0;background:var(--bg);height:100vh;display:flex;justify-content:center;font-family:-apple-system,sans-serif}
.s{width:92%;max-width:500px;margin-top:15vh;text-align:center}
h1{font-size:48px;font-weight:800;color:var(--a);margin-bottom:30px;letter-spacing:-2px}
.b{background:var(--c);border-radius:18px;padding:5px;display:flex;box-shadow:0 8px 24px rgba(0,0,0,.08)}
input{flex:1;border:none;background:0 0;padding:12px 15px;font-size:17px;color:var(--t);outline:0;-webkit-appearance:none}
button{background:var(--a);color:#fff;border:none;border-radius:14px;padding:0 22px;font-size:16px;font-weight:600}
button:active{opacity:.7}</style></head><body><div class="s"><h1>Baidu</h1><form action="https://m.baidu.com/s" method="GET"><div class="b"><input type="search" name="word" placeholder="搜索..." required autocomplete="off" autofocus><button type="submit">搜索</button></div></form></div></body></html>`;

$done({
    status: 200,
    headers: { "Content-Type": "text/html;charset=UTF-8" },
    body: html
});
