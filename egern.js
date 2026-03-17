// loon-to-egern.js - 运行在 Egern 的 Loon → Egern 转换器

async function operator(r) {
  const url = new URL(r.url);
  let input = '';

  // 支持两种输入：raw=链接 或 text=Base64内容
  if (url.searchParams.has('raw')) {
    const rawUrl = url.searchParams.get('raw');
    try {
      const res = await fetch(rawUrl);
      input = await res.text();
    } catch (e) {
      return { response: { status: 500, body: `无法获取链接: ${e}` } };
    }
  } else if (url.searchParams.has('text')) {
    try {
      input = atob(url.searchParams.get('text'));  // Base64 解码
    } catch (e) {
      return { response: { status: 400, body: 'Base64 解码失败' } };
    }
  } else {
    return { response: { status: 400, body: '缺少参数：?raw=... 或 ?text=...' } };
  }

  // 核心解析
  const yaml = convertLoonToEgern(input);

  return {
    response: {
      status: 200,
      headers: { 'Content-Type': 'text/yaml; charset=utf-8' },
      body: yaml
    }
  };
}

// ==================== 解析核心 ====================
function convertLoonToEgern(loon) {
  const lines = loon.split('\n').map(l => l.trim());
  let name = 'Loon-Converted';
  let desc = '从 Loon 转换而来';
  let icon = '';
  let openUrl = '';

  const rules = [];
  const rewrites = []; // body_rewrites
  const locals = [];   // map_locals
  const mitmSet = new Set();

  let section = '';

  for (let line of lines) {
    if (!line || line.startsWith('//') || line.startsWith('#')) {
      // 元信息
      if (line.startsWith('#!name=')) name = line.slice(7);
      if (line.startsWith('#!desc=')) desc = line.slice(7);
      if (line.startsWith('#!icon=')) icon = line.slice(7);
      if (line.startsWith('#!openUrl=')) openUrl = line.slice(10);
      continue;
    }

    if (line.startsWith('[')) {
      section = line.slice(1, -1).toLowerCase();
      continue;
    }

    // [Rule]
    if (section === 'rule') {
      if (line.startsWith('DOMAIN,')) {
        const domain = line.split(',')[1];
        rules.push({ domain_keyword: domain, policy: 'REJECT' });
      }
      // 可加其他 rule 类型支持，如 DOMAIN-SUFFIX 等
    }

    // [Body Rewrite] http-response-jq
    if (section === 'body rewrite' && line.includes('http-response-jq')) {
      const match = line.match(/http-response-jq\s+([^\s']+)\s+'([^']+)'/);
      if (match) {
        let [, pattern, filter] = match;
        // 合并相同 match 的 filter
        let existing = rewrites.find(r => r.response_jq?.match === pattern);
        if (existing) {
          existing.response_jq.filter += ' | ' + filter;
        } else {
          rewrites.push({
            response_jq: {
              match: pattern,
              body_required: true,
              timeout: 30,
              filter: filter
            }
          });
        }
      }
    }

    // [Map Local]
    if (section === 'map local') {
      const parts = line.split(/\s+/);
      const match = parts[0];
      let body = '{}';
      let status = 200;
      let headers = { 'Content-Type': 'application/json' };

      for (let i = 1; i < parts.length; i++) {
        if (parts[i].startsWith('data=')) body = parts[i].slice(5).replace(/^"|"$/g, '');
        if (parts[i].startsWith('status-code=')) status = parseInt(parts[i].slice(12));
        if (parts[i].startsWith('header=')) {
          const h = parts[i].slice(7).replace(/^"|"$/g, '');
          if (h.includes(':')) {
            const [k, v] = h.split(':');
            headers[k.trim()] = v.trim();
          }
        }
      }

      locals.push({ match, status, headers, body });
    }

    // [MITM]
    if (section === 'mitm' && line.includes('hostname')) {
      const hosts = line.split('=')[1]?.split(',').map(h => h.trim()) || [];
      hosts.forEach(h => {
        if (h) {
          mitmSet.add(h);
          const base = h.replace(/^\*\./, '');
          if (!h.startsWith('*.')) mitmSet.add('*.' + base);
        }
      });
    }
  }

  // 构建 YAML 字符串（多行 filter 用 |）
  let yaml = `name: ${name}
description: ${desc}
open_url: ${openUrl}
icon: ${icon}

rules:
${rules.map(r => `  - domain_keyword: ${r.domain_keyword}\n    policy: REJECT`).join('\n') || '  []'}

body_rewrites:
${rewrites.map(r => {
  const f = r.response_jq.filter;
  return `  - response_jq:
      match: ${r.response_jq.match}
      body_required: true
      timeout: 30
      filter: |
        ${f.split(' | ').join('\n        ')}`;
}).join('\n') || '  []'}

map_locals:
${locals.map(l => `  - match: ${l.match}
    status: ${l.status}
    headers:
      ${Object.entries(l.headers).map(([k,v]) => `${k}: ${v}`).join('\n      ')}
    body: '${l.body.replace(/'/g, "\\'")}'`).join('\n') || '  []'}

mitm:
  hostnames:
    includes:
${Array.from(mitmSet).map(h => `      - ${h}`).join('\n') || '      - "*.example.com"'}
`;

  return yaml;
}