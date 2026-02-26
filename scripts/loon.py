#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import ipaddress
import re
import time
from datetime import datetime, timedelta
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ================= 配置区 =================
RULE_SOURCES = [
    {
        "name": "anti-ad", 
        "url": "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-surge.txt"
    },
    {
        "name": "adrules", 
        "url": "https://raw.githubusercontent.com/Cats-Team/AdRules/main/adrules.list"
    }
]

OUTPUT_FILE = "Loon.lsr"
AUDIT_LOG_FILE = "Loon.log"
# ==========================================

def get_beijing_time():
    return (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')

def create_session():
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

def parse_rule(line):
    """解析规则，仅识别 DOMAIN, DOMAIN-SUFFIX, IP-CIDR"""
    line = line.strip()
    
    # 跳过空行和注释
    if not line or line.startswith('#') or line.startswith('//') or line.startswith('!'):
        return None, None, False, False
    
    # 检查前导点（视为无效，仅统计）
    if line.startswith('.'):
        return None, None, False, True  # True 表示是前导点格式
    
    parts = [p.strip() for p in line.split(',')]
    if len(parts) < 2:
        return None, None, False, False
    
    rtype = parts[0].upper()
    rval = parts[1].lower().strip()
    
    if rtype not in ('DOMAIN', 'DOMAIN-SUFFIX', 'IP-CIDR'):
        return None, None, False, False
    
    if not rval:
        return None, None, False, False
    
    # IP-CIDR 验证
    if rtype == 'IP-CIDR':
        try:
            ipaddress.IPv4Network(rval, strict=False)
        except ValueError:
            return None, None, False, False
        # 检查是否已有 no-resolve
        has_no_resolve = len(parts) >= 3 and 'no-resolve' in [p.strip().lower() for p in parts[2:]]
        return rtype, rval, True, has_no_resolve
    
    # 域名验证
    if not re.match(r'^[a-z0-9\-\.]+$', rval) or rval.startswith('.') or rval.endswith('.') or '..' in rval:
        return None, None, False, False
    
    return rtype, rval, True, False

def normalize(rtype, rval, has_no_resolve=False):
    """标准化规则"""
    if rtype == 'IP-CIDR':
        if has_no_resolve:
            return f"{rtype},{rval},no-resolve"
        return f"{rtype},{rval},no-resolve"
    return f"{rtype},{rval}"

class DomainTrie:
    """域名Trie树"""
    
    def __init__(self):
        self.root = {}
    
    def add(self, suffix):
        node = self.root
        for part in reversed(suffix.split('.')):
            if part not in node:
                node[part] = {}
            node = node[part]
        node['#'] = True
    
    def is_covered(self, domain):
        """检查domain是否被某个DOMAIN-SUFFIX覆盖"""
        node = self.root
        matched = []
        for part in reversed(domain.split('.')):
            if '#' in node and matched:
                return True, '.'.join(reversed(matched))
            if part not in node:
                return False, None
            node = node[part]
            matched.append(part)
        return '#' in node, '.'.join(reversed(matched)) if matched else None

class IPCidrManager:
    """IP-CIDR管理器"""
    
    def __init__(self):
        self.nets = []
    
    def add(self, cidr):
        network = ipaddress.IPv4Network(cidr, strict=False)
        
        # 检查是否被已有网段覆盖
        for existing_net, existing_str in self.nets:
            if existing_net.supernet_of(network):
                return True, existing_str
        
        # 移除被新网段覆盖的
        self.nets = [(n, s) for n, s in self.nets if not network.supernet_of(n)]
        self.nets.append((network, cidr))
        return False, None

def main():
    print(f"[{get_beijing_time()}] 开始获取规则...")
    session = create_session()
    all_rules = []  # (norm, rtype, rval, source, orig, has_no_resolve)
    source_stats = []
    
    # 获取规则
    for src in RULE_SOURCES:
        try:
            resp = session.get(src['url'], timeout=30)
            resp.raise_for_status()
            lines = resp.text.splitlines()
            
            valid = 0
            leading_dot = 0
            
            for line in lines:
                rtype, rval, ok, is_leading_dot = parse_rule(line)
                
                if is_leading_dot:
                    leading_dot += 1
                    continue
                
                if ok:
                    has_no_resolve = False
                    if rtype == 'IP-CIDR':
                        # 重新解析检查 no-resolve
                        parts = [p.strip() for p in line.split(',')]
                        has_no_resolve = len(parts) >= 3 and 'no-resolve' in [p.strip().lower() for p in parts[2:]]
                    
                    norm = normalize(rtype, rval, has_no_resolve)
                    all_rules.append((norm, rtype, rval, src['name'], line.strip(), has_no_resolve))
                    valid += 1
            
            source_stats.append({
                'name': src['name'],
                'total': len(lines),
                'valid': valid,
                'leading_dot': leading_dot
            })
            print(f"[{get_beijing_time()}] {src['name']}: 有效 {valid}, 前导点 {leading_dot}, 总行 {len(lines)}")
            
        except Exception as e:
            print(f"[{get_beijing_time()}] {src['name']} 获取失败: {e}")
            source_stats.append({
                'name': src['name'],
                'total': 0,
                'valid': 0,
                'leading_dot': 0,
                'error': str(e)
            })
    
    if not all_rules:
        print("没有有效规则")
        return
    
    print(f"[{get_beijing_time()}] 开始去重，共 {len(all_rules)} 条...")
    
    # 第一步：完全相同去重
    seen = {}
    unique = []
    exact_dup = 0
    
    for norm, rtype, rval, source, orig, has_no_resolve in all_rules:
        if norm in seen:
            exact_dup += 1
        else:
            seen[norm] = source
            unique.append((norm, rtype, rval, source, orig))
    
    # 第二步：包含去重
    trie = DomainTrie()
    ip_mgr = IPCidrManager()
    final_domains = []
    final_suffixes = []
    final_ips = []
    cover_logs = []
    domain_covered = 0
    ip_covered = 0
    
    # 先处理 DOMAIN-SUFFIX（按长度排序，父域优先）
    suffixes = [(n, r, v, s, o) for n, r, v, s, o in unique if r == 'DOMAIN-SUFFIX']
    suffixes.sort(key=lambda x: len(x[2]))
    
    for norm, rtype, rval, source, orig in suffixes:
        covered, by = trie.is_covered(rval)
        if covered:
            domain_covered += 1
            cover_logs.append(f"[包含去重] {orig:<50} # 溯源: DOMAIN-SUFFIX,{by}")
        else:
            trie.add(rval)
            final_suffixes.append(norm)
    
    # 处理 DOMAIN
    domains = [(n, r, v, s, o) for n, r, v, s, o in unique if r == 'DOMAIN']
    for norm, rtype, rval, source, orig in domains:
        covered, by = trie.is_covered(rval)
        if covered:
            domain_covered += 1
            cover_logs.append(f"[包含去重] {orig:<50} # 溯源: DOMAIN-SUFFIX,{by}")
        else:
            final_domains.append(norm)
    
    # 处理 IP-CIDR（大网段优先）
    ips = [(n, r, v, s, o) for n, r, v, s, o in unique if r == 'IP-CIDR']
    ips.sort(key=lambda x: int(x[2].split('/')[1]), reverse=True)
    
    for norm, rtype, rval, source, orig in ips:
        covered, by = ip_mgr.add(rval)
        if covered:
            ip_covered += 1
            cover_logs.append(f"[包含去重] {orig:<50} # 溯源: IP-CIDR,{by}")
        else:
            final_ips.append(norm)
    
    # 合并排序
    final_rules = sorted(final_domains) + sorted(final_suffixes) + sorted(final_ips)
    
    # 统计各类型数量
    type_counts = {
        'DOMAIN': len(final_domains),
        'DOMAIN-SUFFIX': len(final_suffixes),
        'IP-CIDR': len(final_ips)
    }
    
    # 生成文件头（新风格）
    header_lines = [
        "# ==========================================================",
        "# 合并规则文件",
        f"# 生成时间: {get_beijing_time()}",
        f"# 总计保留: {len(final_rules)} 条规则",
        f"# 类型分布: DOMAIN: {type_counts['DOMAIN']} | DOMAIN-SUFFIX: {type_counts['DOMAIN-SUFFIX']} | IP-CIDR: {type_counts['IP-CIDR']}",
        f"# 压缩分析: 完全相同去重 {exact_dup} | 域名包含去重 {domain_covered} | IP网段包含去重 {ip_covered}",
        "# ==========================================================",
        "# 名称                原始规模      有效提取      无效/丢弃",
        "# ----------------------------------------------------------",
    ]
    
    for s in source_stats:
        invalid = s['total'] - s['valid'] + s['leading_dot']
        header_lines.append(f"# {s['name']:<18} {s['total']:>10}  {s['valid']:>10}  {invalid:>10}")
    
    header_lines.extend([
        "# ==========================================================",
        ""
    ])
    
    # 写规则文件
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header_lines) + '\n'.join(final_rules))
    
    # 写审计日志
    log_lines = [
        f"# 规则合并审计日志 - {get_beijing_time()}",
        "# ----------------------------------------------------------",
        f"# 最终规则总数: {len(final_rules)}",
        f"# 逻辑精简总数: {domain_covered + ip_covered}",
        "# ----------------------------------------------------------",
        ""
    ]
    
    if cover_logs:
        log_lines.extend(cover_logs)
    else:
        log_lines.append("# 无包含去重记录")
    
    with open(AUDIT_LOG_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(log_lines))
    
    # 输出摘要
    print(f"\n[{get_beijing_time()}] 处理完成!")
    print(f"  原始规则: {len(all_rules)}")
    print(f"  完全相同去重: {exact_dup}")
    print(f"  域名包含去重: {domain_covered}")
    print(f"  IP网段包含去重: {ip_covered}")
    print(f"  最终保留: {len(final_rules)}")
    print(f"    - DOMAIN: {type_counts['DOMAIN']}")
    print(f"    - DOMAIN-SUFFIX: {type_counts['DOMAIN-SUFFIX']}")
    print(f"    - IP-CIDR: {type_counts['IP-CIDR']}")
    print(f"\n  输出: {OUTPUT_FILE}, {AUDIT_LOG_FILE}")

if __name__ == "__main__":
    main()
