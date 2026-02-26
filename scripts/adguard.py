#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AGH 规则合并去重工具 | 深度监控全功能版
特点：保留完整头部信息统计，引入 O(n*L) 级去重算法，支持过滤明细追踪
"""

import requests
import time
from datetime import datetime, timedelta
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# --- 基础配置 ---
AGH_RULE_URLS = [
    "https://adrules.top/dns.txt",
    "https://anti-ad.net/easylist.txt",
]
AGH_RULE_NAMES = ["adrules", "anti-ad"]
AGH_OUTPUT_FILE = "adguard.txt"
REMOVED_LOG_FILE = "adguard.log"
SUBSCRIBE_URL = "https://w-1349.github.io/scripts/adguard.txt"
TIMEOUT = 30

def create_retry_session():
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session

def fetch_remote_content(url, source_name):
    start = time.time()
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
        resp = create_retry_session().get(url, headers=headers, timeout=TIMEOUT)
        resp.raise_for_status()
        content = resp.text
        lines = content.splitlines()
        print(f"  [✓] 同步完成: {source_name:<10} | 耗时: {time.time()-start:>5.2f}s | 原始规模: {len(lines):>6} 行")
        return content, len(lines)
    except Exception as e:
        print(f"  [✗] 同步失败: {source_name:<10} | 错误: {type(e).__name__}")
        return "", 0

def apply_containment_dedup(rules, rule_type="规则"):
    if not rules:
        return [], []
    
    start_time = time.time()
    processed = []
    for r in rules:
        domain = r.split('$')[0].replace('||', '').replace('@@', '').replace('^', '').lower()
        if domain:
            processed.append((domain, r))
    
    # 核心：按域名层级排序
    processed.sort(key=lambda x: x[0].count('.'))
    
    final_rules = []
    seen_domains = set()
    removed_details = [] 
    
    for dom, original in processed:
        is_subdomain = False
        parts = dom.split('.')
        for i in range(len(parts) - 1, 0, -1):
            parent = ".".join(parts[i:])
            if parent in seen_domains:
                is_subdomain = True
                removed_details.append(f"[{rule_type}] {original:<45} # 父域覆盖: {parent}")
                break
        
        if not is_subdomain:
            final_rules.append(original)
            seen_domains.add(dom)
    
    print(f"  [✂] {rule_type}过滤: 缩减 {len(removed_details):>6} 条 | 耗时: {time.time()-start_time:.4f}s")
    return final_rules, removed_details

def main():
    main_start = time.time()
    source_stats_list = []
    total_raw_line = 0
    total_skip = 0
    all_raw_rules = []

    print("="*80 + "\n📦 开始处理【所有AGH规则源】\n" + "="*80)

    # 1. 拉取与初步统计
    for url, name in zip(AGH_RULE_URLS, AGH_RULE_NAMES):
        content, raw_line_count = fetch_remote_content(url, name)
        total_raw_line += raw_line_count
        
        valid = []
        skip_count = 0
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith(('!', '#')):
                skip_count += 1
                continue
            valid.append(line)
        
        total_skip += skip_count
        # 统计黑白名单
        black = sum(1 for r in valid if r.startswith("||"))
        white = sum(1 for r in valid if r.startswith("@@"))
        
        stats = {
            "name": name, "raw_line": raw_line_count, "skip": skip_count,
            "total_rule": len(valid), "black": black, "white": white, "other": len(valid)-black-white
        }
        source_stats_list.append(stats)
        all_raw_rules.extend(valid)

    # 2. 全局基础去重
    unique_rules = list(dict.fromkeys(all_raw_rules))
    cross_dedup = len(all_raw_rules) - len(unique_rules)

    # 3. 逻辑分类
    white_list = [r for r in unique_rules if r.startswith("@@")]
    black_list = [r for r in unique_rules if r.startswith("||")]
    other_list = [r for r in unique_rules if not (r.startswith("@@") or r.startswith("||"))]

    # 4. 高级算法包含去重
    print(f"\n[阶段 2] 正在分析域名包含关系...")
    white_final, white_removed = apply_containment_dedup(white_list, "白名单")
    black_final, black_removed = apply_containment_dedup(black_list, "黑名单")

    # 5. 构建生成文件
    final_rules = white_final + black_final + other_list
    beijing_time = (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')
    
    # 组装头部注释 (还原你的风格)
    source_stats_lines = [
        f"#   {i+1}. {s['name']} | 总规则数：{s['total_rule']} 条 | 黑名单：{s['black']} 条 | 白名单：{s['white']} 条 | 其他：{s['other']} 条"
        for i, s in enumerate(source_stats_list)
    ]
    
    header = [
        f"# AGH规则合并",
        f"# 生成时间（北京时间）: {beijing_time}",
        f"# 订阅地址：{SUBSCRIBE_URL}",
        f"# ==============================================================================",
        f"# 【各规则源单独统计】",
        *source_stats_lines,
        f"# ==============================================================================",
        f"# 【全局合并统计】",
        f"# 原始总行数：{total_raw_line} 条 | 跳过无效行：{total_skip} 条",
        f"# 跨源重复去重数：{cross_dedup} 条",
        f"# 包含去重统计：白名单去除 {len(white_removed)} 条 | 黑名单去除 {len(black_removed)} 条",
        f"# 最终全局保留总数：{len(final_rules)} 条",
        f"# ==============================================================================",
        f""
    ]

    # 6. 持久化存储
    with open(AGH_OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header + final_rules))

    with open(REMOVED_LOG_FILE, 'w', encoding='utf-8') as f:
        f.write(f"# AGH 过滤明细日志 - {beijing_time}\n" + "="*80 + "\n")
        f.write('\n'.join(white_removed + black_removed))

    # 7. 控制台最终大报告
    print("\n" + "="*80)
    print(f"✅ 处理完成！生成文件：{AGH_OUTPUT_FILE}")
    print(f"📊 最终保留总数：{len(final_rules)} 条")
    print(f"🕒 总耗时：{time.time() - main_start:.2f} 秒")
    print(f"📑 详细过滤明细已记录至：{REMOVED_LOG_FILE}")
    print("="*80)

if __name__ == "__main__":
    main()
