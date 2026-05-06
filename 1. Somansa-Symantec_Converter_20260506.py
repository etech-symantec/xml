import re
import os
import json
import csv
import urllib.parse
import tkinter as tk
from tkinter import filedialog
from datetime import datetime
import sys
import subprocess
import ipaddress
import collections

# --- 필수 외부 라이브러리 자동 확인 및 설치 ---
def check_dependencies():
    required_packages = {'colorama'}
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            print(f"\n[!] 필수 라이브러리 '{package}'가 설치되어 있지 않습니다.")
            print(f"[*] 자동으로 설치를 진행합니다. 잠시만 기다려주세요...\n")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                print(f"\n[*] '{package}' 설치가 완료되었습니다!\n")
            except Exception as e:
                print(f"\n[X] '{package}' 자동 설치 중 오류가 발생했습니다.")
                print(f"명령 프롬프트(cmd)를 열고 다음 명령어를 직접 실행해 주세요: pip install {package}")
                input("\n엔터(Enter) 키를 누르면 종료됩니다...")
                sys.exit(1)

check_dependencies()
from colorama import init, Fore, Style

# 색상 초기화
init(autoreset=True)

# --- 네이밍 컨벤션 포맷터 ---
def format_obj_name(name, prefix='a'):
    if not name: return f"{prefix}_Unknown"
    name = str(name).replace(" ", "_").replace("(", "").replace(")", "")
    if not re.match(r'^[a-zA-Z]', name):
        name = prefix + name
    return name

# --- XML 특수문자 변환 ---
def escape_xml(text):
    if not text: return ""
    text = text.replace("&", "&amp;")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    text = text.replace('"', "&quot;")
    text = text.replace("'", "&apos;")
    return text

def escape_xml_reverse(text):
    if not text: return ""
    return text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"').replace("&apos;", "'")

def get_col_attrs(name, col_id):
    if name.upper() == "ANY": name = "Any"
    if name.upper() == "NONE": name = "None"
    name_esc = escape_xml(name)
    
    if col_id == "ac":
        t = "String" if name == "None" else "Condition"
    elif col_id == "co" or name in ("Any", "None"):
        t = "String"
    else:
        t = "Condition"
        
    if t == "Condition":
        return f'name="{name_esc}" negate="false" type="{t}"'
    return f'name="{name_esc}" type="{t}"'

def ip_to_tuple(ip_str):
    base = ip_str.split('/')[0].split('-')[0].strip()
    try:
        return tuple(int(x) for x in base.split('.'))
    except:
        return (255, 255, 255, 255)

def normalize_ip_range(ip_str):
    if '-' in ip_str:
        parts = ip_str.split('-')
        if len(parts) == 2:
            start_ip = parts[0].strip()
            end_ip = parts[1].strip()
            try:
                s_tup = tuple(int(x) for x in start_ip.split('.'))
                e_tup = tuple(int(x) for x in end_ip.split('.'))
                if len(s_tup) == 4 and len(e_tup) == 4:
                    if s_tup > e_tup:
                        start_ip, end_ip = end_ip, start_ip
                        s_tup, e_tup = e_tup, s_tup
                    if s_tup[:3] == e_tup[:3]:
                        if (s_tup[3] == 0 and e_tup[3] == 255) or \
                           (s_tup[3] == 1 and e_tup[3] == 254):
                            return f"{'.'.join(map(str, s_tup[:3]))}.0/24"
                    return f"{start_ip}-{end_ip}"
            except:
                pass
    return ip_str

def is_private_ip(ip_str, internal_nets):
    try:
        ip_obj = None
        if '-' in ip_str:
            start_ip_str = ip_str.split('-')[0].strip()
            m = re.search(r'\d+\.\d+\.\d+\.\d+', start_ip_str)
            if m: ip_obj = ipaddress.ip_address(m.group(0))
        elif '/' in ip_str:
            m = re.search(r'\d+\.\d+\.\d+\.\d+', ip_str)
            if m: ip_obj = ipaddress.ip_address(m.group(0))
        else:
            m = re.search(r'\d+\.\d+\.\d+\.\d+', ip_str)
            if m: ip_obj = ipaddress.ip_address(m.group(0))
            
        if ip_obj:
            for net in internal_nets:
                if ip_obj in net:
                    return True
        return False
    except:
        return False

def is_ip_format(ip_str):
    return bool(re.match(r'^[\d\.\-\/\s]+$', ip_str))

def clean_url_trailing_tuple(u):
    u = str(u).strip()
    u = re.sub(r'\([\d,\s~()]+\)\s*$', '', u)
    return u.strip('*').strip()

def is_path_only(url_val_str):
    # [수정] http://. 로 시작하는 것도 Path로 간주하여 분기 처리되도록 설정
    if url_val_str.startswith('http://.'):
        return True
    if url_val_str.startswith('/'):
        return True
    if not re.search(r'\.[a-zA-Z]{2,4}(?:/|$)', url_val_str) and re.search(r'\.(cgi|js|php|css|html|htm)$', url_val_str, re.IGNORECASE):
        return True
    return False

def generate_a_url_xml(obj_name, url_val, is_regex=False):
    url_val_str = str(url_val).strip()
    
    # [추가] http://. 로 시작하는 경우 Advanced Path 객체로 변환
    if url_val_str.startswith('http://.'):
        clean_path = url_val_str[8:]
        return f'<a-url name="{escape_xml(obj_name)}" p="{escape_xml(clean_path)}" p-t="contains" typ="r"/>'
    
    if is_path_only(url_val_str):
        clean_path = url_val_str[1:] if url_val_str.startswith('/') else url_val_str
        return f'<a-url name="{escape_xml(obj_name)}" p="{escape_xml(clean_path)}" p-t="contains" typ="r"/>'
        
    has_regex_char = any(c in url_val_str for c in ['*', '^', '$', '[', ']', '|', '\\', '(', ')'])
    if is_regex or has_regex_char:
        return f'<a-url r="{escape_xml(url_val_str)}" name="{escape_xml(obj_name)}" typ="r"/>'
        
    m = re.match(r'^(?:https?://)?([^:/]+):(\d+)(/.*)?$', url_val_str, re.IGNORECASE)
    if m:
        host = m.group(1)
        port = m.group(2)
        path = m.group(3) if m.group(3) else ""
        if path.startswith('/'):
            path = path[1:]
        return f'<a-url f-p="{port}" h="{escape_xml(host)}" h-t="contains" name="{escape_xml(obj_name)}" p="{escape_xml(path)}" p-t="contains" typ="r"/>'
    
    return f'<a-url d="{escape_xml(url_val_str)}" name="{escape_xml(obj_name)}" typ="r"/>'

def auto_detect_internal_network(input_data):
    target_outer_regex = re.compile(r'<Target>(.*?)(?:<Target/>|</Target>)', re.IGNORECASE | re.DOTALL)
    target_regex = re.compile(r'define\s+Target\s+["\'“”](.*?)["\'“”](.*?)end\s+Target', re.IGNORECASE | re.DOTALL)
    
    ip_counts = collections.Counter()
    
    for outer_match in target_outer_regex.finditer(input_data):
        for match in target_regex.finditer(outer_match.group(1)):
            ips = [line.strip() for line in match.group(2).split('\n') if line.strip() and not line.startswith('<') and not line.startswith('define') and not line.startswith('end')]
            for ip_str in ips:
                ip_part = ip_str.split()[0]
                ip_part = ip_part.split('-')[0].split('/')[0].strip()
                m = re.match(r'^(\d+)\.\d+\.\d+\.\d+$', ip_part)
                if m:
                    first_octet = m.group(1)
                    ip_counts[first_octet] += 1
                    
    if ip_counts:
        most_common_octet, _ = ip_counts.most_common(1)[0]
        return f"{most_common_octet}.0.0.0/8"
    return ""

def strip_neg_silent(val):
    v = str(val).strip().strip('"\'').strip()
    v = re.sub(r'(?i)^ANY,\s*', '', v).strip()
    m = re.match(r'(?i)^negate\s*:\s*(.*)', v)
    v = m.group(1).strip() if m else v
    v = re.sub(r'\s+/', '/', v) 
    return v

# --- HTML 뷰어용 포맷팅 헬퍼 ---
def format_rules_to_html(node, depth=0):
    if not node: return ""
    if "condition" in node and "rules" in node:
        cond = node["condition"].upper()
        cond_color = "#e74c3c" if cond == "OR" else "#2980b9"
        cond_html = f'<div style="color:{cond_color}; font-weight:bold; margin: 3px 0; font-size:10px;">[{cond}]</div>'
        
        rules_html_list = []
        for r in node["rules"]:
            res = format_rules_to_html(r, depth+1)
            if res: rules_html_list.append(res)
        
        if not rules_html_list: return ""
        if len(rules_html_list) == 1: return rules_html_list[0]
        
        indent = "margin-left: 6px; border-left: 2px solid #ecf0f1; padding-left: 6px;" if depth > 0 else ""
        joined = cond_html.join([f"<div>{rh}</div>" for rh in rules_html_list])
        return f'<div style="{indent}">{joined}</div>'
        
    elif "id" in node:
        rid = node.get("id", "").replace("http:", "")
        op = node.get("operator", "")
        val = str(node.get("value", ""))
        if op == "wildcard" and val == "*":
            return ""
        return f'<div style="background:#f1f2f6; padding:2px 5px; border-radius:3px; font-size:10px; border:1px solid #dcdde1; display:inline-block; margin-bottom:2px; word-break:break-all;"><b>{rid}</b> <span style="color:#7f8c8d;">{op}</span> <span style="color:#c0392b;">{escape_xml(val)}</span></div>'
    return ""

def format_address_group(addrs_list, group_dict):
    res = []
    for addr in addrs_list:
        if addr in group_dict and group_dict[addr]:
            items = group_dict[addr]
            if ("Custom_category" in addr or "Category" in addr) and len(items) >= 27000:
                continue
                
            if len(items) == 1:
                res.append(f"<div style='margin-bottom:3px;'><span style='font-weight:bold; color:#2c3e50;'>{escape_xml(items[0])}</span></div>")
            else:
                display_items = items[:100]
                items_text = "\n".join([escape_xml(i) for i in display_items])
                if len(items) > 100:
                    items_text += f"\n\n... 외 {len(items)-100}개 항목 생략됨 (렉 방지)"
                
                summary_title = addr
                res.append(f"<details><summary style='cursor:pointer; font-weight:bold; color:#2c3e50;'>{escape_xml(summary_title)} <span style='font-size:10px; color:#7f8c8d;'>({len(items)})</span></summary><div style='margin:4px 0 6px 0; padding: 5px; background: #f8f9fa; border: 1px solid #ddd; max-height: 120px; overflow-y: auto; font-size:10px; color:#555; white-space: pre-wrap; word-break: break-all;'>{items_text}</div></details>")
        else:
            res.append(f"<div style='margin-bottom:3px; font-weight:bold; color:#2c3e50;'>{escape_xml(addr)}</div>")
    return "".join(res)

def flatten_sym_group(obj_name, group_map, visited=None):
    if visited is None: visited = set()
    if obj_name in visited: return []
    visited.add(obj_name)
    
    if obj_name not in group_map:
        return [obj_name]
    
    res = []
    for child in group_map[obj_name]:
        res.extend(flatten_sym_group(child, group_map, visited))
    return res

def get_sym_obj_html(obj_name, group_map):
    if obj_name == "Any": return "Any"
    
    items = get_flat_sym_items(obj_name, group_map)
    if ("Custom_category" in obj_name or "Category" in obj_name) and len(items) >= 27000:
        return ""
        
    def is_req_url(n):
        nl = n.lower()
        return "requesturl" in nl or "_path" in nl or "_url" in nl
        
    def build_sym_tree_html(node_name, visited):
        if node_name in visited:
            return ""
        visited.add(node_name)
        
        if node_name not in group_map:
            return f"<div style='margin-bottom:2px; font-size:11px; font-weight:bold; color:#2c3e50; word-break:break-all;'>{escape_xml(node_name)}</div>"
            
        children = group_map[node_name]
        n = node_name.lower()
        
        if len(children) == 1 and children[0] not in group_map:
            if is_req_url(node_name):
                return f"<div style='margin-bottom:3px;'><span style='font-weight:bold; color:#2c3e50;'>{escape_xml(children[0])}</span></div>"
            else:
                return f"<div style='margin-bottom:3px;'><span style='font-weight:bold; color:#2c3e50;'>{escape_xml(children[0])}</span> <span style='font-size:9px; color:#7f8c8d; background:#eaf2f8; padding:2px 4px; border-radius:3px;'>Obj: {escape_xml(node_name)}</span></div>"
        
        is_root_like = "combined" in n or "category" in n
        open_attr = "open" if is_root_like else ""
        
        res = f"<details {open_attr} style='margin-bottom:2px;'><summary style='cursor:pointer; font-weight:bold; color:#2980b9; font-size:11px;'>{escape_xml(node_name)} <span style='font-size:9px; color:#7f8c8d;'>({len(children)})</span></summary>"
        res += f"<div style='margin-left: 10px; border-left: 2px solid #bdc3c7; padding-left: 8px; margin-top: 3px;'>"
        
        all_leaves = all(c not in group_map for c in children)
        if all_leaves:
            display_items = children[:100]
            items_text = "\n".join([escape_xml(i) for i in display_items])
            if len(children) > 100:
                items_text += f"\n\n... 외 {len(children)-100}개 항목 생략됨"
            res += f"<div style='font-size:10px; color:#333; white-space: pre-wrap; word-break: break-all;'>{items_text}</div>"
        else:
            for child in children:
                res += build_sym_tree_html(child, visited.copy())
                
        res += "</div></details>"
        return res

    html = build_sym_tree_html(obj_name, set())
    return html if html else f"<div style='margin-bottom:3px; font-weight:bold; color:#2980b9;'>{escape_xml(obj_name)}</div>"

def get_flat_sym_items(name, group_map):
    if name == "Any": return []
    items = flatten_sym_group(name, group_map)
    clean_items = []
    for i in items:
        clean_i = i
        if clean_i.startswith("s_IP_"): clean_i = clean_i[5:]
        elif clean_i.startswith("d_IP_"): clean_i = clean_i[5:]
        elif clean_i.startswith("s_"): clean_i = clean_i[2:]
        elif clean_i.startswith("d_"): clean_i = clean_i[2:]
        clean_items.append(clean_i)
    return sorted(list(dict.fromkeys(clean_items)))

def get_obj_details(xml_str, obj_type):
    m_name = re.search(r'name="([^"]+)"', xml_str)
    if not m_name:
        m_name = re.search(r'\bn="([^"]+)"', xml_str)
    name = m_name.group(1).replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"').replace("&apos;", "'") if m_name else "Unknown"
    
    content = ""
    if obj_type == "IP 단일/범위 객체":
        m = re.search(r'value="([^"]+)"', xml_str)
        if m: content = m.group(1)
    elif obj_type == "다중 IP List 객체":
        m = re.search(r'l="([^"]+)"', xml_str)
        if m: content = m.group(1)
    elif obj_type == "Host-Port 객체":
        m = re.search(r'val="([^"]+)"', xml_str)
        if m: content = m.group(1)
    elif obj_type in ("Request URL 객체", "기타 a-url 객체"):
        m_url = re.search(r'url="([^"]+)"', xml_str)
        m_d = re.search(r'd="([^"]+)"', xml_str)
        m_p = re.search(r'p="([^"]+)"', xml_str)
        m_r = re.search(r'r="([^"]+)"', xml_str)
        m_h = re.search(r'h="([^"]+)"', xml_str)
        if m_url: content = m_url.group(1)
        elif m_r: content = "Regex: " + m_r.group(1)
        elif m_d: content = m_d.group(1)
        elif m_p: 
            parts = []
            if m_h: parts.append("Domain: " + m_h.group(1))
            parts.append("Path: " + m_p.group(1))
            content = " / ".join(parts)
        elif m_h: 
            content = "Domain: " + m_h.group(1)
        else:
            content = "Unknown URL Type"
    elif obj_type == "Http Header 객체":
        m_h = re.search(r'h="([^"]+)"', xml_str)
        m_v = re.search(r'v="([^"]+)"', xml_str)
        m_f = re.search(r'f="([^"]+)"', xml_str)
        h = m_h.group(1) if m_h else ""
        v = m_v.group(1) if m_v else ""
        f = m_f.group(1) if m_f else ""
        content = f"{h}: {v} ({f})"
    elif obj_type == "카테고리 Node 객체":
        m = re.search(r'u-l="([^"]+)"', xml_str)
        if m: content = m.group(1).replace("&#10;", ", ")
    elif obj_type == "Combined 객체":
        m = re.findall(r'n="([^"]+)"', xml_str)
        inner_names = [x for x in m if x != name]
        content = ", ".join(inner_names)
    elif obj_type == "Category List 객체":
        m = re.findall(r'<i>([^<]+)</i>', xml_str)
        content = ", ".join(m)
        
    content = content.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"').replace("&apos;", "'")
    return [obj_type, name, content]


# =====================================================================
# [2번 파일 생성 데이터] 소만사 정책 요약 JSON 추출
# 기능: 입력된 소만사 원본 텍스트(.txt)를 분석하여 정책별로 JSON 형태로 요약하여 반환합니다.
# 이 데이터는 이후 "2. Somansa_policy_summary_YYYYMMDD.json" 파일로 저장됩니다.
# =====================================================================
def extract_policy_to_json(input_data, skip_auto_update=False):
    def process_val_for_json(val):
        v = str(val).strip().strip('"\'').strip()
        v = re.sub(r'(?i)^ANY,\s*', '', v).strip()
        m = re.match(r'(?i)^negate\s*:\s*(.*)', v)
        v = m.group(1).strip() if m else v
        v = re.sub(r'\s+/', '/', v) 
        if v.startswith("http://."): v = v[8:]
        v = clean_url_trailing_tuple(v)
        return v
        
    group_dict = {}
    
    target_outer_regex = re.compile(r'<Target>(.*?)(?:<Target/>|</Target>)', re.IGNORECASE | re.DOTALL)
    target_regex = re.compile(r'define\s+Target\s+["\'“”](.*?)["\'“”](.*?)end\s+Target', re.IGNORECASE | re.DOTALL)
    for outer_match in target_outer_regex.finditer(input_data):
        for match in target_regex.finditer(outer_match.group(1)):
            name = match.group(1).strip()
            ips = [line.strip() for line in match.group(2).split('\n') if line.strip() and not line.startswith('<') and not line.startswith('define') and not line.startswith('end')]
            group_dict[name] = [re.sub(r'\s+all', '', process_val_for_json(ip), flags=re.IGNORECASE).strip() for ip in ips]

    webcat_outer_regex = re.compile(r'<userdefinedurl>(.*?)(?:<userdefinedurl/>|</userdefinedurl>)', re.IGNORECASE | re.DOTALL)
    webcat_regex = re.compile(r'define\s+webcategory\s+["\'“”](.*?)["\'“”](.*?)end\s+webcategory', re.IGNORECASE | re.DOTALL)
    for outer_match in webcat_outer_regex.finditer(input_data):
        for match in webcat_regex.finditer(outer_match.group(1)):
            name = match.group(1).strip()
            if skip_auto_update and name == "Auto_Update_Blacklist_Deny":
                continue
            urls = [process_val_for_json(urllib.parse.unquote(line.strip())) for line in match.group(2).split('\n') if line.strip() and not line.startswith('<') and not line.startswith('define') and not line.startswith('end')]
            group_dict[name] = list(dict.fromkeys(urls))

    policies = []
    policy_regex = re.compile(r'define\s+Policy\s+["\'“”](.*?)["\'“”](.*?)end\s+policy', re.IGNORECASE | re.DOTALL)
    
    def get_flat_som_items(names, g_dict):
        res = []
        for n in names:
            if n.upper() == "ANY": continue
            if n in g_dict and g_dict[n]:
                res.extend(g_dict[n])
            else:
                res.append(n)
        return sorted(list(dict.fromkeys(res)))
    
    for match in policy_regex.finditer(input_data):
        p_body = match.group(2)
        
        name_m = re.search(r'name=(.*?)\s+(?:prioirty|priority)=', p_body, re.IGNORECASE)
        prio_m = re.search(r'(?:prioirty|priority)=(.*?)\s+activated=', p_body, re.IGNORECASE)
        act_m = re.search(r'activated=(.*?)\s+', p_body, re.IGNORECASE)
        http_type_m = re.search(r'http-type=(.*?)\s+', p_body, re.IGNORECASE)
        action_m = re.search(r'action\s+value=(.*?)\s+', p_body, re.IGNORECASE)
        block_msg_m = re.search(r'block-message\s+value=(.*?)\s+', p_body, re.IGNORECASE)
        
        p_name = name_m.group(1).strip() if name_m else match.group(1).strip()
        priority = prio_m.group(1).strip() if prio_m else ""
        activated = act_m.group(1).strip() if act_m else ""
        http_type = http_type_m.group(1).strip() if http_type_m else ""
        action_val = action_m.group(1).strip() if action_m else ""
        block_msg = block_msg_m.group(1).strip() if block_msg_m else ""
        
        active_match = re.search(r'activeDate=(\d{4}-\d{2}-\d{2})\s+\d{2}:\d{2}:\d{2}', p_body, re.IGNORECASE)
        expire_match = re.search(r'expireDate=(\d{4}-\d{2}-\d{2})\s+\d{2}:\d{2}:\d{2}', p_body, re.IGNORECASE)
        time_val = "Any"
        if active_match and expire_match:
            time_val = f"{active_match.group(1)} ~ {expire_match.group(1)}"
        
        inbound_names = []
        outbound_names = []
        dir_blocks = re.split(r'(?i)address\s+direction=', p_body)
        for d_block in dir_blocks[1:]:
            dir_m = re.match(r'^\s*(\w+)', d_block)
            if not dir_m: continue
            direction = dir_m.group(1).lower()
            for line in d_block.splitlines()[1:]:
                line = line.strip()
                if not line: continue
                name_match = re.match(r'(?i)^(?:address|adress)\s+name=(.*)', line)
                if name_match:
                    val = process_val_for_json(name_match.group(1))
                    if direction == 'inbound': inbound_names.append(val)
                    elif direction == 'outbound': outbound_names.append(val)
                else: break
        
        user_cat_m = re.search(r'userDefinedCategory\s+name=(.*)', p_body, re.IGNORECASE)
        if user_cat_m: outbound_names.append(process_val_for_json(user_cat_m.group(1)))
        
        web_cat_ids_raw = re.findall(r'web-category-id\s+value=(.*)', p_body, re.IGNORECASE)
        web_cat_ids = [process_val_for_json(c) for c in web_cat_ids_raw if c.strip() and process_val_for_json(c).upper() != "ANY"]
        
        web_url_list_m = re.search(r'webUrlList:\s*(.*)', p_body, re.IGNORECASE)
        if web_url_list_m:
            raw_urls = web_url_list_m.group(1).strip()
            if raw_urls:
                urls = [process_val_for_json(u) for u in raw_urls.split(',') if u.strip()]
                outbound_names.extend(urls)
                if web_cat_ids:
                    web_cat_ids.pop(0) 

        outbound_names.extend(web_cat_ids)
        outbound_names = list(dict.fromkeys(outbound_names))
        
        rules_str = ""
        rules_html = ""
        rules_list = []
        
        for line in p_body.splitlines():
            line = line.strip()
            if line.lower().startswith("policyhttprules="):
                json_str = line[len("policyHttpRules="):].strip()
                if not json_str: break
                last_brace = json_str.rfind("}")
                if last_brace != -1:
                    json_str = json_str[:last_brace+1]
                try:
                    j_data = json.loads(json_str)
                    rules_html = format_rules_to_html(j_data)
                    def extract_rules(node):
                        if "condition" in node and "rules" in node:
                            for r in node["rules"]:
                                extract_rules(r)
                        elif "id" in node:
                            val = process_val_for_json(node.get("value", ""))
                            op = node.get("operator", "")
                            rid = node.get("id", "")
                            if op == "wildcard" and val == "*": return
                            if val:
                                rules_list.append(f"{rid} ({op}: {val})")
                    extract_rules(j_data)
                    rules_str = ", ".join(rules_list)
                except:
                    rules_str = "JSON Parsing Error"
                    rules_html = "JSON Parsing Error"
                break
        
        policy_data = {
            "name": p_name,
            "priority": priority,
            "activated": activated,
            "http-type": http_type,
            "time": time_val,
            "inbound_address": ", ".join(inbound_names),
            "outbound_address": ", ".join(outbound_names),
            "policyHttpRules": rules_str,
            "action": action_val,
            "block-message": block_msg,
            "_inbound_html": format_address_group(inbound_names, group_dict),
            "_outbound_html": format_address_group(outbound_names, group_dict),
            "_rules_html": rules_html,
            "_inbound_flat": get_flat_som_items(inbound_names, group_dict),
            "_outbound_flat": get_flat_som_items(outbound_names, group_dict)
        }
        policies.append(policy_data)
        
    return policies

# =====================================================================
# [3번 파일 생성] 소만사 원본 정책 검토 HTML 뷰어
# 기능: 추출된 소만사 정책 JSON 데이터를 사용자가 브라우저에서 확인할 수 있는 UI로 만듭니다.
# "3. Somansa_policy_viewer_YYYYMMDD.html" 파일 생성에 사용됩니다.
# =====================================================================
def generate_html_viewer(json_data, output_path):
    tabs_data = []
    current_group_id = 0
    for item in json_data:
        if "통과" in item.get('action', ''):
            current_group_id += 1
            tabs_data.append({"id": current_group_id, "name": item.get('name', 'Unknown')})
            
    tabs_html = f'<select id="sectionSelect" onchange="if(this.value) scrollToGroup(this.value)" style="width: 300px; padding: 6px 15px; border: 1px solid #3498db; border-radius: 20px; font-size: 12px; font-weight: bold; color: #2980b9; cursor: pointer; box-shadow: 0 2px 4px rgba(0,0,0,0.05); outline: none;">\n'
    tabs_html += '<option value="">🎯 빠르게 이동할 구분선(통과 정책) 선택</option>\n'
    for t in tabs_data:
        tabs_html += f'<option value="{t["id"]}">▶ {escape_xml(t["name"])}</option>\n'
    tabs_html += '</select>\n'

    html_content = f"""<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>소만사 원본 정책 검토 뷰어</title>
    <style>
        body {{ font-family: 'Malgun Gothic', 'Apple SD Gothic Neo', sans-serif; margin: 0; background-color: #f4f7f6; color: #333; overflow: hidden; }}
        .top-section {{ padding: 10px 20px; background-color: #f4f7f6; box-shadow: 0 2px 5px rgba(0,0,0,0.05); z-index: 100; position: sticky; top:0;}}
        h2 {{ text-align: center; color: #2c3e50; margin: 0 0 10px 0; font-size: 18px; }}
        .controls {{ display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 15px; background: #fff; padding: 10px 15px; border-radius: 6px; border: 1px solid #e0e0e0; margin-bottom: 8px; }}
        .search-box {{ flex: 1; min-width: 250px; }}
        .search-box input {{ width: 100%; padding: 8px 10px; border: 1px solid #ccc; border-radius: 4px; font-size: 12px; box-sizing: border-box; transition: border-color 0.3s; }}
        .search-box input:focus {{ border-color: #3498db; outline: none; }}
        .col-toggles {{ display: flex; gap: 6px; flex-wrap: wrap; font-size: 11px; align-items: center; }}
        .col-toggles b {{ margin-right: 5px; color: #555; }}
        .col-toggles label {{ cursor: pointer; user-select: none; background: #ecf0f1; padding: 4px 8px; border-radius: 15px; transition: all 0.2s; border: 1px solid #dcdde1; }}
        .col-toggles label:hover {{ background: #e0e6ed; }}
        .col-toggles input[type="checkbox"] {{ margin-right: 3px; cursor: pointer; vertical-align: middle; }}
        .tabs-wrapper {{ display: flex; align-items: center; justify-content: center; gap: 15px; margin-top: 5px; flex-wrap: wrap; }}
        #paginationControls button {{ padding: 4px 12px; margin: 0 3px; border: 1px solid #3498db; background: #fff; color: #3498db; border-radius: 15px; cursor: pointer; font-size: 11px; font-weight: bold; transition: 0.2s; }}
        #paginationControls button:hover:not(:disabled) {{ background: #3498db; color: #fff; }}
        #paginationControls button:disabled {{ border-color: #bdc3c7; color: #bdc3c7; cursor: not-allowed; }}
        .page-info {{ margin: 0 10px; font-size: 12px; font-weight: bold; color: #2c3e50; }}
        .expand-btn, .collapse-btn {{ padding: 4px 10px; cursor: pointer; border: 1px solid #7f8c8d; background: #fff; color: #7f8c8d; border-radius: 12px; font-size: 10px; transition: 0.2s; margin-bottom:2px; }}
        .expand-btn:hover, .collapse-btn:hover {{ background: #7f8c8d; color: #fff; }}
        .rule-filter-btn {{ padding: 4px 10px; cursor: pointer; border: 1px solid #e74c3c; background: #fff; color: #e74c3c; border-radius: 12px; font-size: 10px; transition: 0.2s; margin-bottom:2px; font-weight: bold; }}
        .rule-filter-btn:hover {{ background: #e74c3c; color: #fff; }}
        .rule-filter-btn.active {{ background: #e74c3c; color: #fff; }}
        .table-container {{ height: calc(100vh - 150px); overflow-y: auto; overflow-x: hidden; margin: 0 20px 20px 20px; border: 1px solid #e0e0e0; box-shadow: 0 0 10px rgba(0,0,0,0.05); background: #fff; scroll-behavior: smooth; }}
        table {{ width: 100%; border-collapse: collapse; table-layout: fixed; }}
        th, td {{ border: 1px solid #e0e0e0; padding: 6px 8px; text-align: left; font-size: 10px !important; word-break: break-all; overflow-wrap: break-word; vertical-align: top; }}
        th {{ background-color: #34495e; color: white; position: sticky; top: 0; z-index: 10; font-size: 11px !important; box-shadow: 0 2px 2px -1px rgba(0,0,0,0.1); }}
        tr:hover td {{ background-color: #f1f2f6; }}
        .paginate-item {{ content-visibility: auto; contain-intrinsic-size: auto 40px; }}
        .hidden-by-search {{ display: none !important; }}
        .hidden-by-page {{ display: none !important; }}
        .hidden-by-collapse {{ display: none !important; }}
        .row-deny td {{ background-color: #fff5f5 !important; }}
        .row-deny:hover td {{ background-color: #ffe0e0 !important; }}
        .row-allow td {{ background-color: #f0fff4 !important; }}
        .row-allow:hover td {{ background-color: #dcfce7 !important; }}
        .pass-divider td {{ background-color: #2c3e50 !important; color: #ecf0f1 !important; border: none !important; border-top: 4px solid #fff !important; cursor: pointer; font-size: 12px !important; font-weight: bold; }}
        .pass-divider:hover td {{ background-color: #34495e !important; }}
        .toggle-icon {{ display: inline-block; width: 12px; text-align: center; color: #ecf0f1; font-weight: bold; font-size: 10px; margin-right: 4px; pointer-events: none; }}
        .chk-review {{ transform: scale(1.3); cursor: pointer; margin: 0 auto; display: block; }}
        .checked-row td {{ background-color: #e9ecef !important; color: #a0a0a0 !important; text-decoration: line-through; border-color:#e0e0e0 !important;}}
        .checked-row summary, .checked-row span {{ color: #a0a0a0 !important; }}
        .action-allow {{ color: #2980b9; font-weight: bold; }}
        .action-deny {{ color: #c0392b; font-weight: bold; }}
        .hide-col-4 .col-4 {{ display: none !important; }}
        .hide-col-1 .col-1 {{ display: none !important; }}
        .hide-col-2 .col-2 {{ display: none !important; }}
        .hide-col-3 .col-3 {{ display: none !important; }}
        .hide-col-5 .col-5 {{ display: none !important; }}
        .hide-col-6 .col-6 {{ display: none !important; }}
        .hide-col-7 .col-7 {{ display: none !important; }}
        .hide-col-8 .col-8 {{ display: none !important; }}
        .hide-col-9 .col-9 {{ display: none !important; }}
        .hide-col-10 .col-10 {{ display: none !important; }}
        .highlight-flash td {{ background-color: #fff3cd !important; transition: background-color 0.5s ease; }}
        ::-webkit-scrollbar {{ width: 8px; height: 8px;}}
        ::-webkit-scrollbar-track {{ background: #f1f1f1; border-radius:4px; }}
        ::-webkit-scrollbar-thumb {{ background: #c1c1c1; border-radius: 4px; }}
        ::-webkit-scrollbar-thumb:hover {{ background: #a8a8a8; }}
    </style>
</head>
<body>
    <div class="top-section">
        <h2>🔍 소만사 원본 정책 검토 뷰어</h2>
        <div class="controls">
            <div class="search-box">
                <input type="text" id="searchInput" onkeyup="filterTable()" placeholder="🔍 테이블 전체 내용 통합 검색 (정책명, IP, 조건 등)...">
            </div>
            <div class="col-toggles">
                <b>표시 항목:</b>
                <label><input type="checkbox" checked onchange="toggleCol(2)"> 상태</label>
                <label><input type="checkbox" checked onchange="toggleCol(3)"> 우선순위</label>
                <label><input type="checkbox" onchange="toggleCol(4)"> 타입</label> 
                <label><input type="checkbox" checked onchange="toggleCol(5)"> 정책명</label>
                <label><input type="checkbox" checked onchange="toggleCol(6)"> 출발지</label>
                <label><input type="checkbox" checked onchange="toggleCol(7)"> 목적지</label>
                <label><input type="checkbox" checked onchange="toggleCol(8)"> 탐지 조건</label>
                <label><input type="checkbox" checked onchange="toggleCol(9)"> 액션</label>
                <label><input type="checkbox" checked onchange="toggleCol(10)"> 차단 메시지</label>
            </div>
        </div>
        <div class="tabs-wrapper">
            {tabs_html}
            <div style="display:flex; align-items:center; gap:5px; margin-left: 10px;">
                <input type="number" id="goToInput" placeholder="No." style="width:60px; padding:6px 10px; border:1px solid #3498db; border-radius:20px; font-size:12px; outline:none; text-align:center;" onkeypress="if(event.key==='Enter') goToNo()">
                <button onclick="goToNo()" style="padding: 6px 12px; border: 1px solid #3498db; background: #fff; color: #3498db; border-radius: 15px; cursor: pointer; font-size: 11px; font-weight: bold; transition: 0.2s;">이동</button>
            </div>
            <div id="paginationControls" style="display: flex; align-items: center; margin-left: 10px;"></div>
            <div style="white-space: nowrap; display: flex; gap: 5px; margin-left: 10px; align-items:center;">
                <button id="filterRulesBtn" class="rule-filter-btn" onclick="toggleRuleFilter()">🚨 탐지 조건 모아보기</button>
                <button class="expand-btn" onclick="expandAll()">전체 펼치기</button>
                <button class="collapse-btn" onclick="collapseAll()">전체 접기</button>
            </div>
        </div>
    </div>
    <div class="table-container">
        <table id="policyTable" class="hide-col-4">
            <thead>
                <tr>
                    <th class="col-1" style="width: 35px; text-align: center;">검토</th>
                    <th class="col-2" style="width: 5%;">상태</th>
                    <th class="col-3" style="width: 6%;">우선순위</th>
                    <th class="col-4" style="width: 5%;">타입</th>
                    <th class="col-5" style="width: 15%;">정책명 (Name)</th>
                    <th class="col-6" style="width: 14%;">출발지 (Inbound)</th>
                    <th class="col-7" style="width: 14%;">목적지 (Outbound)</th>
                    <th class="col-8" style="width: 21%;">탐지 조건 (Rules)</th>
                    <th class="col-9" style="width: 5%;">액션</th>
                    <th class="col-10" style="width: 10%;">차단 메시지</th>
                </tr>
            </thead>
"""
    current_group_id = 0
    for idx, som in enumerate(json_data):
        raw_action = som.get('action', '')
        action_val_escaped = escape_xml(raw_action)
        is_allow = ("허용" in raw_action or "Allow" in raw_action)
        is_deny = ("차단" in raw_action or "Deny" in raw_action)
        is_pass = ("통과" in raw_action)
        if is_pass:
            current_group_id += 1
            html_content += f"""
            <tbody class="paginate-item pass-divider" id="group-header-{current_group_id}" data-row="{idx+1}" onclick="toggleSection({current_group_id}, event)" title="클릭하여 하위 정책 접기/펼치기">
                <tr><td colspan="10"><span class="toggle-icon" id="icon-{current_group_id}">▶</span> {escape_xml(som.get('name', ''))}</td></tr>
            </tbody>
            """
        else:
            row_cls = ""
            if is_allow: row_cls = "row-allow"
            elif is_deny: row_cls = "row-deny"
            action_class = "action-deny" if is_deny else ("action-allow" if is_allow else "")
            hidden_cls = " hidden-by-collapse" if current_group_id > 0 else ""
            
            html_content += f"""
            <tbody class="paginate-item group-item group-item-{current_group_id}{hidden_cls}" id="policy-row-{idx+1}" data-row="{idx+1}">
                <tr class="{row_cls}">
                    <td class="col-1" style="text-align: center; vertical-align: middle;">
                        <div style="font-size:8px; color:#94a3b8; margin-bottom:2px;">No.{idx+1}</div>
                        <input type="checkbox" class="chk-review" onclick="event.stopPropagation(); this.closest('tr').classList.toggle('checked-row')">
                    </td>
                    <td class="col-2">{escape_xml(som.get('activated', ''))}</td>
                    <td class="col-3">{escape_xml(som.get('priority', ''))}</td>
                    <td class="col-4">{escape_xml(som.get('http-type', ''))}</td>
                    <td class="col-5"><b>{escape_xml(som.get('name', ''))}</b></td>
                    <td class="col-6" onclick="event.stopPropagation();">{som.get('_inbound_html', '')}</td>
                    <td class="col-7" onclick="event.stopPropagation();">{som.get('_outbound_html', '')}</td>
                    <td class="col-8">{som.get('_rules_html', '')}</td>
                    <td class="col-9 {action_class}">{action_val_escaped}</td>
                    <td class="col-10">{escape_xml(som.get('block-message', ''))}</td>
                </tr>
            </tbody>
            """
    html_content += """
        </table>
    </div>
    <script>
        let currentPage = 1;
        let itemsPerPage = 50;
        let allItems = [];
        let filterTimeout;
        let ruleFilterActive = false;

        document.addEventListener("DOMContentLoaded", () => {
            allItems = Array.from(document.querySelectorAll('.paginate-item'));
            applyPagination();
        });

        function goToNo() {
            const no = document.getElementById('goToInput').value;
            if (!no) return;
            let target = document.getElementById('policy-row-' + no) || document.querySelector(`[data-row="${no}"]`);
            if (target) {
                if (document.getElementById('searchInput').value !== '') {
                    document.getElementById('searchInput').value = '';
                    filterTable();
                    setTimeout(() => scrollToTarget(target), 350);
                } else {
                    scrollToTarget(target);
                }
            } else {
                alert('해당 번호(' + no + ')의 정책을 찾을 수 없습니다.');
            }
        }

        function scrollToTarget(target) {
            if (target.classList.contains('hidden-by-collapse')) {
                const match = target.className.match(/group-item-(\\d+)/);
                if (match) {
                    const groupId = match[1];
                    const rows = document.querySelectorAll('.group-item-' + groupId);
                    rows.forEach(r => r.classList.remove('hidden-by-collapse'));
                    const icon = document.getElementById('icon-' + groupId);
                    if(icon) icon.textContent = '▼';
                }
            }

            const visibleItems = allItems.filter(item => !item.classList.contains('hidden-by-search'));
            const idx = visibleItems.indexOf(target);
            if (idx > -1) {
                currentPage = Math.floor(idx / itemsPerPage) + 1;
                applyPagination();
                
                setTimeout(() => {
                    const container = document.querySelector(".table-container");
                    const targetRect = target.getBoundingClientRect();
                    const containerRect = container.getBoundingClientRect();
                    const theadHeight = document.querySelector('thead').offsetHeight || 40;
                    
                    container.scrollBy({
                        top: targetRect.top - containerRect.top - theadHeight - 10,
                        behavior: 'smooth'
                    });
                    
                    target.classList.add('highlight-flash');
                    setTimeout(() => { target.classList.remove('highlight-flash'); }, 2000);
                }, 50);
            }
        }

        function toggleRuleFilter() {
            ruleFilterActive = !ruleFilterActive;
            const btn = document.getElementById("filterRulesBtn");
            if (ruleFilterActive) {
                btn.classList.add("active");
                btn.textContent = "탐지 조건 모아보기 해제";
                itemsPerPage = 99999; 
                expandAll(); 
            } else {
                btn.classList.remove("active");
                btn.textContent = "🚨 탐지 조건 모아보기";
                itemsPerPage = 50; 
            }
            filterTable();
        }

        function filterTable() {
            clearTimeout(filterTimeout);
            filterTimeout = setTimeout(() => {
                const input = document.getElementById("searchInput").value.toLowerCase();
                
                allItems.forEach(item => {
                    let text = item.textContent || item.innerText;
                    let matchSearch = text.toLowerCase().indexOf(input) > -1;
                    let matchRule = true;
                    
                    if (ruleFilterActive) {
                        if (item.classList.contains('pass-divider')) {
                            matchRule = false;
                        } else {
                            const ruleCol = item.querySelector('.col-8');
                            if (ruleCol && !ruleCol.textContent.trim()) {
                                matchRule = false;
                            }
                        }
                    }

                    if (matchSearch && matchRule) {
                        item.classList.remove('hidden-by-search');
                    } else {
                        item.classList.add('hidden-by-search');
                    }
                });
                
                currentPage = 1;
                applyPagination();
            }, 300);
        }

        function applyPagination() {
            const visibleItems = allItems.filter(item => !item.classList.contains('hidden-by-search'));
            const totalPages = Math.ceil(visibleItems.length / itemsPerPage) || 1;
            if (currentPage > totalPages) currentPage = totalPages;
            
            const start = (currentPage - 1) * itemsPerPage;
            const end = start + itemsPerPage;
            
            visibleItems.forEach((item, idx) => {
                if (idx >= start && idx < end) {
                    item.classList.remove('hidden-by-page');
                } else {
                    item.classList.add('hidden-by-page');
                }
            });
            
            renderPaginationUI(visibleItems.length, totalPages);
        }

        function renderPaginationUI(totalItems, totalPages) {
            const ui = document.getElementById("paginationControls");
            if(!ui) return;
            
            if (ruleFilterActive || totalPages <= 1) {
                ui.innerHTML = `<span class="page-info">현재 ${totalItems}개 표시 중</span>`;
                return;
            }
            
            let html = `<button onclick="changePage(1)" ${currentPage === 1 ? 'disabled' : ''}>&laquo; 처음</button>`;
            html += `<button onclick="changePage(${currentPage - 1})" ${currentPage === 1 ? 'disabled' : ''}>&lsaquo; 이전</button>`;
            html += `<span class="page-info">페이지 ${currentPage} / ${totalPages} (총 ${totalItems}개)</span>`;
            html += `<button onclick="changePage(${currentPage + 1})" ${currentPage === totalPages ? 'disabled' : ''}>다음 &rsaquo;</button>`;
            html += `<button onclick="changePage(${totalPages})" ${currentPage === totalPages ? 'disabled' : ''}>마지막 &raquo;</button>`;
            
            ui.innerHTML = html;
        }

        function changePage(page) {
            currentPage = page;
            applyPagination();
            document.querySelector('.table-container').scrollTop = 0;
        }

        function toggleCol(colIdx) {
            document.getElementById("policyTable").classList.toggle('hide-col-' + colIdx);
        }
        
        function toggleSection(groupId, event) {
            if (event && (event.target.tagName.toLowerCase() === 'input' || event.target.tagName.toLowerCase() === 'details' || event.target.tagName.toLowerCase() === 'summary')) return;
            const icon = document.getElementById('icon-' + groupId);
            const rows = document.querySelectorAll('.group-item-' + groupId);
            if (rows.length === 0) return;
            
            const isCurrentlyHidden = rows[0].classList.contains('hidden-by-collapse');
            rows.forEach(r => {
                if (isCurrentlyHidden) {
                    r.classList.remove('hidden-by-collapse');
                } else {
                    r.classList.add('hidden-by-collapse');
                }
            });
            if (icon) icon.textContent = isCurrentlyHidden ? '▼' : '▶';
        }
        
        function scrollToGroup(groupId) {
            const target = document.getElementById("group-header-" + groupId);
            if (target) {
                const visibleItems = allItems.filter(item => !item.classList.contains('hidden-by-search'));
                const idx = visibleItems.indexOf(target);
                if (idx > -1) {
                    currentPage = Math.floor(idx / itemsPerPage) + 1;
                    applyPagination();
                    
                    setTimeout(() => {
                        const container = document.querySelector(".table-container");
                        const targetRect = target.getBoundingClientRect();
                        const containerRect = container.getBoundingClientRect();
                        const theadHeight = document.querySelector('thead').offsetHeight || 40;
                        container.scrollBy({
                            top: targetRect.top - containerRect.top - theadHeight - 10,
                            behavior: 'smooth'
                        });
                    }, 50);
                } else {
                    document.getElementById("searchInput").value = "";
                    filterTable();
                    setTimeout(() => scrollToGroup(groupId), 350);
                }
                document.getElementById("sectionSelect").value = "";
            }
        }
        
        function expandAll() {
            document.querySelectorAll('.group-item').forEach(r => r.classList.remove('hidden-by-collapse'));
            document.querySelectorAll('.toggle-icon').forEach(icon => icon.textContent = '▼');
        }
        
        function collapseAll() {
            document.querySelectorAll('.group-item').forEach(r => r.classList.add('hidden-by-collapse'));
            document.querySelectorAll('.toggle-icon').forEach(icon => icon.textContent = '▶');
        }
    </script>
</body>
</html>
"""
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

def normalize_action(act):
    a = str(act).strip().lower()
    if "허용" in a or "allow" in a: return "allow"
    if "차단" in a or "deny" in a: return "deny"
    if "통과" in a or "pass" in a: return "pass"
    return a

# 가짜 Diff 방지를 위한 완벽한 평탄화 비교 함수 (대소문자, 슬래시, 와일드카드, 정규화, 중복 무시)
def clean_flat(flat_list):
    s = set()
    for x in flat_list:
        v = str(x).strip()
        if v.upper() not in ("ANY", "NONE", ""):
            v = normalize_ip_range(v)
            v = re.sub(r'\s+', ' ', v).lower()
            v = v.rstrip('/')
            v = v.strip('*')
            s.add(v)
    return s

# =====================================================================
# [8번 파일 생성] 소만사 vs 시만텍 1:1 비교 검증 HTML 뷰어
# 기능: 변환 전(소만사 JSON)과 변환 후(시만텍 JSON)를 양옆에 나란히 배치하고,
# 정규화된 목적지/출발지 값을 비교하여 다를 경우 붉은색 테두리(Diff)로 경고를 표시합니다.
# "8. Somansa_Symantec_policy_viewer_YYYYMMDD.html" 파일 생성에 사용됩니다.
# =====================================================================
def generate_comparison_viewer(somansa_json, symantec_json, output_path):
    sym_dict = {item.get('_somansa_name', ''): item for item in symantec_json}
    
    tabs_data = []
    current_group_id = 0
    for item in somansa_json:
        if "통과" in item.get('action', ''):
            current_group_id += 1
            tabs_data.append({"id": current_group_id, "name": item.get('name', 'Unknown')})
            
    tabs_html = f'<select id="sectionSelect" onchange="if(this.value) scrollToGroup(this.value)" style="width: 300px; padding: 6px 15px; border: 1px solid #3498db; border-radius: 20px; font-size: 12px; font-weight: bold; color: #2980b9; cursor: pointer; box-shadow: 0 2px 4px rgba(0,0,0,0.05); outline: none;">\n'
    tabs_html += '<option value="">🎯 빠르게 이동할 구분선(통과 정책) 선택</option>\n'
    for t in tabs_data:
        tabs_html += f'<option value="{t["id"]}">▶ {escape_xml(t["name"])}</option>\n'
    tabs_html += '</select>\n'
    
    html_content = f"""<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>정책 변환 1:1 비교 검증 뷰어</title>
    <style>
        body {{ font-family: 'Malgun Gothic', 'Apple SD Gothic Neo', sans-serif; margin: 0; background-color: #f4f7f6; color: #333; overflow: hidden; }}
        .top-section {{ padding: 15px 20px; background-color: #fff; box-shadow: 0 2px 8px rgba(0,0,0,0.08); z-index: 100; position: sticky; top: 0;}}
        h2 {{ text-align: center; color: #2c3e50; margin: 0 0 15px 0; font-size: 20px; }}
        .search-box {{ display: flex; justify-content: center; margin-bottom: 10px; }}
        .search-box input {{ width: 50%; min-width: 300px; padding: 10px 15px; border: 1px solid #ccc; border-radius: 20px; font-size: 13px; box-shadow: inset 0 1px 3px rgba(0,0,0,0.05); outline: none; transition: 0.3s; }}
        .search-box input:focus {{ border-color: #3498db; box-shadow: 0 0 5px rgba(52, 152, 219, 0.3); }}
        .tabs-wrapper {{ display: flex; justify-content: center; align-items: flex-start; gap: 15px; margin-top: 5px; }}
        #paginationControls button {{ padding: 4px 12px; margin: 0 3px; border: 1px solid #3498db; background: #fff; color: #3498db; border-radius: 15px; cursor: pointer; font-size: 11px; font-weight: bold; transition: 0.2s; }}
        #paginationControls button:hover:not(:disabled) {{ background: #3498db; color: #fff; }}
        #paginationControls button:disabled {{ border-color: #bdc3c7; color: #bdc3c7; cursor: not-allowed; }}
        .page-info {{ margin: 0 10px; font-size: 12px; font-weight: bold; color: #2c3e50; }}
        .table-container {{ height: calc(100vh - 140px); overflow-y: auto; overflow-x: hidden; padding: 0 20px 20px 20px; box-sizing: border-box; scroll-behavior: smooth; }}
        table {{ width: 100%; border-collapse: collapse; table-layout: fixed; background: #fff; box-shadow: 0 0 10px rgba(0,0,0,0.05); }}
        th, td {{ border: 1px solid #e0e0e0; padding: 8px 10px; text-align: left; font-size: 11px; word-break: break-all; overflow-wrap: break-word; vertical-align: middle; }}
        th {{ background-color: #34495e; color: white; position: sticky; top: 0; z-index: 10; font-size: 12px; }}
        .paginate-item {{ content-visibility: auto; contain-intrinsic-size: auto 120px; transition: background-color 0.2s; }}
        .pass-divider {{ content-visibility: auto; contain-intrinsic-size: auto 40px; }}
        .hidden-by-search {{ display: none !important; }}
        .hidden-by-page {{ display: none !important; }}
        .policy-group:hover td {{ background-color: #f9fbfd !important; }}
        .somansa-row td {{ background-color: #ffffff; }}
        .symantec-row td {{ background-color: #f4f8fb; border-bottom: 2px solid #bdc3c7; }}
        .pass-divider td {{ background-color: #2c3e50 !important; color: #ecf0f1 !important; border: none; font-size: 13px; font-weight: bold; border-top: 4px solid #fff; }}
        .chk-review {{ transform: scale(1.3); cursor: pointer; margin: 0 auto; display: block; }}
        .checked-group {{ content-visibility: visible; }} 
        .checked-group .symantec-row {{ display: none; }}
        .checked-group .somansa-row td {{ background-color: #e9ecef !important; color: #a0a0a0 !important; text-decoration: line-through; border-color:#e0e0e0 !important; padding: 4px 10px; }}
        .checked-group .badge {{ opacity: 0.4; filter: grayscale(100%); }}
        .diff-cell {{ border: 2px solid #e74c3c !important; background-color: #fff9f9 !important; }}
        .badge {{ padding: 3px 6px; border-radius: 3px; font-weight: bold; font-size: 10px; color: #fff; text-align: center; display: inline-block; width: 60px; }}
        .badge.somansa {{ background-color: #e67e22; }}
        .badge.symantec {{ background-color: #2980b9; }}
        .highlight-allow {{ color: #27ae60; font-weight: bold; }}
        .highlight-deny {{ color: #c0392b; font-weight: bold; }}
        .highlight-pass {{ color: #8e44ad; font-weight: bold; }}
        .highlight-flash td {{ background-color: #fff3cd !important; transition: background-color 0.5s ease; }}
        ::-webkit-scrollbar {{ width: 8px; height: 8px;}}
        ::-webkit-scrollbar-track {{ background: #f1f1f1; border-radius:4px; }}
        ::-webkit-scrollbar-thumb {{ background: #c1c1c1; border-radius: 4px; }}
        ::-webkit-scrollbar-thumb:hover {{ background: #a8a8a8; }}
    </style>
</head>
<body>
    <div class="top-section">
        <h2>🔍 정책 변환 1:1 비교 검증 뷰어 (Somansa vs Symantec)</h2>
        <div class="search-box">
            <input type="text" id="searchInput" onkeyup="filterTable()" placeholder="검색어를 입력하세요 (정책명, IP, 카테고리 등)...">
        </div>
        <div class="tabs-wrapper">
            {tabs_html}
            <div style="display:flex; align-items:center; gap:5px; margin-left: 10px;">
                <input type="number" id="goToInput" placeholder="No." style="width:60px; padding:6px 10px; border:1px solid #3498db; border-radius:20px; font-size:12px; outline:none; text-align:center;" onkeypress="if(event.key==='Enter') goToNo()">
                <button onclick="goToNo()" style="padding: 6px 12px; border: 1px solid #3498db; background: #fff; color: #3498db; border-radius: 15px; cursor: pointer; font-size: 11px; font-weight: bold; transition: 0.2s;">이동</button>
            </div>
            <div id="paginationControls" style="display: flex; align-items: center; margin-left: 10px;"></div>
        </div>
    </div>
    
    <div class="table-container">
        <table id="compTable">
            <thead>
                <tr>
                    <th style="width: 40px; text-align: center;">검토</th>
                    <th style="width: 40px; text-align: center;">No.</th>
                    <th style="width: 80px; text-align: center;">구분</th>
                    <th style="width: 14%;">정책명 / Track (Layer)</th>
                    <th style="width: 5%;">상태</th>
                    <th style="width: 11%;">출발지 (Source)</th>
                    <th style="width: 11%;">목적지 (Destination)</th>
                    <th style="width: 17%;">조건 (Rules / Service)</th>
                    <th style="width: 10%;">기간 (Time)</th>
                    <th style="width: 5%;">액션</th>
                    <th style="width: 9%;">차단 메시지</th>
                </tr>
            </thead>
"""
    current_group_id = 0
    for idx, som in enumerate(somansa_json):
        som_act_raw = som.get('action', '')
        is_pass = "통과" in som_act_raw
        if is_pass:
            current_group_id += 1
            html_content += f"""
            <tbody id="group-header-{current_group_id}" class="paginate-item pass-divider" data-row="{idx+1}">
                <tr>
                    <td colspan="11">▶ {escape_xml(som.get('name', ''))}</td>
                </tr>
            </tbody>
            """
        else:
            sym = sym_dict.get(som.get('name', ''), {})
            sym_act_raw = sym.get('Action', '')
            som_act = escape_xml(som_act_raw)
            sym_act = escape_xml(sym_act_raw)

            som_blk_raw = som.get('block-message', '')
            sym_blk_raw = sym.get('Block Message', '')
            if "허용" in som_act_raw or "allow" in som_act_raw.lower():
                som_blk_raw = ""
            if "allow" in sym_act_raw.lower() or "허용" in sym_act_raw.lower():
                sym_blk_raw = ""
            
            som_blk = escape_xml(som_blk_raw)
            sym_blk = escape_xml(sym_blk_raw)

            som_cls = "highlight-allow" if "허용" in som_act else "highlight-deny"
            sym_cls = "highlight-allow" if "Allow" in sym_act else ("highlight-deny" if "Deny" in sym_act else "")
            if "None" in sym_act: sym_cls = ""

            diff_src = "diff-cell" if clean_flat(som.get('_inbound_flat', [])) != clean_flat(sym.get('_source_flat', [])) else ""
            diff_dest = "diff-cell" if clean_flat(som.get('_outbound_flat', [])) != clean_flat(sym.get('_dest_flat', [])) else ""
            
            som_cond_val = str(som.get('policyHttpRules', '')).strip()
            sym_cond_val = str(sym.get('Service', '')).strip()
            is_cond_diff = True
            if som_cond_val == sym_cond_val:
                is_cond_diff = False
            elif not som_cond_val and sym_cond_val.lower() == 'any':
                is_cond_diff = False
            diff_cond = "diff-cell" if is_cond_diff else ""
            
            som_time_raw = som.get('time', 'Any')
            sym_time_raw = sym.get('Time', 'Any')
            som_time = escape_xml(som_time_raw)
            sym_time = escape_xml(sym_time_raw)
            
            is_time_diff = True
            if som_time_raw == "Any" and sym_time_raw == "Any":
                is_time_diff = False
            elif som_time_raw != "Any" and sym_time_raw != "Any":
                som_date_str = som_time_raw.replace(" ~ ", "_")
                if som_date_str in sym_time_raw:
                    is_time_diff = False
            diff_time = "diff-cell" if is_time_diff else ""
            
            diff_act = "diff-cell" if normalize_action(som_act_raw) != normalize_action(sym_act_raw) else ""
            diff_blk = "diff-cell" if str(som_blk_raw).strip() != str(sym_blk_raw).strip() else ""

            html_content += f"""
            <tbody id="policy-row-{idx+1}" class="paginate-item policy-group group-item-{current_group_id} hidden-by-collapse" data-row="{idx+1}">
                <tr class="somansa-row">
                    <td rowspan="2" style="text-align: center; vertical-align: middle; border-right:1px solid #e0e0e0;">
                        <input type="checkbox" class="chk-review" onchange="toggleReview(this)">
                    </td>
                    <td rowspan="2" style="text-align: center; font-weight: bold; font-size: 13px; color:#555;">{idx+1}</td>
                    <td style="text-align: center;"><span class="badge somansa">Somansa</span></td>
                    <td><b>{escape_xml(som.get('name', ''))}</b></td>
                    <td>{escape_xml(som.get('activated', ''))}</td>
                    <td class="{diff_src}">{som.get('_inbound_html', '')}</td>
                    <td class="{diff_dest}">{som.get('_outbound_html', '')}</td>
                    <td class="{diff_cond}">{som.get('_rules_html', '')}</td>
                    <td class="{diff_time}" style="font-size: 9px; text-align: center;">{som_time}</td>
                    <td class="{diff_act} {som_cls}">{som_act}</td>
                    <td class="{diff_blk}">{som_blk}</td>
                </tr>
                <tr class="symantec-row">
                    <td style="text-align: center;"><span class="badge symantec">Symantec</span></td>
                    <td><b>{escape_xml(sym.get('Track', ''))}</b><br><span style="font-size:9px; color:#7f8c8d;">({escape_xml(sym.get('Layer', ''))})</span></td>
                    <td>{escape_xml(sym.get('Enabled', ''))}</td>
                    <td class="{diff_src}">{sym.get('_source_html', escape_xml(sym.get('Source', '')))}</td>
                    <td class="{diff_dest}">{sym.get('_dest_html', escape_xml(sym.get('Destination', '')))}</td>
                    <td class="{diff_cond}">{escape_xml(sym.get('Service', ''))}</td>
                    <td class="{diff_time}" style="font-size: 9px; text-align: center;">{sym_time}</td>
                    <td class="{diff_act} {sym_cls}">{sym_act}</td>
                    <td class="{diff_blk}">{sym_blk}</td>
                </tr>
            </tbody>
            """
        
    html_content += """
        </table>
    </div>
    <script>
        let currentPage = 1;
        const itemsPerPage = 50;
        let allItems = [];
        let filterTimeout;

        document.addEventListener("DOMContentLoaded", () => {
            allItems = Array.from(document.querySelectorAll('.paginate-item'));
            applyPagination();
        });

        function goToNo() {
            const no = document.getElementById('goToInput').value;
            if (!no) return;
            let target = document.getElementById('policy-row-' + no) || document.querySelector(`[data-row="${no}"]`);
            if (target) {
                if (document.getElementById('searchInput').value !== '') {
                    document.getElementById('searchInput').value = '';
                    filterTable();
                    setTimeout(() => scrollToTarget(target), 350);
                } else {
                    scrollToTarget(target);
                }
            } else {
                alert('해당 번호(' + no + ')의 정책을 찾을 수 없습니다.');
            }
        }

        function scrollToTarget(target) {
            if (target.classList.contains('hidden-by-collapse')) {
                const match = target.className.match(/group-item-(\\d+)/);
                if (match) {
                    const groupId = match[1];
                    const rows = document.querySelectorAll('.group-item-' + groupId);
                    rows.forEach(r => r.classList.remove('hidden-by-collapse'));
                    const icon = document.getElementById('icon-' + groupId);
                    if(icon) icon.textContent = '▼';
                }
            }
            const visibleItems = allItems.filter(item => !item.classList.contains('hidden-by-search'));
            const idx = visibleItems.indexOf(target);
            if (idx > -1) {
                currentPage = Math.floor(idx / itemsPerPage) + 1;
                applyPagination();
                
                setTimeout(() => {
                    const container = document.querySelector(".table-container");
                    const targetRect = target.getBoundingClientRect();
                    const containerRect = container.getBoundingClientRect();
                    const theadHeight = document.querySelector('thead').offsetHeight || 40;
                    
                    container.scrollBy({
                        top: targetRect.top - containerRect.top - theadHeight - 10,
                        behavior: 'smooth'
                    });
                    
                    target.classList.add('highlight-flash');
                    setTimeout(() => { target.classList.remove('highlight-flash'); }, 2000);
                }, 50);
            }
        }

        function toggleReview(chk) {
            const tbody = chk.closest('tbody');
            if (chk.checked) {
                tbody.classList.add('checked-group');
            } else {
                tbody.classList.remove('checked-group');
            }
        }
    
        function filterTable() {
            clearTimeout(filterTimeout);
            filterTimeout = setTimeout(() => {
                const input = document.getElementById("searchInput").value.toLowerCase();
                
                allItems.forEach(item => {
                    let text = item.textContent || item.innerText;
                    if (text.toLowerCase().indexOf(input) > -1) {
                        item.classList.remove('hidden-by-search');
                    } else {
                        item.classList.add('hidden-by-search');
                    }
                });
                
                currentPage = 1;
                applyPagination();
            }, 300);
        }
        
        function applyPagination() {
            const visibleItems = allItems.filter(item => !item.classList.contains('hidden-by-search'));
            const totalPages = Math.ceil(visibleItems.length / itemsPerPage) || 1;
            if (currentPage > totalPages) currentPage = totalPages;
            
            const start = (currentPage - 1) * itemsPerPage;
            const end = start + itemsPerPage;
            
            visibleItems.forEach((item, idx) => {
                if (idx >= start && idx < end) {
                    item.classList.remove('hidden-by-page');
                } else {
                    item.classList.add('hidden-by-page');
                }
            });
            
            renderPaginationUI(visibleItems.length, totalPages);
        }

        function renderPaginationUI(totalItems, totalPages) {
            const ui = document.getElementById("paginationControls");
            if(!ui) return;
            
            if (totalPages <= 1) {
                ui.innerHTML = `<span class="page-info">현재 ${totalItems}개 표시 중</span>`;
                return;
            }
            
            let html = `<button onclick="changePage(1)" ${currentPage === 1 ? 'disabled' : ''}>&laquo; 처음</button>`;
            html += `<button onclick="changePage(${currentPage - 1})" ${currentPage === 1 ? 'disabled' : ''}>&lsaquo; 이전</button>`;
            html += `<span class="page-info">페이지 ${currentPage} / ${totalPages} (총 ${totalItems}개)</span>`;
            html += `<button onclick="changePage(${currentPage + 1})" ${currentPage === totalPages ? 'disabled' : ''}>다음 &rsaquo;</button>`;
            html += `<button onclick="changePage(${totalPages})" ${currentPage === totalPages ? 'disabled' : ''}>마지막 &raquo;</button>`;
            
            ui.innerHTML = html;
        }

        function changePage(page) {
            currentPage = page;
            applyPagination();
            document.querySelector('.table-container').scrollTop = 0;
        }
        
        function toggleSection(groupId, event) {
            if (event && (event.target.tagName.toLowerCase() === 'input' || event.target.tagName.toLowerCase() === 'details' || event.target.tagName.toLowerCase() === 'summary')) return;
            const icon = document.getElementById('icon-' + groupId);
            const rows = document.querySelectorAll('.group-item-' + groupId);
            if (rows.length === 0) return;
            
            const isCurrentlyHidden = rows[0].classList.contains('hidden-by-collapse');
            rows.forEach(r => {
                if (isCurrentlyHidden) {
                    r.classList.remove('hidden-by-collapse');
                } else {
                    r.classList.add('hidden-by-collapse');
                }
            });
            if (icon) icon.textContent = isCurrentlyHidden ? '▼' : '▶';
        }
        
        function scrollToGroup(groupId) {
            const target = document.getElementById("group-header-" + groupId);
            if (target) {
                const visibleItems = allItems.filter(item => !item.classList.contains('hidden-by-search'));
                const idx = visibleItems.indexOf(target);
                if (idx > -1) {
                    currentPage = Math.floor(idx / itemsPerPage) + 1;
                    applyPagination();
                    
                    setTimeout(() => {
                        const container = document.querySelector(".table-container");
                        const targetRect = target.getBoundingClientRect();
                        const containerRect = container.getBoundingClientRect();
                        const theadHeight = document.querySelector('thead').offsetHeight || 40;
                        
                        container.scrollBy({
                            top: targetRect.top - containerRect.top - theadHeight - 10,
                            behavior: 'smooth'
                        });
                    }, 50);
                } else {
                    document.getElementById("searchInput").value = "";
                    filterTable();
                    setTimeout(() => scrollToGroup(groupId), 350);
                }
                document.getElementById("sectionSelect").value = "";
            }
        }
    </script>
</body>
</html>
"""
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

# =====================================================================
# [4, 5, 6, 7번 파일 생성 데이터] 소만사 -> 시만텍 XML 변환 및 데이터 통합 추출
# 기능:
#  - 4번 파일: 커스텀 차단 예외 페이지 모음 (HTML)
#  - 5번 파일: 시만텍 적용을 위한 VPM 기반 XML 변환 (메인 결과물)
#  - 6번 파일: 최적화(Deep GC)로 인해 제거된 미사용 객체 목록 (CSV)
#  - 7번 파일: 뷰어 대조를 위한 시만텍 정책 요약 (JSON)
# 이 데이터들은 하단 __main__ 실행부에서 각각의 파일로 저장됩니다.
# =====================================================================
def convert_somansa_to_symantec(input_data, mode, optimize_choice, internal_networks, skip_auto_update=False, unify_deny_choice='y'):
    
    # [복구] Scope Error(NameError) 방지를 위해 함수 최상단에 병합 객체 맵 선언
    combined_source_map = {}
    combined_dest_map = {}
    
    global_single_url_map = {}
    global_url_list_map = {}
    
    exception_tracked_list = []
    symantec_json_data = [] 
    symantec_group_map = {} 

    negated_items_log = []
    space_slash_log = []
    http_dot_log = []
    
    used_names_exact = set()
    
    def process_and_log_value(val, context_name, p_name=""):
        v = str(val).strip().strip('"\'').strip()
        v = re.sub(r'(?i)^ANY,\s*', '', v).strip()
        
        m = re.match(r'(?i)^negate\s*:\s*(.*)', v)
        if m:
            clean_val = m.group(1).strip()
            prefix = f"정책 [{p_name}]" if p_name else "객체"
            log_str = f"{prefix} - {context_name} : {clean_val} (원본: {v})"
            if log_str not in negated_items_log:
                negated_items_log.append(log_str)
            v = clean_val
            
        v_fixed = re.sub(r'\s+/', '/', v)
        if v_fixed != v:
            prefix = f"정책 [{p_name}]" if p_name else "객체"
            log_str = f"{prefix} - {context_name} : '{v}' -> '{v_fixed}'"
            if log_str not in space_slash_log:
                space_slash_log.append(log_str)
            v = v_fixed
            
        if v.startswith("http://."):
            prefix = f"정책 [{p_name}]" if p_name else "객체"
            log_str = f"{prefix} - {context_name} : '{v}' -> Path-only '{v[8:]}'(으)로 Advanced 자동 변환"
            if log_str not in http_dot_log:
                http_dot_log.append(log_str)
            v = v[8:]
            
        v = clean_url_trailing_tuple(v)
        return v

    node_name_counter = {}
    def get_unique_node_name(base_name):
        if base_name not in node_name_counter:
            node_name_counter[base_name] = 0
            return base_name
        else:
            node_name_counter[base_name] += 1
            return f"{base_name}_{node_name_counter[base_name]}"
            
    def process_url_list(urls, base_name_hint, target_list, force_category=False):
        if not urls: return
        if force_category:
            url_tuple = tuple(urls)
            if url_tuple in global_url_list_map:
                _, cat_list_name = global_url_list_map[url_tuple]
                target_list.append(cat_list_name)
            else:
                url_string = '&#10;'.join([escape_xml(u) for u in urls])
                cat_node_name = get_unique_node_name(base_name_hint)
                vpm_cat_nodes.append(f'<node n="{escape_xml(cat_node_name)}" u-l="{url_string}"/>')
                
                cat_tuple_group = (cat_node_name,)
                if cat_tuple_group not in category_list_map:
                    cat_list_name = format_obj_name(base_name_hint) if force_category else format_obj_name(f"{base_name_hint}_Cat")
                    category_list_map[cat_tuple_group] = cat_list_name
                    i_tags = f'<i>{escape_xml(cat_node_name)}</i>'
                    cat_xml = f'<categorylist4 name="{escape_xml(cat_list_name)}" typ="r">\n<sel>\n{i_tags}\n</sel>\n<excl/>\n<sel-p/>\n</categorylist4>'
                    category_list_objects.append(cat_xml)
                    symantec_group_map[cat_list_name] = [cat_node_name]
                    symantec_group_map[cat_node_name] = list(urls)
                else:
                    cat_list_name = category_list_map[cat_tuple_group]
                    
                global_url_list_map[url_tuple] = (cat_node_name, cat_list_name)
                target_list.append(cat_list_name)
        elif len(urls) == 1:
            url_val = urls[0]
            if url_val in global_single_url_map:
                obj_name = global_single_url_map[url_val]
            else:
                obj_name = get_unique_node_name(base_name_hint)
                global_single_url_map[url_val] = obj_name
                req_url_objects.append(generate_a_url_xml(obj_name, url_val))
                symantec_group_map[obj_name] = [url_val]
            target_list.append(obj_name)
        else:
            url_tuple = tuple(urls)
            if url_tuple in global_url_list_map:
                _, combo_name = global_url_list_map[url_tuple]
                target_list.append(combo_name)
            else:
                combo_name = get_unique_node_name(base_name_hint + "_urls")
                c_list_str_lines = []
                for i, url_val in enumerate(urls):
                    child_name = f"{combo_name}_{i+1}"
                    req_url_objects.append(generate_a_url_xml(child_name, url_val))
                    c_list_str_lines.append(f'<c-l-1 n="{escape_xml(child_name)}"/>')
                    symantec_group_map[child_name] = [url_val]
                c_list_str = '\n'.join(c_list_str_lines)
                comb_objects.append(f'<comb-obj name="{escape_xml(combo_name)}" d="" n-1="false" n-2="false" t="2">\n{c_list_str}\n</comb-obj>')
                global_url_list_map[url_tuple] = (combo_name, combo_name)
                symantec_group_map[combo_name] = list(urls)
                target_list.append(combo_name)
            
    vpm_cat_nodes = []
    ip_objects = []
    ip_list_objects = []  
    host_port_objects = [] 
    a_url_objects = []
    req_url_objects = []   
    req_hdr_objects = [] 
    policy_id_objects = []  
    time_objects = []
    dny_exc_objects = []  
    service_objects = []  
    http_req_objects = []
    category_list_objects = []
    comb_objects = []
    
    tls_row_items = []
    http_row_items = []
    req_row_items = []  
    custom_cat_row_items = [] 
    
    legacy_http_layers = []
    legacy_tls_layers = []
    current_http_layer = [None]
    current_tls_layer = [None]
    
    exception_pages_text = ""
    req_body_map = {}
    category_list_map = {}
    url_map = {}
    hdr_map = {}
    webcat_name_map = {} 
    
    comb_counter = {"1": 1, "2": 1, "3": 1}
    def get_comb_obj_name(t_val):
        prefix = "CombinedSource" if t_val == "1" else "CombinedDestination"
        name = f"{prefix}_{comb_counter[t_val]}"
        comb_counter[t_val] += 1
        return name

    block_msg_outer_regex = re.compile(r'<Block-message>(.*?)(?:<Block-message/>|</Block-message>)', re.IGNORECASE | re.DOTALL)
    for match in block_msg_outer_regex.finditer(input_data):
        raw_msg = match.group(1).strip()
        exception_pages_text += raw_msg + '\n\n'

    webcat_outer_regex = re.compile(r'<userdefinedurl>(.*?)(?:<userdefinedurl/>|</userdefinedurl>)', re.IGNORECASE | re.DOTALL)
    webcat_regex = re.compile(r'define\s+webcategory\s+["\'“”](.*?)["\'“”](.*?)end\s+webcategory', re.IGNORECASE | re.DOTALL)
    
    for outer_match in webcat_outer_regex.finditer(input_data):
        for match in webcat_regex.finditer(outer_match.group(1)):
            name = match.group(1).strip()
            
            if skip_auto_update and name == "Auto_Update_Blacklist_Deny":
                continue
                
            final_cat_name = format_obj_name(name)
            
            raw_urls = [line.strip() for line in match.group(2).split('\n')]
            valid_urls = list(dict.fromkeys([u for u in raw_urls if u and not u.startswith('<') and not u.startswith('define') and not u.startswith('end')]))

            if valid_urls:
                valid_urls = [process_and_log_value(u, f"WebCategory [{name}]") for u in valid_urls]
                
                path_only_urls = []
                domain_urls = []
                for u in valid_urls:
                    if is_path_only(u): path_only_urls.append(u)
                    else: domain_urls.append(u)
                
                cat_target_names = []
                force_cat = "Custom_category" not in name
                
                process_url_list(domain_urls, final_cat_name, cat_target_names, force_category=force_cat)
                process_url_list(path_only_urls, final_cat_name + "_path", cat_target_names, force_category=False)
                
                if len(cat_target_names) == 1:
                    webcat_name_map[name] = cat_target_names[0]
                elif len(cat_target_names) > 1:
                    combo_name = get_unique_node_name(final_cat_name + "_combined")
                    c_list_str = '\n'.join([f'<c-l-1 n="{escape_xml(c)}"/>' for c in cat_target_names])
                    comb_objects.append(f'<comb-obj name="{escape_xml(combo_name)}" d="" n-1="false" n-2="false" t="2">\n{c_list_str}\n</comb-obj>')
                    symantec_group_map[combo_name] = cat_target_names
                    webcat_name_map[name] = combo_name

    target_outer_regex = re.compile(r'<Target>(.*?)(?:<Target/>|</Target>)', re.IGNORECASE | re.DOTALL)
    target_regex = re.compile(r'define\s+Target\s+["\'“”](.*?)["\'“”](.*?)end\s+Target', re.IGNORECASE | re.DOTALL)
    
    raw_targets = {}
    for outer_match in target_outer_regex.finditer(input_data):
        for match in target_regex.finditer(outer_match.group(1)):
            name = match.group(1).strip()
            raw_ips = [line.strip() for line in match.group(2).split('\n')]
            if name.upper() == "ANY": continue
            
            cleaned_ips = []
            for ip in raw_ips:
                if not ip or ip.startswith('<') or ip.startswith('define') or ip.startswith('end'):
                    continue
                clean_ip = process_and_log_value(ip, f"Target [{name}]")
                cleaned_ips.append(clean_ip)
                
            raw_targets[name] = cleaned_ips

    target_src_map = {}
    target_dest_map = {}
    port_map = {}
    
    for t_name, raw_ips in raw_targets.items():
        ips_only = []
        ports_only = []
        
        for line in raw_ips:
            line = re.sub(r'\s+all', '', line, flags=re.IGNORECASE).strip()
            if not line:
                continue
                
            parts = line.split()
            ip_part = normalize_ip_range(parts[0])
            ips_only.append(ip_part)
            
            if len(parts) > 1 and parts[1].isdigit():
                ports_only.append(parts[1])
                
        ips_only = list(dict.fromkeys(ips_only))
        ports_only = list(dict.fromkeys(ports_only))
        
        src_objs = []
        dest_objs = []
        
        if "User_IP_Exception_ServerFarm" in t_name:
            actual_ips = [ip for ip in ips_only if is_ip_format(ip)]
            if actual_ips:
                if len(actual_ips) == 1:
                    base_name = f"s_IP_{actual_ips[0]}"
                    ip_objects.append(f'<ipobject name="{escape_xml(base_name)}" value="{escape_xml(actual_ips[0])}" single="true" type="1"/>')
                    symantec_group_map[base_name] = [actual_ips[0]]
                else:
                    base_name = format_obj_name(t_name, 's_')
                    ip_list_str = ",".join(actual_ips)
                    ip_list_objects.append(f'<ip-list-object name="{escape_xml(base_name)}" l="{escape_xml(ip_list_str)}" iseffective="false"/>')
                    symantec_group_map[base_name] = actual_ips
                src_objs.append(base_name)
                dest_objs.append(base_name)
                exception_tracked_list.append(f"[Type 1 강제 묶음] {t_name}")
        
        elif "Knox" in t_name or "Group_20180913" in t_name:
            actual_ips = [ip for ip in ips_only if is_ip_format(ip)]
            if actual_ips:
                combo_name = format_obj_name(t_name, 'd_')
                knox_obj_names = []
                for ip in actual_ips:
                    knox_ip_name = f"d_IP_{ip}"
                    ip_objects.append(f'<ipobject name="{escape_xml(knox_ip_name)}" value="{escape_xml(ip)}" single="true" type="2"/>')
                    symantec_group_map[knox_ip_name] = [ip]
                    knox_obj_names.append(knox_ip_name)
                
                if len(knox_obj_names) == 1:
                    dest_objs.append(knox_obj_names[0])
                    src_objs.append(knox_obj_names[0])
                else:
                    unique_knox_names = list(dict.fromkeys(knox_obj_names))
                    c_list_str = '\n'.join([f'<c-l-1 n="{escape_xml(item)}"/>' for item in unique_knox_names])
                    comb_objects.append(f'<comb-obj name="{escape_xml(combo_name)}" d="" n-1="false" n-2="false" t="2">\n{c_list_str}\n</comb-obj>')
                    symantec_group_map[combo_name] = unique_knox_names
                    dest_objs.append(combo_name)
                    src_objs.append(combo_name)
                exception_tracked_list.append(f"[Type 2 개별 및 Combined 변환] {t_name}")
                    
        else:
            priv_ips = []
            pub_ips = []
            domain_urls = []
            path_only_urls = []
            
            for ip in ips_only:
                if ip == "1.1.1.1":
                    priv_ips.append(ip)
                    pub_ips.append(ip)
                elif is_ip_format(ip):
                    if is_private_ip(ip, internal_networks):
                        priv_ips.append(ip)
                    else:
                        pub_ips.append(ip)
                else:
                    if is_path_only(ip):
                        path_only_urls.append(ip)
                    else:
                        domain_urls.append(ip)
                    
            if priv_ips:
                if len(priv_ips) == 1:
                    formatted_ip = priv_ips[0]
                    ip_obj_name = f"s_IP_{formatted_ip}"
                    ip_objects.append(f'<ipobject name="{escape_xml(ip_obj_name)}" value="{escape_xml(formatted_ip)}" single="true" type="1"/>')
                    symantec_group_map[ip_obj_name] = [formatted_ip]
                else:
                    base_name = t_name if not pub_ips and not domain_urls else f"{t_name}_PrivIP"
                    ip_obj_name = format_obj_name(base_name, 's_')
                    ip_list_str = ",".join(priv_ips)
                    ip_list_objects.append(f'<ip-list-object name="{escape_xml(ip_obj_name)}" l="{escape_xml(ip_list_str)}" iseffective="false"/>')
                    symantec_group_map[ip_obj_name] = priv_ips
                src_objs.append(ip_obj_name)
                    
            if pub_ips:
                if len(pub_ips) == 1:
                    formatted_ip = pub_ips[0]
                    pub_obj_name = f"d_IP_{formatted_ip}"
                    ip_objects.append(f'<ipobject name="{escape_xml(pub_obj_name)}" value="{escape_xml(formatted_ip)}" single="true" type="2"/>')
                    symantec_group_map[pub_obj_name] = [formatted_ip]
                else:
                    base_name = t_name if not priv_ips and not domain_urls else f"{t_name}_PubIP"
                    pub_obj_name = format_obj_name(base_name, 'd_')
                    ip_list_str = ",".join(pub_ips)
                    ip_list_objects.append(f'<ip-list-object name="{escape_xml(pub_obj_name)}" l="{escape_xml(ip_list_str)}" iseffective="false"/>')
                    symantec_group_map[pub_obj_name] = pub_ips
                dest_objs.append(pub_obj_name)
                
            if domain_urls:
                process_url_list(domain_urls, t_name + "_URL", dest_objs, force_category=False)
                        
            if path_only_urls:
                process_url_list(path_only_urls, t_name + "_Path", dest_objs, force_category=False)
            
        for p in ports_only:
            if p not in port_map:
                port_name = format_obj_name(f"HostPort_{p}")
                port_map[p] = port_name
                host_port_objects.append(f'<host-port name="{escape_xml(port_name)}" h="" h-t="exact-phrase" val="{escape_xml(p)}"/>')
                symantec_group_map[port_name] = [p]
            dest_objs.append(port_map[p])
            
        if src_objs: target_src_map[t_name] = src_objs
        if dest_objs: target_dest_map[t_name] = dest_objs

    policy_regex = re.compile(r'define\s+Policy\s+["\'“”](.*?)["\'“”](.*?)end\s+policy', re.IGNORECASE | re.DOTALL)
    
    def parse_policy(is_tls, block):
        for match in policy_regex.finditer(block):
            pol_name_str = match.group(1).strip()
            p_body = match.group(2)

            name_match = re.search(r'name=(.*?)\s+(?:prioirty|priority)=', p_body, re.IGNORECASE)
            prio_match = re.search(r'(?:prioirty|priority)=(.*?)\s+activated=', p_body, re.IGNORECASE)
            act_match = re.search(r'activated=(.*?)\s+', p_body, re.IGNORECASE)
            desc_match = re.search(r'desc=(.*?)\s+(?:editDate=|expireDate=|expired=)', p_body, re.IGNORECASE)
            active_match = re.search(r'activeDate=(\d{4}-\d{2}-\d{2})\s+\d{2}:\d{2}:\d{2}', p_body, re.IGNORECASE)
            expire_match = re.search(r'expireDate=(\d{4}-\d{2}-\d{2})\s+\d{2}:\d{2}:\d{2}', p_body, re.IGNORECASE)

            p_name = name_match.group(1).strip() if name_match else pol_name_str
            is_enabled = "true" if act_match and act_match.group(1).strip() == "사용" else "false"
            p_desc = desc_match.group(1).strip() if desc_match else ""
            if p_desc == "description": p_desc = ""
            
            comment = f"{p_name} {p_desc}".strip()
            
            if mode == "legacy" and "▼" in p_name:
                layer_name = p_name.replace("▼", "").strip()
                if not layer_name: layer_name = "새로운 정책 그룹"
                
                if is_tls:
                    current_tls_layer[0] = {"name": layer_name, "rows": []}
                    legacy_tls_layers.append(current_tls_layer[0])
                else:
                    current_http_layer[0] = {"name": layer_name, "rows": []}
                    legacy_http_layers.append(current_http_layer[0])
                continue

            ti_name = "Any"
            if active_match and expire_match:
                ti_name = format_obj_name(f"Time_{active_match.group(1)}_{expire_match.group(1)}")
                time_obj_xml = f'<time name="{escape_xml(ti_name)}" UTC="false" time="0000..2359" absoluterange="{active_match.group(1)}..{expire_match.group(1)}" single="true" value="{escape_xml(ti_name)}"/>'
                time_objects.append(time_obj_xml)

            json_methods = set()
            json_payloads = set()
            json_src_obj = None
            json_dest_obj = None

            j_data = None
            for line in p_body.splitlines():
                line = line.strip()
                if line.lower().startswith("policyhttprules="):
                    json_str = line[len("policyHttpRules="):].strip()
                    if not json_str: break
                    last_brace = json_str.rfind("}")
                    if last_brace != -1:
                        json_str = json_str[:last_brace+1]
                    try:
                        j_data = json.loads(json_str)
                    except json.JSONDecodeError:
                        pass
                    break

            if j_data:
                def build_ast(node):
                    if "condition" in node and "rules" in node:
                        cond = node["condition"].upper()
                        children = [build_ast(r) for r in node["rules"]]
                        children = [c for c in children if c is not None]
                        if not children: return None
                        if len(children) == 1: return children[0]
                        flat_children = []
                        for c in children:
                            if isinstance(c, tuple) and c[0] == cond:
                                flat_children.extend(c[1])
                            else:
                                flat_children.append(c)
                        return (cond, flat_children)
                        
                    elif "id" in node:
                        rid = node["id"]
                        val = node.get("value", "")
                        op = node.get("operator", "equal")
                        
                        if rid == "http:method":
                            json_methods.add(val.upper())
                            return None
                        elif "payload-length" in rid:
                            m = re.search(r'\d+', str(val))
                            if m: json_payloads.add((op, m.group()))
                            return None
                        elif rid == "http:url":
                            val_str = str(val).strip()
                            if op == "wildcard" and val_str == "*":
                                return None
                            
                            val_str = process_and_log_value(val_str, f"URL Condition ({rid})", p_name)
                            if op == "wildcard":
                                val_str = val_str.strip('*').strip()
                                
                            if not val_str:
                                return None
                            
                            is_equal = (op == "equal")
                            
                            if val_str in global_single_url_map:
                                url_name = global_single_url_map[val_str]
                            else:
                                url_name = format_obj_name(f"RequestUrl_{len(url_map)+1}")
                                url_name = get_unique_node_name(url_name)
                                global_single_url_map[val_str] = url_name
                                url_map[f"{val_str}_{op}"] = url_name
                                req_url_objects.append(generate_a_url_xml(url_name, val_str, is_regex=(not is_equal)))
                                
                            symantec_group_map[url_name] = [val_str]
                            return ("LEAF", "DEST", url_name)

                        elif rid in ("http:request-header", "http:response-header"):
                            if "," in val:
                                hdr, hval = val.split(",", 1)
                            else:
                                hdr, hval = "Unknown", val
                                
                            hval = process_and_log_value(str(hval), f"Header Condition ({rid})", p_name)
                                
                            if op == "wildcard":
                                hval = hval.replace(".", "\\.").replace("*", ".*")
                                v_f = "regex"
                            elif op == "regex":
                                v_f = "regex"
                            else:
                                # [수정된 부분] 값에 정규식 특수문자가 포함되어 있으면 자동 감지하여 regex로 처리
                                has_regex_char = any(c in hval for c in ['*', '^', '$', '[', ']', '|', '\\', '(', ')'])
                                v_f = "regex" if has_regex_char else "exact"
                                
                            obj_type = "request" if rid == "http:request-header" else "response"
                            hash_key = f"{hdr}|{hval}|{v_f}|{obj_type}"
                            
                            if hash_key not in hdr_map:
                                prefix = "RequestHeader" if obj_type == "request" else "ResponseHeader"
                                hdr_name = format_obj_name(f"{prefix}{len(hdr_map)+1}")
                                hdr_map[hash_key] = hdr_name
                                req_hdr_objects.append(f'<hdr-obj name="{escape_xml(hdr_name)}" h="{escape_xml(hdr.strip())}" v="{escape_xml(hval.strip())}" f="{v_f}" t="{obj_type}"/>')
                                symantec_group_map[hdr_name] = [f"{hdr}: {hval} ({v_f})"]
                                
                            leaf_type = "SRC" if obj_type == "request" else "DEST"
                            return ("LEAF", leaf_type, hdr_map.get(hash_key, "Dummy"))
                    return None

                def compile_ast_by_type(ast_node, target_type):
                    if ast_node is None: return None
                    if ast_node[0] == "LEAF": 
                        if ast_node[1] == target_type: return ast_node[2]
                        return None
                    
                    cond, children = ast_node
                    
                    if cond == "OR":
                        compiled_children = []
                        for c in children:
                            name = compile_ast_by_type(c, target_type)
                            if name: compiled_children.append(name)
                        if not compiled_children: return None
                        if len(compiled_children) == 1: return compiled_children[0]
                        
                        t_val = "1" if target_type == "SRC" else "2"
                        combo_name = get_comb_obj_name(t_val)
                        c_list_str = '\n'.join([f'<c-l-1 n="{escape_xml(c)}"/>' for c in compiled_children])
                        comb_objects.append(f'<comb-obj name="{escape_xml(combo_name)}" d="" n-1="false" n-2="false" t="{t_val}">\n{c_list_str}\n</comb-obj>')
                        symantec_group_map[combo_name] = compiled_children
                        return combo_name
                        
                    elif cond == "AND":
                        def get_or_list(node):
                            if node[0] == "LEAF": 
                                return [node[2]] if node[1] == target_type else []
                            elif node[0] == "OR": 
                                res = []
                                for c in node[1]:
                                    name = compile_ast_by_type(c, target_type)
                                    if name: res.append(name)
                                return res
                            else: 
                                name = compile_ast_by_type(node, target_type)
                                return [name] if name else []
                                
                        compiled_items = list(children)
                        valid_items = []
                        for c in compiled_items:
                            if get_or_list(c): valid_items.append(c)
                            
                        if not valid_items: return None
                        if len(valid_items) == 1: return compile_ast_by_type(valid_items[0], target_type)
                        
                        while len(valid_items) > 1:
                            left_node = valid_items.pop(0)
                            right_node = valid_items.pop(0)
                            
                            left_names = get_or_list(left_node)
                            right_names = get_or_list(right_node)
                            
                            t_val = "1" if target_type == "SRC" else "2"
                            combo_name = get_comb_obj_name(t_val)
                            cl1_str = '\n'.join([f'<c-l-1 n="{escape_xml(n)}"/>' for n in left_names])
                            cl2_str = '\n'.join([f'<c-l-2 n="{escape_xml(n)}"/>' for n in right_names])
                            comb_xml = f'<comb-obj name="{escape_xml(combo_name)}" d="" n-1="false" n-2="false" t="{t_val}">\n{cl1_str}\n{cl2_str}\n</comb-obj>'
                            comb_objects.append(comb_xml)
                            symantec_group_map[combo_name] = left_names + right_names
                            valid_items.insert(0, ("LEAF", target_type, combo_name))
                        return valid_items[0][2]

                ast_root = build_ast(j_data)
                
                json_src_obj = compile_ast_by_type(ast_root, "SRC")
                json_dest_obj = compile_ast_by_type(ast_root, "DEST")

            se_name = "Any"
            target_methods = {"POST", "PUT", "PATCH", "BITS_POST"}
            found_methods = json_methods.intersection(target_methods)
            method_matches = re.findall(r'"id"\s*:\s*"http:method"\s*,\s*"operator"\s*:\s*"equal"\s*,\s*"value"\s*:\s*"([^"]+)"', p_body, re.IGNORECASE)
            for m in method_matches:
                if m.upper() in target_methods:
                    found_methods.add(m.upper())

            if found_methods:
                se_name = "PUT/POST/PATCH"
                service_objects.append('<prot-meth name="PUT/POST/PATCH" t="http" non-h="no" m="POST,PUT,PATCH"/>')

            inbound_names = []
            outbound_names = []
            dir_blocks = re.split(r'(?i)address\s+direction=', p_body)
            for d_block in dir_blocks[1:]:
                dir_m = re.match(r'^\s*(\w+)', d_block)
                if not dir_m: continue
                direction = dir_m.group(1).lower()
                names = []
                for line in d_block.splitlines()[1:]:
                    line = line.strip()
                    if not line: continue
                    name_match = re.match(r'(?i)^(?:address|adress)\s+name=(.*)', line)
                    if name_match:
                        val = process_and_log_value(name_match.group(1), "출발지/목적지", p_name)
                        names.append(val)
                    else: break
                
                if direction == 'inbound': inbound_names.extend(names)
                elif direction == 'outbound': outbound_names.extend(names)

            so_name = "Any"
            de_name = "Any"
            
            mapped_inbounds = []
            for n in inbound_names:
                if n.upper() == "ANY": continue
                if n in target_src_map:
                    mapped_inbounds.extend(target_src_map[n])
                else:
                    mapped_inbounds.append(format_obj_name(n))
            
            if json_src_obj:
                mapped_inbounds.append(json_src_obj)

            if mapped_inbounds:
                mapped_inbounds = list(dict.fromkeys(mapped_inbounds))
                if len(mapped_inbounds) == 1:
                    so_name = mapped_inbounds[0]
                elif len(mapped_inbounds) > 1:
                    combo_key = tuple(mapped_inbounds)
                    if combo_key not in combined_source_map:
                        combo_name = get_comb_obj_name("1")
                        combined_source_map[combo_key] = combo_name
                        c_list_str = '\n'.join([f'<c-l-1 n="{escape_xml(item)}"/>' for item in combo_key])
                        comb_objects.append(f'<comb-obj name="{escape_xml(combo_name)}" d="" n-1="false" n-2="false" t="1">\n{c_list_str}\n</comb-obj>')
                        symantec_group_map[combo_name] = list(combo_key)
                    so_name = combined_source_map[combo_key]

            mapped_outbounds = []
            for n in outbound_names:
                if n.upper() == "ANY": continue
                if n in target_dest_map:
                    mapped_outbounds.extend(target_dest_map[n])
                else:
                    mapped_outbounds.append(format_obj_name(n))

            rule_categories = []
            cat_name = ""
            user_cat_name = ""
            web_cat_ids = []

            if is_tls:
                cat_match = re.search(r'userDefinedCategory\s+name=(.*)', p_body, re.IGNORECASE)
                cat_name = process_and_log_value(cat_match.group(1), "Category", p_name) if cat_match else ""
                
                type_match = re.search(r'type\s+name=(.*)', p_body, re.IGNORECASE)
                type_name = process_and_log_value(type_match.group(1), "Type", p_name) if type_match else ""
                
                if type_name: 
                    mapped_inbounds.append(format_obj_name(type_name))
                if cat_name and cat_name.upper() not in ("ANY", "ANY,"): 
                    clean_cat = re.sub(r'^ANY,\s*', '', cat_name, flags=re.IGNORECASE).strip()
                    if clean_cat and clean_cat.upper() != "ANY":
                        m_cat = webcat_name_map.get(clean_cat, format_obj_name(clean_cat))
                        if m_cat in global_single_url_map.values():
                            mapped_outbounds.append(m_cat)
                        else:
                            rule_categories.append(m_cat)
            else:
                user_cat_match = re.search(r'userDefinedCategory\s+name=(.*)', p_body, re.IGNORECASE)
                user_cat_name = process_and_log_value(user_cat_match.group(1), "UserCategory", p_name) if user_cat_match else ""
                
                web_cat_ids_raw = re.findall(r'web-category-id\s+value=(.*)', p_body, re.IGNORECASE)
                web_cat_ids = [process_and_log_value(c, "WebCategory", p_name) for c in web_cat_ids_raw if c.strip() and process_and_log_value(c, "WebCategory", p_name).upper() != "ANY"]
                
                if user_cat_name and user_cat_name.upper() not in ("ANY", "ANY,"):
                    clean_cat = re.sub(r'^ANY,\s*', '', user_cat_name, flags=re.IGNORECASE).strip()
                    if clean_cat and clean_cat.upper() != "ANY":
                        m_cat = webcat_name_map.get(clean_cat, format_obj_name(clean_cat))
                        if m_cat in global_single_url_map.values():
                            mapped_outbounds.append(m_cat)
                        else:
                            rule_categories.append(m_cat)

                if web_cat_ids:
                    web_url_list_m = re.search(r'webUrlList:\s*(.*)', p_body, re.IGNORECASE)
                    if web_url_list_m:
                        raw_urls = web_url_list_m.group(1).strip()
                        if raw_urls:
                            urls = [process_and_log_value(u, "webUrlList URL", p_name) for u in raw_urls.split(',') if u.strip()]
                            base_cat_name = webcat_name_map.get(web_cat_ids[0], format_obj_name(web_cat_ids[0])) if web_cat_ids else format_obj_name("WebUrlList")
                            
                            path_only_urls = []
                            domain_urls = []
                            for u in urls:
                                if is_path_only(u): path_only_urls.append(u)
                                else: domain_urls.append(u)
                                
                            process_url_list(domain_urls, base_cat_name + "_URL", mapped_outbounds, force_category=False)
                            process_url_list(path_only_urls, base_cat_name + "_Path", mapped_outbounds, force_category=False)
                            
                            if web_cat_ids:
                                web_cat_ids.pop(0)
                    
                    for c in web_cat_ids:
                        if c.upper() != "ANY":
                            m_cat = webcat_name_map.get(c, format_obj_name(c))
                            if m_cat in global_single_url_map.values():
                                mapped_outbounds.append(m_cat)
                            else:
                                rule_categories.append(m_cat)

            if rule_categories:
                rule_categories = list(dict.fromkeys(rule_categories))
                cat_tuple = tuple(rule_categories)
                if cat_tuple not in category_list_map:
                    if len(cat_tuple) == 1:
                        cat_list_name = cat_tuple[0]
                    else:
                        cat_list_name = format_obj_name(f"RequestURLCategory_{len(category_list_map) + 1}")
                    category_list_map[cat_tuple] = cat_list_name
                    i_tags = '\n'.join([f'<i>{escape_xml(c)}</i>' for c in cat_tuple])
                    cat_xml = f'<categorylist4 name="{escape_xml(cat_list_name)}" typ="r">\n<sel>\n{i_tags}\n</sel>\n<excl/>\n<sel-p/>\n</categorylist4>'
                    category_list_objects.append(cat_xml)
                    symantec_group_map[cat_list_name] = list(cat_tuple)
                
                mapped_outbounds.append(category_list_map[cat_tuple])

            if json_dest_obj:
                mapped_outbounds.append(json_dest_obj)

            if mapped_outbounds:
                mapped_outbounds = list(dict.fromkeys(mapped_outbounds))
                if len(mapped_outbounds) == 1:
                    de_name = mapped_outbounds[0]
                elif len(mapped_outbounds) > 1:
                    combo_key = tuple(mapped_outbounds)
                    if combo_key not in combined_dest_map:
                        combo_name = get_comb_obj_name("2")
                        combined_dest_map[combo_key] = combo_name
                        c_list_str = '\n'.join([f'<c-l-1 n="{escape_xml(item)}"/>' for item in combo_key])
                        comb_objects.append(f'<comb-obj name="{escape_xml(combo_name)}" d="" n-1="false" n-2="false" t="2">\n{c_list_str}\n</comb-obj>')
                        symantec_group_map[combo_name] = list(combo_key)
                    de_name = combined_dest_map[combo_key]

            is_custom_cat_policy = False
            for d in outbound_names + web_cat_ids + [user_cat_name, cat_name]:
                if d and "Custom_category" in d:
                    is_custom_cat_policy = True
                    break

            ac_name = "None"
            
            payload_match = re.search(r'"id"\s*:\s*"http:request-payload-length"\s*,\s*"operator"\s*:\s*"([^"]+)"\s*,\s*"value"\s*:\s*"(\d+)"', p_body, re.IGNORECASE)
            if payload_match:
                json_payloads.add((payload_match.group(1), payload_match.group(2)))

            action_match = re.search(r'action\s+value=(.*)', p_body, re.IGNORECASE)
            block_msg_match = re.search(r'block-message\s+value=(.*)', p_body, re.IGNORECASE)
            action_val = action_match.group(1).strip() if action_match else ""
            block_msg = block_msg_match.group(1).strip() if block_msg_match else ""

            if json_payloads:
                op, val = sorted(list(json_payloads))[0]
                val_int = int(val)
                if op in ("greator-than-or-eq", "greater-than-or-eq", "less-than-or-eq"):
                    bs_val = val_int - 1
                else:
                    bs_val = val_int
                    
                payload_name = format_obj_name(f"HttpRequestMaxBodySize_{op}_{val}")
                if payload_name not in req_body_map:
                    req_body_map[payload_name] = bs_val
                    http_req_objects.append(f'<http-req-max-body-size name="{escape_xml(payload_name)}" b-s="{bs_val}"/>')
                ac_name = payload_name
            else:
                if action_val == "허용": 
                    ac_name = "Allow"
                elif action_val == "차단": 
                    if not block_msg or block_msg.lower() == "deny":
                        ac_name = "Deny"
                    elif block_msg.lower() == "force_deny":
                        ac_name = "Force Deny"
                    else:
                        ac_name = format_obj_name(block_msg)
                        esc_ac = escape_xml(ac_name)
                        dny_exc_xml = f'<dny-exc a="false" e="{esc_ac}" f="false" m="" name="{esc_ac}" p="userdefined"> </dny-exc>'
                        dny_exc_objects.append(dny_exc_xml)

            if ac_name == "None":
                is_enabled = "false"
                
            # [적용] Allow, None이 아닌 액션을 전부 Deny로 통일
            if unify_deny_choice == 'y' and ac_name not in ("Allow", "None"):
                ac_name = "Deny"

            is_upload_policy = (se_name == "PUT/POST/PATCH")

            layer_type_name = ""
            if mode == "legacy":
                if is_tls:
                    if current_tls_layer[0] is None:
                        current_tls_layer[0] = {"name": "기본 TLS 정책", "rows": []}
                        legacy_tls_layers.append(current_tls_layer[0])
                    layer_idx = len(legacy_tls_layers)
                    row_idx = len(current_tls_layer[0]["rows"])
                    has_time = False
                    track_name = format_obj_name(f"TLS_L{layer_idx}_P{row_idx + 1}")
                    layer_type_name = current_tls_layer[0]["name"]
                else:
                    if current_http_layer[0] is None:
                        current_http_layer[0] = {"name": "기본 웹 정책", "rows": []}
                        legacy_http_layers.append(current_http_layer[0])
                    layer_idx = len(legacy_http_layers)
                    row_idx = len(current_http_layer[0]["rows"])
                    has_time = True
                    track_name = format_obj_name(f"WA_L{layer_idx}_P{row_idx + 1}")
                    layer_type_name = current_http_layer[0]["name"]
            elif mode == "single":
                if is_tls:
                    row_idx = len(tls_row_items)
                    has_time = False
                    track_name = format_obj_name(f"TLS_P{row_idx + 1}")
                    layer_type_name = "SSL_Intercept_Layer"
                else:
                    row_idx = len(http_row_items)
                    has_time = True
                    track_name = format_obj_name(f"WA_P{row_idx + 1}")
                    layer_type_name = "Web_Access_Layer"
            else:
                if is_custom_cat_policy:
                    row_idx = len(custom_cat_row_items)
                    has_time = True
                    track_name = format_obj_name(f"CC_P{row_idx + 1}")
                    layer_type_name = "a_Custom_Category_웹_정책"
                elif is_upload_policy:
                    row_idx = len(req_row_items)
                    has_time = True  
                    track_name = format_obj_name(f"WR_P{row_idx + 1}")
                    layer_type_name = "a_업로드_정책"
                elif is_tls:
                    row_idx = len(tls_row_items)
                    has_time = False 
                    track_name = format_obj_name(f"TLS_P{row_idx + 1}")
                    layer_type_name = "TLS_Policies"
                else:
                    row_idx = len(http_row_items)
                    has_time = True
                    track_name = format_obj_name(f"WA_P{row_idx + 1}")
                    layer_type_name = "a_기본_웹_정책"

            policy_id_objects.append(f'<policy-id name="{escape_xml(track_name)}" cmt="{escape_xml(comment)}"/>')

            used_names_exact.add(so_name)
            used_names_exact.add(de_name)
            used_names_exact.add(se_name)
            used_names_exact.add(ti_name)
            if ac_name not in ("Allow", "Deny", "Force Deny", "None", ""):
                used_names_exact.add(ac_name)

            row_str = f'''<rowItem enabled="{is_enabled}" num="{row_idx}">
<colItem col="0" id="no" value="{row_idx + 1}"/>
<colItem col="1" id="so" {get_col_attrs(so_name, 'so')}/>
<colItem col="2" id="de" {get_col_attrs(de_name, 'de')}/>
<colItem col="3" id="se" {get_col_attrs(se_name, 'se')}/>'''

            if has_time:
                row_str += f'\n<colItem col="4" id="ti" {get_col_attrs(ti_name, "ti")}/>'
                col_offset = 5
            else:
                col_offset = 4
                
            row_str += f'''
<colItem col="{col_offset}" id="ac" {get_col_attrs(ac_name, 'ac')}/>
<colItem col="{col_offset+1}" id="tr" {get_col_attrs(track_name, 'tr')}/>
<colItem col="{col_offset+2}" id="ep" {get_col_attrs("Appliance", "ep")}/>
<colItem col="{col_offset+3}" id="co" {get_col_attrs(comment, 'co')}/>
</rowItem>'''

            if mode == "legacy":
                if is_tls: current_tls_layer[0]["rows"].append(row_str)
                else: current_http_layer[0]["rows"].append(row_str)
            elif mode == "single":
                if is_tls: tls_row_items.append(row_str)
                else: http_row_items.append(row_str)
            else:
                if is_custom_cat_policy: custom_cat_row_items.append(row_str)
                elif is_upload_policy: req_row_items.append(row_str)
                elif is_tls: tls_row_items.append(row_str)
                else: http_row_items.append(row_str)
                
            sym_pol = {
                "Layer": layer_type_name,
                "Track": track_name,
                "Enabled": is_enabled,
                "Source": so_name,
                "Destination": de_name,
                "Service": se_name,
                "Time": ti_name if has_time else "Any",
                "Action": ac_name,
                "Block Message": block_msg,
                "Comment": comment,
                "_somansa_name": p_name,
                "_source_html": get_sym_obj_html(so_name, symantec_group_map),
                "_dest_html": get_sym_obj_html(de_name, symantec_group_map),
                "_source_flat": get_flat_sym_items(so_name, symantec_group_map),
                "_dest_flat": get_flat_sym_items(de_name, symantec_group_map)
            }
            symantec_json_data.append(sym_pol)

    tls_outer_regex = re.compile(r'<TLS-Policy>(.*?)(?:<TLS-Policy/>|</TLS-Policy>)', re.IGNORECASE | re.DOTALL)
    for outer_match in tls_outer_regex.finditer(input_data):
        parse_policy(True, outer_match.group(1))

    http_outer_regex = re.compile(r'<HTTP-Policy>(.*?)(?:<HTTP-Policy/>|</HTTP-Policy>)', re.IGNORECASE | re.DOTALL)
    for outer_match in http_outer_regex.finditer(input_data):
        parse_policy(False, outer_match.group(1))

    def get_unique(items):
        seen = set()
        return [x for x in items if not (x in seen or seen.add(x))]

    unique_vpm_cat_nodes = get_unique(vpm_cat_nodes)
    unique_a_url_objects = get_unique(a_url_objects)
    unique_req_url_objects = get_unique(req_url_objects)
    unique_req_hdr_objects = get_unique(req_hdr_objects)
    unique_ip_objects = get_unique(ip_objects)
    unique_ip_list_objects = get_unique(ip_list_objects)
    unique_host_port_objects = get_unique(host_port_objects)
    unique_comb_objects = get_unique(comb_objects)
    unique_category_list_objects = get_unique(category_list_objects)
    unique_time_objects = get_unique(time_objects)
    unique_policy_id_objects = get_unique(policy_id_objects)
    unique_service_objects = get_unique(service_objects)
    unique_dny_exc_objects = get_unique(dny_exc_objects)
    unique_http_req_objects = get_unique(http_req_objects)

    print(f"\n{Fore.CYAN}========================================")
    print(f"{Fore.CYAN}{Style.BRIGHT} 📊 [파싱 완료 통계 정보]")
    print(f"{Fore.CYAN}========================================")
    print(f"{Fore.WHITE} [정책 (Policy) 레이어 분포]")
    if mode == "legacy":
        print(f"  - 분할된 Web Access Layer 수 : {len(legacy_http_layers)}개 그룹")
        print(f"  - 분할된 TLS Access Layer 수 : {len(legacy_tls_layers)}개 그룹")
    elif mode == "single":
        print(f"  - 단일 Web Access Layer 규칙 수 : {len(http_row_items)}개")
        print(f"  - 단일 TLS Access Layer 규칙 수 : {len(tls_row_items)}개")
    else:
        print(f"  - Custom Category 규칙 수    : {len(custom_cat_row_items)}개")
        print(f"  - Web Access (기본 웹) 규칙 수 : {len(http_row_items)}개")
        print(f"  - Web Request (업로드) 규칙 수 : {len(req_row_items)}개")
        print(f"  - TLS-Policy 규칙 수         : {len(tls_row_items)}개")
        
    print(f"\n{Fore.WHITE} [생성된 conditionObjects 종류]")
    print(f"  - 단일 IP 객체        : {len(unique_ip_objects)}개")
    print(f"  - 다중 IP List 객체   : {len(unique_ip_list_objects)}개")
    print(f"  - Host-Port 객체      : {len(unique_host_port_objects)}개")
    print(f"  - Combined 객체       : {len(unique_comb_objects)}개")
    print(f"  - Request URL 객체    : {len(unique_req_url_objects)}개")
    print(f"  - 기타 a-url 객체     : {len(unique_a_url_objects)}개")
    print(f"  - Http Header 객체    : {len(unique_req_hdr_objects)}개")
    print(f"  - 카테고리 Node 객체  : {len(unique_vpm_cat_nodes)}개")
    print(f"  - Category List 객체  : {len(unique_category_list_objects)}개")
    print(f"  - Time 객체           : {len(unique_time_objects)}개")
    print(f"  - Policy ID 객체      : {len(unique_policy_id_objects)}개")
    print(f"  - Service(Method) 객체: {len(unique_service_objects)}개")
    print(f"  - Deny/Exception 객체 : {len(unique_dny_exc_objects)}개")
    print(f"  - Http Req Max Size   : {len(unique_http_req_objects)}개")
    print(f"{Fore.CYAN}========================================\n")

    removed_csv_data = []

    if optimize_choice == 'y':
        print(f"{Fore.GREEN}▶ [4/6] 🧹 2차 딥 클린업 (Deep GC) 실행 중: 정책에 한 번도 연결되지 않은 찌꺼기 객체 재귀 추적 및 삭제...")
        
        used_names_exact.discard("Any")
        used_names_exact.discard("None")
        
        while True:
            added_new = False
            for comb_xml in unique_comb_objects:
                m = re.search(r'<comb-obj[^>]*\sname="([^"]+)"', comb_xml)
                if m and escape_xml_reverse(m.group(1)) in used_names_exact:
                    inner_names = re.findall(r'<c-l-\d+\s+n="([^"]+)"', comb_xml)
                    for inner in inner_names:
                        clean_inner = escape_xml_reverse(inner)
                        if clean_inner not in used_names_exact:
                            used_names_exact.add(clean_inner)
                            added_new = True
                            
            for cat_list_xml in unique_category_list_objects:
                m = re.search(r'<categorylist4[^>]*\sname="([^"]+)"', cat_list_xml)
                if m and escape_xml_reverse(m.group(1)) in used_names_exact:
                    inner_names = re.findall(r'<i>([^<]+)</i>', cat_list_xml)
                    for inner in inner_names:
                        clean_inner = escape_xml_reverse(inner)
                        if clean_inner not in used_names_exact:
                            used_names_exact.add(clean_inner)
                            added_new = True
            if not added_new: break

        def is_used(xml_str, tag):
            m = re.search(fr'<{tag}[^>]*\sname="([^"]+)"', xml_str)
            if m:
                return escape_xml_reverse(m.group(1)) in used_names_exact
            return False

        def is_node_used(xml_str):
            m = re.search(r'<node\s+n="([^"]+)"', xml_str)
            if m:
                return escape_xml_reverse(m.group(1)) in used_names_exact
            return False

        active_comb_objects = [x for x in unique_comb_objects if is_used(x, 'comb-obj')]
        active_category_list_objects = [x for x in unique_category_list_objects if is_used(x, 'categorylist4')]
        active_ip_objects = [x for x in unique_ip_objects if is_used(x, 'ipobject')]
        active_ip_list_objects = [x for x in unique_ip_list_objects if is_used(x, 'ip-list-object')]
        active_host_port_objects = [x for x in unique_host_port_objects if is_used(x, 'host-port')]
        active_a_url_objects = [x for x in unique_a_url_objects if is_used(x, '(?:a-url|url)')]
        active_req_url_objects = [x for x in unique_req_url_objects if is_used(x, '(?:a-url|url)')]
        active_req_hdr_objects = [x for x in unique_req_hdr_objects if is_used(x, 'hdr-obj')]
        active_vpm_cat_nodes = [x for x in unique_vpm_cat_nodes if is_node_used(x)]
        active_dny_exc_objects = [x for x in unique_dny_exc_objects if is_used(x, 'dny-exc')]
        active_http_req_objects = [x for x in unique_http_req_objects if is_used(x, 'http-req-max-body-size')]

        for obj in unique_ip_objects:
            if obj not in active_ip_objects: removed_csv_data.append(get_obj_details(obj, "IP 단일/범위 객체"))
        for obj in unique_ip_list_objects:
            if obj not in active_ip_list_objects: removed_csv_data.append(get_obj_details(obj, "다중 IP List 객체"))
        for obj in unique_host_port_objects:
            if obj not in active_host_port_objects: removed_csv_data.append(get_obj_details(obj, "Host-Port 객체"))
        for obj in unique_comb_objects:
            if obj not in active_comb_objects: removed_csv_data.append(get_obj_details(obj, "Combined 객체"))
        for obj in unique_req_url_objects:
            if obj not in active_req_url_objects: removed_csv_data.append(get_obj_details(obj, "Request URL 객체"))
        for obj in unique_a_url_objects:
            if obj not in active_a_url_objects: removed_csv_data.append(get_obj_details(obj, "기타 a-url 객체"))
        for obj in unique_req_hdr_objects:
            if obj not in active_req_hdr_objects: removed_csv_data.append(get_obj_details(obj, "Http Header 객체"))
        for obj in unique_vpm_cat_nodes:
            if obj not in active_vpm_cat_nodes: removed_csv_data.append(get_obj_details(obj, "카테고리 Node 객체"))
        for obj in unique_category_list_objects:
            if obj not in active_category_list_objects: removed_csv_data.append(get_obj_details(obj, "Category List 객체"))
    else:
        active_vpm_cat_nodes = unique_vpm_cat_nodes
        active_a_url_objects = unique_a_url_objects
        active_req_url_objects = unique_req_url_objects
        active_req_hdr_objects = unique_req_hdr_objects
        active_ip_objects = unique_ip_objects
        active_ip_list_objects = unique_ip_list_objects
        active_host_port_objects = unique_host_port_objects
        active_comb_objects = unique_comb_objects
        active_category_list_objects = unique_category_list_objects
        active_dny_exc_objects = unique_dny_exc_objects
        active_http_req_objects = unique_http_req_objects
        print(f"{Fore.YELLOW}▶ [4/6] 최적화를 진행하지 않고 모든 객체를 변환합니다...")

    output_xml = '<?xml version="1.0" encoding="UTF-8"?>\n<vpmapp>\n<vpmxml-info version="631"/>\n<enforcement-point enabled="false"/>\n<conditionObjects>\n'
    
    if active_vpm_cat_nodes: output_xml += '<vpm-cat>\n' + '\n'.join(active_vpm_cat_nodes) + '\n</vpm-cat>\n'
    if active_a_url_objects: output_xml += '\n'.join(active_a_url_objects) + '\n'
    if active_req_url_objects: output_xml += '\n'.join(active_req_url_objects) + '\n'
    if active_req_hdr_objects: output_xml += '\n'.join(active_req_hdr_objects) + '\n'
    if active_ip_objects: output_xml += '\n'.join(active_ip_objects) + '\n'
    if active_ip_list_objects: output_xml += '\n'.join(active_ip_list_objects) + '\n'
    if active_host_port_objects: output_xml += '\n'.join(active_host_port_objects) + '\n'
    if active_comb_objects: output_xml += '\n'.join(active_comb_objects) + '\n'
    if unique_time_objects: output_xml += '\n'.join(unique_time_objects) + '\n'
    if active_category_list_objects: output_xml += '\n'.join(active_category_list_objects) + '\n'
    if unique_policy_id_objects: output_xml += '\n'.join(unique_policy_id_objects) + '\n'
    if unique_service_objects: output_xml += '\n'.join(unique_service_objects) + '\n'
    if unique_dny_exc_objects: output_xml += '\n'.join(unique_dny_exc_objects) + '\n'
    if unique_http_req_objects: output_xml += '\n'.join(unique_http_req_objects) + '\n'
        
    output_xml += '</conditionObjects>\n<layers>\n'

    if mode == "legacy":
        for layer in legacy_tls_layers:
            if layer["rows"]:
                output_xml += f'<layer layertype="com.bluecoat.sgos.vpm.SSLAccessPolicyTable">\n<name>{escape_xml(layer["name"])}</name>\n<numRows>{len(layer["rows"])}</numRows>\n' + '\n'.join(layer["rows"]) + '\n</layer>\n'
        for layer in legacy_http_layers:
            if layer["rows"]:
                output_xml += f'<layer layertype="com.bluecoat.sgos.vpm.WebAccessPolicyTable">\n<name>{escape_xml(layer["name"])}</name>\n<numRows>{len(layer["rows"])}</numRows>\n' + '\n'.join(layer["rows"]) + '\n</layer>\n'
    elif mode == "single":
        if tls_row_items:
            output_xml += f'<layer layertype="com.bluecoat.sgos.vpm.SSLAccessPolicyTable">\n<name>SSL_Intercept_Layer</name>\n<numRows>{len(tls_row_items)}</numRows>\n' + '\n'.join(tls_row_items) + '\n</layer>\n'
        if http_row_items:
            output_xml += f'<layer layertype="com.bluecoat.sgos.vpm.WebAccessPolicyTable">\n<name>Web_Access_Layer</name>\n<numRows>{len(http_row_items)}</numRows>\n' + '\n'.join(http_row_items) + '\n</layer>\n'
    else:
        if tls_row_items:
            output_xml += f'<layer layertype="com.bluecoat.sgos.vpm.SSLAccessPolicyTable">\n<name>TLS_Policies</name>\n<numRows>{len(tls_row_items)}</numRows>\n' + '\n'.join(tls_row_items) + '\n</layer>\n'
        if http_row_items:
            output_xml += f'<layer layertype="com.bluecoat.sgos.vpm.WebAccessPolicyTable">\n<name>a_기본_웹_정책</name>\n<numRows>{len(http_row_items)}</numRows>\n' + '\n'.join(http_row_items) + '\n</layer>\n'
        if custom_cat_row_items:
            output_xml += f'<layer layertype="com.bluecoat.sgos.vpm.WebAccessPolicyTable">\n<name>a_Custom_Category_웹_정책</name>\n<numRows>{len(custom_cat_row_items)}</numRows>\n' + '\n'.join(custom_cat_row_items) + '\n</layer>\n'

        guard_xml = '''<guard enabled="true" num="0">
<colItem col="0" id="no" value="0"/>
<colItem col="1" id="so" name="Any" type="String"/>
<colItem col="2" id="de" name="Any" type="String"/>
<colItem col="3" id="se" name="PUT/POST/PATCH" negate="false" type="Condition"/>
<colItem col="4" id="ti" name="Any" type="String"/>
<colItem col="5" id="ac" name="None" type="String"/>
<colItem col="6" id="tr" name="None" type="String"/>
<colItem col="7" id="ep" name="None" type="String"/>
<colItem col="8" id="co" name="" type="String"/>
</guard>'''

        if req_row_items:
            output_xml += f'<layer layertype="com.bluecoat.sgos.vpm.WebRequestPolicyTable">\n<name>a_업로드_정책</name>\n{guard_xml}\n<numRows>{len(req_row_items)}</numRows>\n' + '\n'.join(req_row_items) + '\n</layer>\n'

    output_xml += '</layers>\n</vpmapp>'
	
	# [적용] {가 있고 20글자 안에 }로 닫히지 않는 경우 앞에 \ 추가 (이스케이프 로직 추가)
    output_xml = re.sub(r'(?<!\\)\{(?![^}]{0,20}\})', r'\\{', output_xml)
    
    return output_xml, exception_pages_text, removed_csv_data, exception_tracked_list, symantec_json_data, negated_items_log, space_slash_log, http_dot_log

if __name__ == "__main__":
    print(f"{Fore.CYAN}========================================")
    print(f"{Fore.CYAN}{Style.BRIGHT} ⚡ 소만사 -> 시만텍 XML 로컬 컨버터 ⚡")
    print(f"{Fore.CYAN}========================================")
    
    root = tk.Tk()
    root.withdraw() 
    
    target_auto_file = "소만사_web policy_full_EN.txt"
    input_file_path = ""
    
    if getattr(sys, 'frozen', False):
        script_dir = os.path.dirname(sys.executable)
    else:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        
    auto_file_path = os.path.join(script_dir, target_auto_file)
    
    if not os.path.exists(auto_file_path) and os.path.exists(target_auto_file):
        auto_file_path = os.path.abspath(target_auto_file)

    if os.path.exists(auto_file_path):
        input_file_path = auto_file_path
        print(f"{Fore.GREEN}💡 [자동 인식] 동일 폴더 내에서 '{target_auto_file}' 파일을 발견하여 자동으로 불러옵니다.\n")
    else:
        print(f"\n{Fore.YELLOW}📂 변환할 소만사 정책 파일(.txt)을 선택해 주세요...")
        input_file_path = filedialog.askopenfilename(
            title="소만사 정책 파일 선택",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if not input_file_path:
            print(f"{Fore.RED}❌ 파일 선택이 취소되었습니다. 프로그램을 종료합니다.")
            input(f"\n{Fore.WHITE}엔터(Enter) 키를 누르면 창이 닫힙니다...")
            sys.exit(0)

    print(f"{Fore.GREEN}📄 선택된 파일: {input_file_path}")
    
    with open(input_file_path, 'r', encoding='utf-8') as f:
        raw_input = f.read()
        
    print(f"\n{Fore.CYAN}========================================")
    print(f"{Fore.CYAN} 🛠 [정책 구분 방식 선택]")
    print(f"{Fore.CYAN} 1. 기존 구분 방식 : '▼' 구분선마다 새로운 Web Access Layer로 분할")
    print(f"{Fore.CYAN} 2. 새로운 구분 방식 : 업로드(Web Request) 및 Custom Category 전용 Layer 자동 분류")
    print(f"{Fore.CYAN} 3. 통 레이어 그대로 : 모든 정책을 단일 Layer 하나로 통합 생성")
    print(f"{Fore.CYAN}========================================")
    mode_input = input(f"{Fore.YELLOW}👉 방식을 선택하세요 (1/2/3) [기본값: 3]: ").strip()
    if mode_input == '1':
        selected_mode = "legacy"
    elif mode_input == '2':
        selected_mode = "new"
    else:
        selected_mode = "single"
    
    print(f"\n{Fore.CYAN}========================================")
    print(f"{Fore.CYAN} 🌐 [사내망(Private IP) 대역 설정]")
    print(f"{Fore.WHITE}Target에 섞여있는 IP 중, 사내망에 해당하는 IP는 Client IP(Type 1) 객체로,")
    print(f"{Fore.WHITE}공인 IP는 Server IP(Type 2) 객체로 자동 분류하여 생성합니다.")
    print(f"{Fore.CYAN}========================================")
    
    internal_networks = []
    auto_subnet = auto_detect_internal_network(raw_input)
    
    if auto_subnet:
        print(f"{Fore.GREEN}💡 [자동 분석 완료] Target 객체에서 가장 많이 사용된 8비트 대역을 찾았습니다.")
        print(f"{Fore.WHITE}   👉 자동 감지된 사내망: {Fore.YELLOW}{auto_subnet}")
        use_auto = input(f"\n{Fore.YELLOW}이 자동 감지된 사내망 대역을 그대로 적용하시겠습니까? (Y/N) [기본값: Y]: ").strip().lower()
        
        if use_auto != 'n':
            try:
                internal_networks.append(ipaddress.ip_network(auto_subnet, strict=False))
                print(f"{Fore.GREEN}▶ '{auto_subnet}' 대역이 사내망으로 자동 적용되었습니다.")
            except ValueError:
                pass
        else:
            internal_input = input(f"\n{Fore.YELLOW}👉 사내망 대역을 콤마(,)로 구분하여 직접 입력하세요 (없으면 엔터): ").strip()
            if internal_input:
                for net_str in internal_input.split(','):
                    net_str = net_str.strip()
                    if net_str:
                        try:
                            internal_networks.append(ipaddress.ip_network(net_str, strict=False))
                        except ValueError:
                            print(f"{Fore.RED}⚠️ 경고: '{net_str}'은(는) 올바른 CIDR 형식이 아니어서 무시됩니다.")
    else:
        print(f"{Fore.WHITE}※ 기본 탑재된 사설망은 없으며, 직접 입력한 대역만 사내망으로 인식합니다.")
        internal_input = input(f"{Fore.YELLOW}👉 사내망 대역을 콤마(,)로 구분하여 입력하세요 (없으면 엔터): ").strip()
        
        if internal_input:
            for net_str in internal_input.split(','):
                net_str = net_str.strip()
                if net_str:
                    try:
                        internal_networks.append(ipaddress.ip_network(net_str, strict=False))
                    except ValueError:
                        print(f"{Fore.RED}⚠️ 경고: '{net_str}'은(는) 올바른 CIDR 형식이 아니어서 무시됩니다.")
    
    opt_input = input(f"\n{Fore.YELLOW}🤔 정책에서 사용되지 않은 잉여 객체들을 삭제(최적화) 하시겠습니까? (Y/N) [기본값: Y]: ").strip().lower()
    optimize_choice = 'n' if opt_input == 'n' else 'y'

    print(f"\n{Fore.CYAN}========================================")
    print(f"{Fore.CYAN} 🛡️ [시만텍 액션(Action) 일괄 통일 설정]")
    print(f"{Fore.WHITE}XML 변환 시 'None'과 'Allow'를 제외한 모든 커스텀 차단 액션")
    print(f"{Fore.WHITE}(예: a20250918_Outlook_blocking_page 등)을 'Deny'로 일괄 변경합니다.")
    print(f"{Fore.CYAN}========================================")
    opt_deny_input = input(f"{Fore.YELLOW}👉 'Deny'로 일괄 통일하시겠습니까? (Y/N) [기본값: Y]: ").strip().lower()
    unify_deny_choice = 'n' if opt_deny_input == 'n' else 'y'
    
    base_dir = os.path.dirname(input_file_path)
    today_str = datetime.now().strftime("%Y%m%d")
    
    # ---------------------------------------------------------------------
    # 하단 __main__ 블록에서 실제 파일 저장(open)이 이루어지며,
    # 각 파일별 데이터는 위에서 정의된 추출/생성 함수들을 통해 만들어집니다.
    # ---------------------------------------------------------------------
    
    JSON_OUTPUT = os.path.join(base_dir, f"2. Somansa_policy_summary_{today_str}.json")
    VIEWER_OUTPUT = os.path.join(base_dir, f"3. Somansa_policy_viewer_{today_str}.html")
    HTML_OUTPUT = os.path.join(base_dir, f"4. Somansa_exception_pages_{today_str}.html")
    XML_OUTPUT = os.path.join(base_dir, f"5. Symantec_policy_{today_str}.xml")
    CSV_OUTPUT = os.path.join(base_dir, f"6. Symantec_removed_object_{today_str}.csv")
    SYMANTEC_JSON_OUTPUT = os.path.join(base_dir, f"7. Symantec_policy_summary_{today_str}.json")
    COMPARISON_VIEWER_OUTPUT = os.path.join(base_dir, f"8. Somansa_Symantec_policy_viewer_{today_str}.html")
    
    skip_auto_update = False
    if "Auto_Update_Blacklist_Deny" in raw_input:
        print(f"\n{Fore.CYAN}========================================")
        print(f"{Fore.CYAN} 🚨 [대용량 카테고리 감지]")
        print(f"{Fore.WHITE} 'Auto_Update_Blacklist_Deny' 웹 카테고리가 발견되었습니다.")
        print(f"{Fore.WHITE} 이 카테고리는 방대한 양의 URL을 포함하고 있어 변환 시 오랜 시간이 걸릴 수 있습니다.")
        print(f"{Fore.CYAN}========================================")
        
        ans = input(f"{Fore.YELLOW}👉 해당 카테고리를 변환하시겠습니까? (아니오 선택 시 스킵) (Y/N) [기본값: N]: ").strip().lower()
        if ans != 'y':
            skip_auto_update = True
            print(f"{Fore.GREEN}▶ 해당 카테고리 변환을 스킵합니다.")
        else:
            print(f"{Fore.YELLOW}▶ 해당 카테고리를 변환에 포함합니다. (시간이 오래 걸릴 수 있습니다)")

    print(f"\n{Fore.CYAN}========================================")
    print(f"{Fore.CYAN} 🚀 [엔진 구동] 데이터 추출 및 변환 시작...")
    print(f"{Fore.CYAN}========================================")

    # [2번 파일] extract_policy_to_json 실행
    print(f"{Fore.GREEN}▶ [1/6] 정책 추출 및 JSON 요약 파일(2번) 생성 중...")
    policy_json_data = extract_policy_to_json(raw_input, skip_auto_update)
    clean_json_data = []
    for p in policy_json_data:
        clean_p = {k: v for k, v in p.items() if not k.startswith('_')}
        clean_json_data.append(clean_p)
        
    with open(JSON_OUTPUT, 'w', encoding='utf-8') as f:
        json.dump(clean_json_data, f, ensure_ascii=False, indent=4)
        
    # [3번 파일] generate_html_viewer 실행
    print(f"{Fore.GREEN}▶ [2/6] 원본 검토 HTML 뷰어(3번) 생성 중...")
    generate_html_viewer(policy_json_data, VIEWER_OUTPUT)
    
    # [4, 5, 6, 7번 파일] convert_somansa_to_symantec 실행
    print(f"{Fore.GREEN}▶ [3/6] 시만텍 VPM XML(5번) 1차 변환 진행 중 (시간이 소요될 수 있습니다)...")
    output_xml, exception_pages_text, removed_csv_data, tracked_exceptions, symantec_json_data, negated_items_log, space_slash_log, http_dot_log = convert_somansa_to_symantec(raw_input, selected_mode, optimize_choice, internal_networks, skip_auto_update, unify_deny_choice)
    
    if removed_csv_data:
        print(f"{Fore.GREEN}▶ [4/6] 최적화 완료: 미사용 객체 총 {len(removed_csv_data)}개 제거 및 목록(6번) 저장 중...")
        
        removed_counter = collections.Counter(item[0] for item in removed_csv_data)
        for obj_type, count in sorted(removed_counter.items(), key=lambda x: x[1], reverse=True):
            print(f"{Fore.WHITE}    ㄴ {obj_type} : {count}개")
            
        # 6번 파일 작성 (Deep GC 제거 객체 목록)
        with open(CSV_OUTPUT, 'w', encoding='utf-8-sig', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["객체 타입", "객체명", "객체 내용"])
            writer.writerows(removed_csv_data)
    else:
        print(f"{Fore.GREEN}▶ [4/6] 최적화 건너뜀 (미사용 객체 없음 또는 최적화 미선택)")
    
    # 5번 파일 작성 (시만텍 XML)
    with open(XML_OUTPUT, 'w', encoding='utf-8') as f:
        f.write(output_xml)
        
    print(f"{Fore.GREEN}▶ [5/6] 예외(차단) 페이지(4번) 및 시만텍 정책 요약 JSON(7번) 생성 중...")
    # 4번 파일 작성 (차단 예외 페이지 HTML 모음)
    with open(HTML_OUTPUT, 'w', encoding='utf-8') as f:
        f.write(exception_pages_text.strip() if exception_pages_text.strip() else "No Exception Page extracted.")

    # 7번 파일 작성 (시만텍 변환 정책 JSON 요약)
    clean_sym_json_data = []
    for p in symantec_json_data:
        clean_p = {k: v for k, v in p.items() if not k.startswith('_')}
        clean_sym_json_data.append(clean_p)
        
    with open(SYMANTEC_JSON_OUTPUT, 'w', encoding='utf-8') as f:
        json.dump(clean_sym_json_data, f, ensure_ascii=False, indent=4)

    # [8번 파일] generate_comparison_viewer 실행
    print(f"{Fore.GREEN}▶ [6/6] 1:1 비교 검증 HTML 뷰어(8번) 생성 중...")
    generate_comparison_viewer(policy_json_data, symantec_json_data, COMPARISON_VIEWER_OUTPUT)

    if tracked_exceptions:
        print(f"\n{Fore.MAGENTA}========================================")
        print(f"{Fore.MAGENTA}{Style.BRIGHT} 🚨 [강제 예외 처리 적용된 객체 목록]")
        print(f"{Fore.MAGENTA}========================================")
        for ex_obj in tracked_exceptions:
            print(f"{Fore.WHITE}  - {ex_obj}")

    if negated_items_log:
        print(f"\n{Fore.YELLOW}========================================")
        print(f"{Fore.YELLOW}{Style.BRIGHT} ⚠️ [Negate (부정조건) 제거 및 추적 목록]")
        print(f"{Fore.WHITE} 원본 정책 중 'Negate:' 문구가 포함된 객체에서 해당 문구를 정상적으로 분리/제거했습니다.")
        print(f"{Fore.YELLOW}========================================")
        for neg_log in negated_items_log:
            print(f"{Fore.WHITE}  - {neg_log}")
            
    if space_slash_log:
        print(f"\n{Fore.YELLOW}========================================")
        print(f"{Fore.YELLOW}{Style.BRIGHT} ✂️ [URL 도메인 공백(/) 오류 보정 추적 목록]")
        print(f"{Fore.WHITE} 도메인 뒤에 실수로 입력된 스페이스+슬래시( /)를 슬래시(/)로 자동 보정했습니다.")
        print(f"{Fore.YELLOW}========================================")
        for space_log in space_slash_log:
            print(f"{Fore.WHITE}  - {space_log}")

    if http_dot_log:
        print(f"\n{Fore.YELLOW}========================================")
        print(f"{Fore.YELLOW}{Style.BRIGHT} 🔗 [http://. 패턴 Advanced Path 변환 추적 목록]")
        print(f"{Fore.WHITE} 'http://.'로 시작하는 URL을 Advanced Request URL (Path) 타입으로 자동 변환했습니다.")
        print(f"{Fore.YELLOW}========================================")
        for h_log in http_dot_log:
            print(f"{Fore.WHITE}  - {h_log}")

    print(f"\n{Fore.CYAN}========================================")
    print(f"{Fore.GREEN}{Style.BRIGHT} ✅ 변환 및 추출 프로세스가 완벽하게 완료되었습니다!")
    print(f"{Fore.CYAN}========================================")
    print(f"{Fore.WHITE}👉 2. 정책 요약 JSON 파일 : {os.path.basename(JSON_OUTPUT)}")
    print(f"{Fore.WHITE}👉 3. 원본 검토 HTML 뷰어 : {os.path.basename(VIEWER_OUTPUT)}")
    print(f"{Fore.WHITE}👉 4. 예외 페이지 파일    : {os.path.basename(HTML_OUTPUT)}")
    print(f"{Fore.WHITE}👉 5. 시만텍 XML 파일     : {os.path.basename(XML_OUTPUT)}")
    if removed_csv_data:
        print(f"{Fore.WHITE}👉 6. 삭제 객체 CSV 파일  : {os.path.basename(CSV_OUTPUT)}")
    print(f"{Fore.WHITE}👉 7. 시만텍 JSON 요약    : {os.path.basename(SYMANTEC_JSON_OUTPUT)}")
    print(f"{Fore.WHITE}👉 8. 1:1 비교 HTML 뷰어  : {os.path.basename(COMPARISON_VIEWER_OUTPUT)}")
    print(f"{Fore.WHITE}(파일은 원본 파일과 동일한 경로에 저장되었습니다.)")
    
    input(f"\n{Fore.YELLOW}엔터(Enter) 키를 누르면 창이 닫힙니다...")