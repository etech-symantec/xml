import sys
import re
import os
import tkinter as tk
from tkinter import filedialog
from datetime import datetime
from copy import deepcopy
import xml.etree.ElementTree as ET

# ── XML 들여쓰기 보조 (Python 3.8 이하 호환) ─────────────────────────
def _indent(elem, level=0):
    pad = "\n" + "  " * level
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = pad + "  "
        if not elem.tail or not elem.tail.strip():
            elem.tail = pad
        for child in elem:
            _indent(child, level + 1)
        if not child.tail or not child.tail.strip():
            child.tail = pad
    else:
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = pad
    if not level:
        elem.tail = "\n"

# ── 객체 정규화 키 생성 ───────────────────────────────────────────────
def _elem_key(elem):
    """tag + attrib + 직계 자식 텍스트를 정규화한 문자열 → 중복 판단에 사용"""
    attrib_str = ";".join(f"{k}={v}" for k, v in sorted(elem.attrib.items()))
    children_str = "|".join(
        f"{c.tag}:{';'.join(f'{k}={v}' for k,v in sorted(c.attrib.items()))}:{(c.text or '').strip()}"
        for c in elem
    )
    return f"{elem.tag}||{attrib_str}||{children_str}"

# ── 객체 이름 추출 ────────────────────────────────────────────────────
def _obj_name(elem):
    return elem.get("name") or elem.get("n") or ""

# ── comb-obj / categorylist4 내부의 참조 이름 수집 ────────────────────
def _collect_internal_refs(elem):
    refs = set()
    # comb-obj: <c-l-1 n="...">, <c-l-2 n="...">
    for ref in elem.findall("c-l-1") + elem.findall("c-l-2"):
        n = ref.get("n")
        if n:
            refs.add(n)
    # categorylist4: <sel><i>name</i></sel>
    for i_tag in elem.iter("i"):
        if i_tag.text and i_tag.text.strip():
            refs.add(i_tag.text.strip())
    return refs

# ── rowItem 에서 직접 참조되는 객체명 수집 ────────────────────────────
def _collect_row_refs(layers_elem):
    refs = set()
    for row in layers_elem.iter("rowItem"):
        for col in row.findall("colItem"):
            name = col.get("name")
            if name and col.get("type") not in ("String",):
                refs.add(name)
            # policy-id(tr 컬럼) 등 String 이라도 이름 수집
            if name:
                refs.add(name)
    return refs

# ── 사용 객체 집합 (전이적 확장) ─────────────────────────────────────
def build_used_set(layers_elem, obj_map):
    """
    rowItem → 직접 참조 → comb-obj/categorylist4 내부 참조 순으로
    전이적으로 사용되는 모든 객체명을 반환
    """
    used = _collect_row_refs(layers_elem)

    # "Any", "None" 등 내장 문자열은 객체가 아님
    builtin = {"Any", "None", "Deny", "Allow", "Force Deny",
               "Disable SSL Interception", "Appliance"}
    used -= builtin

    # 전이 확장
    queue = list(used)
    while queue:
        name = queue.pop()
        elem = obj_map.get(name)
        if elem is None:
            continue
        inner = _collect_internal_refs(elem)
        new = inner - used - builtin
        used |= new
        queue.extend(new)

    return used

# ── vpm-cat <node> 사용 여부 확인 ─────────────────────────────────────
def build_used_nodes(layers_elem, vpm_cat_elem):
    """
    categorylist4의 <i> 값들이 vpm-cat 의 <node n="..."> 와 연결됨
    행에서 직접/간접 참조되는 node 이름만 남김
    """
    # categorylist4 내 <i> 텍스트 수집
    cat4_refs = set()
    for i_tag in layers_elem.iter("i"):
        if i_tag.text and i_tag.text.strip():
            cat4_refs.add(i_tag.text.strip())

    used_nodes = set()
    if vpm_cat_elem is not None:
        for node in vpm_cat_elem.findall("node"):
            n = node.get("n", "")
            if n in cat4_refs:
                used_nodes.add(n)
    return used_nodes

# ═════════════════════════════════════════════════════════════════════
# 메인 병합 로직
# ═════════════════════════════════════════════════════════════════════
def merge(http_path, tls_path, out_path):
    print(f"\n{'='*56}")
    print(f"  Symantec VPM XML 병합 시작")
    print(f"  HTTP : {os.path.basename(http_path)}")
    print(f"  TLS  : {os.path.basename(tls_path)}")
    print(f"{'='*56}\n")

    # ── 파싱 ───────────────────────────────────────────────────────
    ET.register_namespace("", "")
    http_tree = ET.parse(http_path)
    tls_tree  = ET.parse(tls_path)
    http_root = http_tree.getroot()
    tls_root  = tls_tree.getroot()

    http_cond = http_root.find("conditionObjects")
    tls_cond  = tls_root.find("conditionObjects")
    http_layers = http_root.find("layers")
    tls_layers  = tls_root.find("layers")

    # ── conditionObjects 병합 (중복 제거) ─────────────────────────
    # 결과를 담을 새 루트
    merged_root = ET.Element("vpmapp")
    ET.SubElement(merged_root, "vpmxml-info", version="631")
    ET.SubElement(merged_root, "enforcement-point", enabled="false")
    merged_cond = ET.SubElement(merged_root, "conditionObjects")

    # 객체 타입별 정렬 순서 (VPM 표준 순서 유지)
    OBJ_ORDER = [
        "vpm-cat", "a-url", "hdr-obj", "ipobject", "ip-list-object",
        "host-port", "comb-obj", "time", "categorylist4", "policy-id",
        "prot-meth", "dny-exc", "http-req-max-body-size", "ssl-fwd-prxy",
    ]

    # 태그별 컨테이너: {tag: {name: elem}}
    merged_objs = {tag: {} for tag in OBJ_ORDER}
    # 중복 통계
    dup_count = 0
    conflict_count = 0  # 이름 같으나 내용 다른 경우 → HTTP 우선 유지

    def add_objects(cond_elem, source_label):
        nonlocal dup_count, conflict_count
        for elem in cond_elem:
            tag = elem.tag
            if tag not in merged_objs:
                merged_objs[tag] = {}

            # vpm-cat 는 내부 <node> 단위로 처리
            if tag == "vpm-cat":
                if "vpm-cat" not in merged_objs:
                    merged_objs["vpm-cat"] = {}
                existing_nodes = merged_objs["vpm-cat"]  # {node_n: node_elem}
                for node in elem.findall("node"):
                    n = node.get("n", "")
                    if n not in existing_nodes:
                        existing_nodes[n] = deepcopy(node)
                    else:
                        key_new = _elem_key(node)
                        key_old = _elem_key(existing_nodes[n])
                        if key_new == key_old:
                            dup_count += 1
                        else:
                            conflict_count += 1  # HTTP 우선 → 이미 있으면 유지
                continue

            name = _obj_name(elem)
            if not name:
                # 이름 없는 객체(거의 없음)는 그냥 추가
                merged_objs.setdefault(tag, {})
                merged_objs[tag][f"__noname_{id(elem)}"] = deepcopy(elem)
                continue

            if name not in merged_objs[tag]:
                merged_objs[tag][name] = deepcopy(elem)
            else:
                key_new = _elem_key(elem)
                key_old = _elem_key(merged_objs[tag][name])
                if key_new == key_old:
                    dup_count += 1
                else:
                    conflict_count += 1
                    # HTTP(먼저 로드) 우선 → 덮어쓰지 않음

    # HTTP 먼저, TLS 나중 (충돌 시 HTTP 우선)
    add_objects(http_cond, "HTTP")
    add_objects(tls_cond,  "TLS")

    total_before = sum(
        len(v) for tag, v in merged_objs.items()
    )
    print(f"[1/4] conditionObjects 병합 완료")
    print(f"      중복(동일 객체) 제거: {dup_count}개")
    if conflict_count:
        print(f"      ⚠️  이름 동일·내용 상이 (HTTP 우선 유지): {conflict_count}개")
    print(f"      병합 후 총 객체 수 : {total_before}개\n")

    # ── 레이어 병합: SSL Intercept 먼저, Web Access 나중 ──────────
    merged_layers = ET.SubElement(merged_root, "layers")

    tls_layer_elems  = list(tls_layers.findall("layer"))
    http_layer_elems = list(http_layers.findall("layer"))

    ssl_layers = [l for l in tls_layer_elems
                  if "SSLIntercept" in l.get("layertype", "")]
    web_layers = [l for l in http_layer_elems
                  if "WebAccess" in l.get("layertype", "")]
    # 혹시 반대편에 있을 수도 있으니 모두 수집
    ssl_layers += [l for l in http_layer_elems
                   if "SSLIntercept" in l.get("layertype", "")]
    web_layers += [l for l in tls_layer_elems
                   if "WebAccess" in l.get("layertype", "")]

    total_rows = 0
    for layer in ssl_layers + web_layers:
        merged_layers.append(deepcopy(layer))
        rows = len(layer.findall("rowItem"))
        total_rows += rows

    print(f"[2/4] 레이어 병합 완료")
    print(f"      SSL Intercept 레이어 : {len(ssl_layers)}개")
    print(f"      Web Access 레이어    : {len(web_layers)}개")
    print(f"      총 정책 행 수        : {total_rows}개\n")

    # ── 미사용 객체 탐지 및 제거 ─────────────────────────────────
    # 전체 객체 맵 생성 (name → elem)
    all_obj_map = {}
    for tag, name_map in merged_objs.items():
        if tag == "vpm-cat":
            for n, node_elem in name_map.items():
                all_obj_map[n] = node_elem
        else:
            for name, elem in name_map.items():
                all_obj_map[name] = elem

    used_set = build_used_set(merged_layers, all_obj_map)
    used_nodes = build_used_nodes(merged_layers,
                                  None)  # node 사용 여부는 categorylist4 기준

    # categorylist4가 참조하는 vpm-cat node 이름 수집
    cat4_node_refs = set()
    for name, elem in merged_objs.get("categorylist4", {}).items():
        if name in used_set:
            for i_tag in elem.iter("i"):
                if i_tag.text and i_tag.text.strip():
                    cat4_node_refs.add(i_tag.text.strip())

    removed = []  # [(tag, name)]

    def purge(tag, name_map):
        to_del = []
        for name in list(name_map.keys()):
            if name.startswith("__noname_"):
                continue  # 이름 없는 것은 유지
            if name not in used_set:
                to_del.append(name)
        for name in to_del:
            removed.append((tag, name))
            del name_map[name]

    for tag in OBJ_ORDER:
        if tag == "vpm-cat":
            node_map = merged_objs.get("vpm-cat", {})
            to_del = [n for n in node_map if n not in cat4_node_refs]
            for n in to_del:
                removed.append(("vpm-cat/node", n))
                del node_map[n]
        else:
            if tag in merged_objs:
                purge(tag, merged_objs[tag])

    print(f"[3/4] 미사용 객체 제거 완료: {len(removed)}개 삭제\n")

    # ── XML 조립 ─────────────────────────────────────────────────
    for tag in OBJ_ORDER:
        name_map = merged_objs.get(tag, {})
        if not name_map:
            continue

        if tag == "vpm-cat":
            vpm_cat_elem = ET.SubElement(merged_cond, "vpm-cat")
            for n, node_elem in name_map.items():
                vpm_cat_elem.append(deepcopy(node_elem))
        else:
            for name, elem in name_map.items():
                merged_cond.append(deepcopy(elem))

    # ── 직렬화 ────────────────────────────────────────────────────
    _indent(merged_root)
    tree_out = ET.ElementTree(merged_root)

    with open(out_path, "w", encoding="utf-8") as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        ET.indent(tree_out.getroot()) if hasattr(ET, "indent") else None
        tree_out.write(f, encoding="unicode", xml_declaration=False)

    total_after = sum(len(v) for v in merged_objs.values())
    print(f"[4/4] XML 저장 완료 → {os.path.basename(out_path)}")
    print(f"      최종 객체 수: {total_after}개\n")

    # ── 삭제 객체 상세 출력 ──────────────────────────────────────
    if removed:
        print(f"{'─'*56}")
        print(f"  🗑️  삭제된 미사용 객체 목록 (총 {len(removed)}개)")
        print(f"{'─'*56}")
        by_tag = {}
        for tag, name in removed:
            by_tag.setdefault(tag, []).append(name)
        for tag in sorted(by_tag.keys()):
            names = sorted(by_tag[tag])
            print(f"\n  [{tag}]  ({len(names)}개)")
            for n in names:
                print(f"    - {n}")
    else:
        print("  ✅ 미사용 객체 없음 — 모든 객체가 정책에서 사용됩니다.")

    print(f"\n{'='*56}")
    print(f"  병합 완료!")
    print(f"{'='*56}\n")


# ═════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    # Tkinter 루트 창 숨기기
    root = tk.Tk()
    root.withdraw()
    
    print("=" * 56)
    print(" 🛠️ Symantec VPM XML 병합 스크립트 시작")
    print("=" * 56)

    print("\n📂 [1/2] 병합할 Web Access (HTTP) 정책 XML 파일을 선택해 주세요...")
    http_path = filedialog.askopenfilename(
        title="1. Web Access (HTTP) XML 파일 선택",
        filetypes=[("XML Files", "*.xml"), ("All Files", "*.*")]
    )
    if not http_path:
        print("❌ 파일 선택이 취소되었습니다. 스크립트를 종료합니다.")
        input("\n엔터(Enter) 키를 누르면 창이 닫힙니다...")
        sys.exit(0)
    print(f"  👉 선택 완료: {http_path}")

    print("\n📂 [2/2] 병합할 SSL Intercept (TLS) 정책 XML 파일을 선택해 주세요...")
    tls_path = filedialog.askopenfilename(
        title="2. SSL Intercept (TLS) XML 파일 선택",
        filetypes=[("XML Files", "*.xml"), ("All Files", "*.*")]
    )
    if not tls_path:
        print("❌ 파일 선택이 취소되었습니다. 스크립트를 종료합니다.")
        input("\n엔터(Enter) 키를 누르면 창이 닫힙니다...")
        sys.exit(0)
    print(f"  👉 선택 완료: {tls_path}")

    today = datetime.now().strftime("%Y%m%d")
    base  = os.path.dirname(http_path) or "."
    out_path = os.path.join(base, f"5. Symantec_ALL_policy_{today}.xml")

    print("\n🚀 병합을 시작합니다...\n")
    merge(http_path, tls_path, out_path)
    
    input("\n✨ 처리가 완료되었습니다. 엔터(Enter) 키를 누르면 창이 닫힙니다...")