import sys
import subprocess
import os
import re
import csv
import tkinter as tk
from tkinter import filedialog
from concurrent.futures import ThreadPoolExecutor

# =========================================================
# 0. 의존성(Dependency) 체크 및 자동 설치 로직
# =========================================================
def check_and_install_dependencies():
    required_packages = {
        "deep-translator": "deep_translator",
        "colorama": "colorama"
    }
    missing_packages = []

    for pip_name, import_name in required_packages.items():
        try:
            __import__(import_name)
        except ImportError:
            missing_packages.append(pip_name)

    if missing_packages:
        print(f"필요한 라이브러리가 없습니다. 자동 설치를 시작합니다: {', '.join(missing_packages)}")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", *missing_packages])
            print("\n--- 설치가 성공적으로 완료되었습니다! ---\n")
        except Exception as e:
            print(f"자동 설치 중 오류가 발생했습니다.\n오류 내용: {e}")
            input("\n엔터를 누르면 종료됩니다...")
            sys.exit(1)

check_and_install_dependencies()

from deep_translator import GoogleTranslator
import colorama
from colorama import Fore, Back, Style

# Windows 환경에서도 색상이 정상적으로 출력되도록 초기화
colorama.init(autoreset=True)

# =========================================================
# 1. 메인 번역 로직
# =========================================================
def format_object_name(name):
    # 띄어쓰기를 '_'로 변경
    formatted_name = name.replace(' ', '_')
    # 영어로 시작하지 않으면 앞에 'a' 추가
    if formatted_name and not re.match(r'^[a-zA-Z]', formatted_name):
        formatted_name = 'a' + formatted_name
    return formatted_name

def fetch_translation(text_to_translate):
    """단일 텍스트를 번역하는 헬퍼 함수"""
    translator = GoogleTranslator(source='ko', target='en')
    try:
        raw_translation = translator.translate(text_to_translate)
        formatted_translation = format_object_name(raw_translation)
        return text_to_translate, formatted_translation
    except Exception as e:
        return text_to_translate, f"ERROR:{e}"

def translate_korean_to_english(text, base_name):
    korean_pattern = re.compile('[ㄱ-ㅎㅏ-ㅣ가-힣]+')
    quote_pattern = re.compile(r'"([^"]*)"') 
    
    # [추가] 파일 위치와 무관하게 <policy:block-message name="..."> 속성값을 찾아내는 정규식
    block_msg_name_pattern = re.compile(r'<policy:block-message[^>]*?name\s*=\s*"([^"]+)"', re.IGNORECASE)
    
    lines = text.split('\n')
    
    target_keywords = [
        'address name=', 
        'block-message value=', 
        'web-category-id value='
    ]

    # [수정] 섹션 판별과 정규식 글로벌 스캔을 통합한 매칭 함수
    def get_line_matches(line, current_section):
        # 1. 우선순위 1: 섹션 무관하게 <policy:block-message name="..."> 글로벌 스캔
        block_matches = block_msg_name_pattern.findall(line)
        if block_matches:
            return "REGEX_BLOCK_MSG", None, block_matches

        # 2. 우선순위 2: INSIDE 섹션 키워드 스캔
        if current_section == "INSIDE":
            for kw in target_keywords:
                if kw in line:
                    return "KEYWORD", kw, [line.split(kw)[1]]
                    
        # 3. 우선순위 3: BEFORE 섹션 일반 따옴표 스캔
        if current_section == "BEFORE":
            q_matches = quote_pattern.findall(line)
            if q_matches:
                return "QUOTE", None, q_matches
                
        return None, None, []

    # ---------------------------------------------------------
    # 1단계. 번역 대상 스캔
    # ---------------------------------------------------------
    unique_korean_texts = set()
    total_eligible_lines = 0
    section = "BEFORE" 
    
    for line in lines:
        if section == "BEFORE" and '<HTTP-Policy' in line:
            section = "INSIDE"
            
        match_type, kw_or_fullmatch, matches = get_line_matches(line, section)
        
        if match_type:
            has_korean = False
            for match in matches:
                if korean_pattern.search(match):
                    unique_korean_texts.add(match)
                    has_korean = True
                    
            if has_korean:
                total_eligible_lines += 1
                
        if section == "INSIDE" and ('</HTTP-Policy>' in line or '<HTTP-Policy/>' in line):
            section = "AFTER"

    if not unique_korean_texts:
        print(Fore.YELLOW + "번역할 대상(조건에 맞는 한글 텍스트)이 없습니다.")
        return text
        
    print(Fore.CYAN + Style.BRIGHT + f"\n--- 총 {total_eligible_lines}줄에서 {len(unique_korean_texts)}개의 고유 번역 대상을 찾았습니다. ---")
    print(Fore.MAGENTA + "멀티스레딩(고속) 번역을 시작합니다. 잠시만 기다려주세요...\n")
    
    # ---------------------------------------------------------
    # 2단계. 멀티스레딩 고속 번역
    # ---------------------------------------------------------
    translation_map = {}
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(fetch_translation, unique_korean_texts)
        
        for original, result in results:
            if result.startswith("ERROR:"):
                print(Fore.RED + f"[오류] '{original}' 번역 실패: {result}")
                translation_map[original] = original 
            else:
                translation_map[original] = result

    # ---------------------------------------------------------
    # 3단계. 문서 내용 치환
    # ---------------------------------------------------------
    translated_lines = []
    log_data = [] 
    current_count = 0
    section = "BEFORE"
    
    for line in lines:
        if section == "BEFORE" and '<HTTP-Policy' in line:
            section = "INSIDE"

        match_type, kw_or_fullmatch, matches = get_line_matches(line, section)

        if match_type:
            new_line = line
            has_translated = False

            for match in matches:
                if match in translation_map:
                    # [핵심] 매칭 타입별 맞춤형 치환 로직
                    if match_type == "QUOTE":
                        original_str = f'"{match}"'
                        translated_str = f'"{translation_map[match]}"'
                    elif match_type == "KEYWORD":
                        original_str = f'{kw_or_fullmatch}{match}'
                        translated_str = f'{kw_or_fullmatch}{translation_map[match]}'
                    elif match_type == "REGEX_BLOCK_MSG":
                        original_str = f'name="{match}"'
                        translated_str = f'name="{translation_map[match]}"'
                        
                    new_line = new_line.replace(original_str, translated_str)
                    has_translated = True
                    
            if has_translated:
                current_count += 1
                print(Fore.CYAN + f"[{current_count}/{total_eligible_lines}]")
                print(f"  - 원본: {line.strip()}")
                print(f"  - 결과: " + Fore.GREEN + Style.BRIGHT + f"{new_line.strip()}\n")
                
                log_data.append([line.strip(), new_line.strip()])
            
            translated_lines.append(new_line)
        else:
            translated_lines.append(line)

        if section == "INSIDE" and ('</HTTP-Policy>' in line or '<HTTP-Policy/>' in line):
            section = "AFTER"
            
    # ---------------------------------------------------------
    # 4단계. 번역 로그 저장
    # ---------------------------------------------------------
    log_file = f"{base_name}_translation_log.csv"
    try:
        if log_data:
            with open(log_file, 'w', encoding='utf-8-sig', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['원본(Original)', '번역결과(Translated)']) 
                writer.writerows(log_data)
            print(Fore.YELLOW + f"--- 번역 기록이 엑셀(CSV) 파일로 저장되었습니다: {log_file} ---")
    except Exception as e:
        print(Fore.RED + f"로그 파일 저장 중 오류 발생: {e}")
            
    print(Fore.CYAN + Style.BRIGHT + "--- 번역이 모두 완료되었습니다! ---\n")
    return '\n'.join(translated_lines)

# =========================================================
# 2. 파일 입출력 로직
# =========================================================
def process_file(file_path):
    base_name, extension = os.path.splitext(file_path)
    output_file = f"{base_name}_EN{extension}"

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        final_content = translate_korean_to_english(content, base_name)

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(final_content)
        
        print(Fore.GREEN + Style.BRIGHT + f"★ 성공! 번역된 최종 파일이 생성되었습니다: {output_file}\n")

    except FileNotFoundError:
        print(Fore.RED + "파일을 찾을 수 없습니다. 경로를 확인해주세요.\n")
    except Exception as e:
        print(Fore.RED + f"파일 처리 중 오류 발생: {e}\n")

def select_file():
    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)

    file_path = filedialog.askopenfilename(
        title="번역할 파일을 선택하세요",
        filetypes=[("Text files", "*.txt"), ("XML files", "*.xml"), ("All files", "*.*")]
    )
    return file_path

# =========================================================
# 실행 시작점
# =========================================================
if __name__ == "__main__":
    try:
        print(Fore.YELLOW + "파일 선택 창을 엽니다...")
        selected_file = select_file()
        
        if selected_file:
            print(Fore.GREEN + f"선택된 파일: {selected_file}")
            process_file(selected_file)
        else:
            print(Fore.RED + "파일 선택이 취소되었습니다.")
            
    except Exception as e:
        # 예상치 못한 에러가 발생해도 창이 꺼지지 않도록 에러 메시지 출력
        print(Fore.RED + Back.WHITE + f"\n[치명적 오류 발생] {e}")
        
    finally:
        # 정상 종료든 에러든 무조건 여기서 대기합니다.
        print(Style.RESET_ALL) # 색상 설정 초기화
        input(Fore.WHITE + Back.BLUE + Style.BRIGHT + "\n 작업이 모두 끝났습니다. 창을 닫으려면 엔터(Enter) 키를 누르세요... " + Style.RESET_ALL)