import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
from datetime import datetime
import json

# 엔진 선택 (Selenium 우선, 없으면 requests 기반)
SELENIUM_AVAILABLE = False
try:
    from xss_engine_selenium import SeleniumCrawler, SeleniumXSSScanner, PageInfo, ScanResult, StoredXSSResult
    SiteCrawler = SeleniumCrawler
    XSSScanner = SeleniumXSSScanner
    SELENIUM_AVAILABLE = True
    print("✅ Selenium 엔진 로드됨")
except ImportError as e:
    print(f"⚠️ Selenium 엔진 없음, requests 기반 사용: {e}")
    from xss_engine import SiteCrawler, XSSScanner, PageInfo, ScanResult, StoredXSSResult

class XSSScannerGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("XSS 취약점 탐지 도구 v5.5 - Alert 모드 추가")
        self.root.geometry("1100x850")
        self.root.minsize(1000, 750)
        
        self.colors = {
            'bg': '#1e1e1e', 'fg': '#ffffff', 'accent': '#007acc',
            'success': '#4caf50', 'warning': '#ff9800', 'danger': '#f44336',
            'secondary': '#2d2d2d', 'border': '#3d3d3d',
            'critical': '#ff1744', 'high': '#ff5722', 'medium': '#ffc107', 'low': '#8bc34a'
        }
        
        self.root.configure(bg=self.colors['bg'])
        self.crawler = None
        self.scanner = None
        self.pages = []
        self.results = []
        self.stored_results = []
        self.scan_start_time = None
        
        self._setup_styles()
        self._create_widgets()
    
    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('.', background=self.colors['bg'], foreground=self.colors['fg'])
        style.configure('TFrame', background=self.colors['bg'])
        style.configure('TLabel', background=self.colors['bg'], foreground=self.colors['fg'])
        style.configure('TButton', background=self.colors['accent'], foreground=self.colors['fg'], padding=(10, 5))
        style.map('TButton', background=[('active', '#005a9e'), ('disabled', '#555555')])
        style.configure('Danger.TButton', background=self.colors['danger'])
        style.configure('Success.TButton', background=self.colors['success'])
        style.configure('TProgressbar', background=self.colors['accent'], troughcolor=self.colors['secondary'])
        style.configure('TNotebook', background=self.colors['bg'])
        style.configure('TNotebook.Tab', background=self.colors['secondary'], foreground=self.colors['fg'], padding=(10, 5))
        
        # Treeview 스타일
        style.configure('Treeview', 
            background=self.colors['secondary'], 
            foreground=self.colors['fg'], 
            fieldbackground=self.colors['secondary'],
            rowheight=25)
        style.configure('Treeview.Heading', 
            background=self.colors['border'], 
            foreground=self.colors['fg'],
            font=('Segoe UI', 10, 'bold'))
    
    def _create_widgets(self):
        main_frame = ttk.Frame(self.root, padding=15)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # ===== 헤더 =====
        header = ttk.Frame(main_frame)
        header.pack(fill=tk.X, pady=(0, 10))
        title = tk.Label(header, text="🔍 XSS 취약점 탐지 도구 v5.5", 
            font=('Segoe UI', 16, 'bold'), bg=self.colors['bg'], fg=self.colors['fg'])
        title.pack(side=tk.LEFT)
        
        engine_text = "Selenium (JS 실행)" if SELENIUM_AVAILABLE else "Requests (정적)"
        engine_color = self.colors['success'] if SELENIUM_AVAILABLE else self.colors['warning']
        tk.Label(header, text=f"[{engine_text}]", 
            font=('Segoe UI', 10), bg=self.colors['bg'], fg=engine_color).pack(side=tk.LEFT, padx=10)
        
        tk.Label(header, text="⚠️ 권한이 있는 사이트만!", 
            font=('Segoe UI', 10), bg=self.colors['bg'], fg=self.colors['warning']).pack(side=tk.RIGHT)
        
        # ===== URL 입력 =====
        url_frame = ttk.Frame(main_frame)
        url_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(url_frame, text="시작 URL:", font=('Segoe UI', 11)).pack(side=tk.LEFT)
        self.url_entry = tk.Entry(url_frame, font=('Consolas', 11), 
            bg=self.colors['secondary'], fg=self.colors['fg'], insertbackground='white',
            relief=tk.FLAT, highlightthickness=1, highlightbackground=self.colors['border'])
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10)
        self.url_entry.insert(0, "http://localhost:3000")
        
        ttk.Button(url_frame, text="📋", command=self._paste_url, width=3).pack(side=tk.RIGHT)
        
        # ===== 쿠키 입력 =====
        cookie_frame = ttk.Frame(main_frame)
        cookie_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(cookie_frame, text="쿠키 설정:", font=('Segoe UI', 11)).pack(side=tk.LEFT)
        self.cookie_entry = tk.Entry(cookie_frame, font=('Consolas', 10), 
            bg=self.colors['secondary'], fg='#888888', insertbackground='white',
            relief=tk.FLAT)
        self.cookie_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10)
        self.cookie_entry.insert(0, "PHPSESSID=xxx; session=yyy (비워두면 비로그인)")
        self.cookie_entry.bind("<FocusIn>", self._on_cookie_focus)
        
        # ===== 설정 영역 =====
        settings_frame = ttk.Frame(main_frame)
        settings_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(settings_frame, text="최대 페이지:").pack(side=tk.LEFT)
        self.max_pages_var = tk.StringVar(value="30")
        tk.Entry(settings_frame, textvariable=self.max_pages_var, width=5, 
            font=('Consolas', 10), bg=self.colors['secondary'], fg=self.colors['fg']).pack(side=tk.LEFT, padx=(5, 15))
        
        ttk.Label(settings_frame, text="최대 깊이:").pack(side=tk.LEFT)
        self.max_depth_var = tk.StringVar(value="3")
        tk.Entry(settings_frame, textvariable=self.max_depth_var, width=5,
            font=('Consolas', 10), bg=self.colors['secondary'], fg=self.colors['fg']).pack(side=tk.LEFT, padx=(5, 15))
        
        self.quick_mode_var = tk.BooleanVar(value=True)
        tk.Checkbutton(settings_frame, text="빠른 스캔", 
            variable=self.quick_mode_var, bg=self.colors['bg'], fg=self.colors['fg'], 
            selectcolor=self.colors['secondary'], activebackground=self.colors['bg']).pack(side=tk.LEFT, padx=10)
        
        # Selenium 전용 옵션
        if SELENIUM_AVAILABLE:
            self.headless_var = tk.BooleanVar(value=True)
            tk.Checkbutton(settings_frame, text="Headless (브라우저 숨김)", 
                variable=self.headless_var, bg=self.colors['bg'], fg=self.colors['fg'], 
                selectcolor=self.colors['secondary'], activebackground=self.colors['bg']).pack(side=tk.LEFT, padx=10)
            
            # [v5.5] Alert 모드 체크박스 추가
            self.alert_mode_var = tk.BooleanVar(value=False)
            tk.Checkbutton(settings_frame, text="🔔 Alert 모드 (팝업)", 
                variable=self.alert_mode_var, bg=self.colors['bg'], fg=self.colors['fg'], 
                selectcolor=self.colors['secondary'], activebackground=self.colors['bg']).pack(side=tk.LEFT, padx=10)
        else:
            self.headless_var = tk.BooleanVar(value=True)
            self.alert_mode_var = tk.BooleanVar(value=False)
        
        # ===== 버튼 영역 =====
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        self.start_btn = ttk.Button(btn_frame, text="🌐 사이트 전체 스캔", command=self._start_full_scan, width=18)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.page_btn = ttk.Button(btn_frame, text="📄 현재 페이지만", command=self._start_page_scan, width=15)
        self.page_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(btn_frame, text="⏹ 중단", command=self._stop_scan, width=10, style='Danger.TButton')
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn.state(['disabled'])
        
        # 오른쪽 버튼들
        ttk.Button(btn_frame, text="💾 보고서 저장", command=self._export_report, width=12).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(btn_frame, text="🗑 초기화", command=self._clear_all, width=10).pack(side=tk.RIGHT, padx=5)
        
        # ===== 진행률 =====
        progress_frame = ttk.Frame(main_frame)
        progress_frame.pack(fill=tk.X, pady=5)
        
        self.phase_label = tk.Label(progress_frame, text="대기 중", 
            font=('Segoe UI', 9), bg=self.colors['bg'], fg=self.colors['fg'], anchor='w', width=15)
        self.phase_label.pack(side=tk.LEFT)
        
        self.progress_var = tk.IntVar(value=0)
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10)
        
        self.progress_label = tk.Label(progress_frame, text="0%", 
            font=('Segoe UI', 9), bg=self.colors['bg'], fg=self.colors['fg'], width=5)
        self.progress_label.pack(side=tk.RIGHT)
        
        # ===== 결과 탭 노트북 =====
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # ----- 탭 1: 스캔 로그 -----
        log_frame = ttk.Frame(notebook)
        notebook.add(log_frame, text=" 📋 스캔 로그 ")
        
        # 로그 필터
        log_filter_frame = ttk.Frame(log_frame)
        log_filter_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(log_filter_frame, text="필터:").pack(side=tk.LEFT)
        self.log_filter_var = tk.StringVar(value="전체")
        for text in ["전체", "위험", "경고", "정보"]:
            tk.Radiobutton(log_filter_frame, text=text, variable=self.log_filter_var, value=text,
                bg=self.colors['bg'], fg=self.colors['fg'], selectcolor=self.colors['secondary'],
                command=self._filter_log).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(log_filter_frame, text="로그 복사", command=self._copy_log, width=10).pack(side=tk.RIGHT)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, 
            bg=self.colors['secondary'], fg=self.colors['fg'], font=('Consolas', 10),
            wrap=tk.WORD, relief=tk.FLAT)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.tag_config('info', foreground='#888888')
        self.log_text.tag_config('warning', foreground=self.colors['warning'])
        self.log_text.tag_config('danger', foreground=self.colors['danger'])
        self.log_text.tag_config('success', foreground=self.colors['success'])
        self.log_text.tag_config('critical', foreground=self.colors['critical'])
        
        self.all_logs = []  # 전체 로그 저장
        
        # ----- 탭 2: 저장된 XSS (게시글 내 XSS) -----
        stored_frame = ttk.Frame(notebook)
        notebook.add(stored_frame, text=" ⚠️ 저장된 XSS ")
        
        # 상단: 트리뷰
        stored_top = ttk.Frame(stored_frame)
        stored_top.pack(fill=tk.BOTH, expand=True)
        
        self.stored_tree = ttk.Treeview(stored_top, 
            columns=('severity', 'url', 'type', 'content', 'line'), 
            show='headings', selectmode='browse')
        self.stored_tree.heading('severity', text='위험도')
        self.stored_tree.heading('url', text='URL')
        self.stored_tree.heading('type', text='탐지 유형')
        self.stored_tree.heading('content', text='발견된 코드')
        self.stored_tree.heading('line', text='라인')
        
        self.stored_tree.column('severity', width=70, anchor='center')
        self.stored_tree.column('url', width=250)
        self.stored_tree.column('type', width=150)
        self.stored_tree.column('content', width=350)
        self.stored_tree.column('line', width=50, anchor='center')
        
        stored_scroll = ttk.Scrollbar(stored_top, orient=tk.VERTICAL, command=self.stored_tree.yview)
        self.stored_tree.configure(yscrollcommand=stored_scroll.set)
        self.stored_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        stored_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.stored_tree.tag_configure('critical', foreground=self.colors['critical'])
        self.stored_tree.tag_configure('high', foreground=self.colors['high'])
        self.stored_tree.tag_configure('medium', foreground=self.colors['medium'])
        
        # 하단: 상세 정보
        stored_detail = ttk.LabelFrame(stored_frame, text=" 상세 정보 ", padding=10)
        stored_detail.pack(fill=tk.X, pady=(10, 0))
        
        self.stored_detail_text = tk.Text(stored_detail, height=4, 
            bg=self.colors['secondary'], fg=self.colors['fg'], font=('Consolas', 10),
            wrap=tk.WORD, relief=tk.FLAT)
        self.stored_detail_text.pack(fill=tk.X)
        self.stored_detail_text.insert('1.0', '항목을 선택하면 상세 정보가 표시됩니다.')
        self.stored_detail_text.config(state='disabled')
        
        self.stored_tree.bind('<<TreeviewSelect>>', self._on_stored_select)
        
        # ----- 탭 3: 폼/파라미터 취약점 -----
        vuln_frame = ttk.Frame(notebook)
        notebook.add(vuln_frame, text=" 🔴 폼/파라미터 취약점 ")
        
        # 상단: 통계
        vuln_stats = ttk.Frame(vuln_frame)
        vuln_stats.pack(fill=tk.X, pady=(0, 5))
        
        self.vuln_stats_label = tk.Label(vuln_stats, 
            text="취약점: 0 | 반사: 0 | 테스트: 0", 
            font=('Segoe UI', 10), bg=self.colors['bg'], fg=self.colors['fg'])
        self.vuln_stats_label.pack(side=tk.LEFT)
        
        ttk.Button(vuln_stats, text="취약점만 보기", command=self._filter_vulnerable, width=12).pack(side=tk.RIGHT)
        
        # 트리뷰
        vuln_top = ttk.Frame(vuln_frame)
        vuln_top.pack(fill=tk.BOTH, expand=True)
        
        self.vuln_tree = ttk.Treeview(vuln_top, 
            columns=('status', 'url', 'param', 'payload', 'code'), 
            show='headings', selectmode='browse')
        self.vuln_tree.heading('status', text='상태')
        self.vuln_tree.heading('url', text='URL')
        self.vuln_tree.heading('param', text='파라미터')
        self.vuln_tree.heading('payload', text='페이로드')
        self.vuln_tree.heading('code', text='응답')
        
        self.vuln_tree.column('status', width=70, anchor='center')
        self.vuln_tree.column('url', width=250)
        self.vuln_tree.column('param', width=150)
        self.vuln_tree.column('payload', width=300)
        self.vuln_tree.column('code', width=50, anchor='center')
        
        vuln_scroll = ttk.Scrollbar(vuln_top, orient=tk.VERTICAL, command=self.vuln_tree.yview)
        self.vuln_tree.configure(yscrollcommand=vuln_scroll.set)
        self.vuln_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vuln_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.vuln_tree.tag_configure('vulnerable', foreground=self.colors['danger'])
        self.vuln_tree.tag_configure('reflected', foreground=self.colors['warning'])
        
        # 하단: 상세 정보 및 권장 조치
        vuln_detail = ttk.LabelFrame(vuln_frame, text=" 상세 정보 & 권장 조치 ", padding=10)
        vuln_detail.pack(fill=tk.X, pady=(10, 0))
        
        self.vuln_detail_text = tk.Text(vuln_detail, height=5, 
            bg=self.colors['secondary'], fg=self.colors['fg'], font=('Consolas', 10),
            wrap=tk.WORD, relief=tk.FLAT)
        self.vuln_detail_text.pack(fill=tk.X)
        self.vuln_detail_text.insert('1.0', '항목을 선택하면 상세 정보와 권장 조치가 표시됩니다.')
        self.vuln_detail_text.config(state='disabled')
        
        self.vuln_tree.bind('<<TreeviewSelect>>', self._on_vuln_select)
        
        # ----- 탭 4: 크롤링된 페이지 -----
        pages_frame = ttk.Frame(notebook)
        notebook.add(pages_frame, text=" 🌐 크롤링된 페이지 ")
        
        self.pages_tree = ttk.Treeview(pages_frame, 
            columns=('url', 'forms', 'params', 'status'), 
            show='headings')
        self.pages_tree.heading('url', text='URL')
        self.pages_tree.heading('forms', text='폼')
        self.pages_tree.heading('params', text='파라미터')
        self.pages_tree.heading('status', text='상태')
        
        self.pages_tree.column('url', width=500)
        self.pages_tree.column('forms', width=80, anchor='center')
        self.pages_tree.column('params', width=80, anchor='center')
        self.pages_tree.column('status', width=100, anchor='center')
        
        pages_scroll = ttk.Scrollbar(pages_frame, orient=tk.VERTICAL, command=self.pages_tree.yview)
        self.pages_tree.configure(yscrollcommand=pages_scroll.set)
        self.pages_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        pages_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # ===== 상태바 =====
        status_frame = tk.Frame(main_frame, bg=self.colors['secondary'], height=30)
        status_frame.pack(fill=tk.X, pady=(10, 0))
        status_frame.pack_propagate(False)
        
        self.status_label = tk.Label(status_frame, text="준비됨", 
            font=('Segoe UI', 9), bg=self.colors['secondary'], fg=self.colors['fg'], anchor='w')
        self.status_label.pack(side=tk.LEFT, padx=10, fill=tk.Y)
        
        self.count_label = tk.Label(status_frame, 
            text="페이지: 0 | 저장된XSS: 0 | 취약점: 0 | 반사: 0", 
            font=('Segoe UI', 9), bg=self.colors['secondary'], fg=self.colors['fg'])
        self.count_label.pack(side=tk.RIGHT, padx=10)
        
        # 초기 메시지
        self._log("=" * 50, 'info')
        self._log("XSS 취약점 탐지 도구 v5.5", 'success')
        if SELENIUM_AVAILABLE:
            self._log("🌐 Selenium 엔진 (JavaScript 실행 지원)", 'success')
        else:
            self._log("📄 Requests 엔진 (정적 분석)", 'warning')
        self._log("=" * 50, 'info')
        self._log("", 'info')
        self._log("✨ 기능:", 'success')
        self._log("  • 사이트 전체 크롤링 (게시글 포함)", 'info')
        self._log("  • 저장된 XSS 탐지 (콘텐츠 분석)", 'info')
        if SELENIUM_AVAILABLE:
            self._log("  • 실제 XSS 실행 확인 (콘솔 로그 캡처)", 'info')
            self._log("  • JavaScript 렌더링 후 DOM 분석", 'info')
            self._log("  • 🔔 Alert 모드 - 팝업으로 XSS 확인 (NEW!)", 'success')
        self._log("  • 폼/파라미터 취약점 스캔", 'info')
        self._log("  • Cookie 세션 지원", 'info')
        self._log("", 'info')
        self._log("💡 팁: Alert 모드 체크 시 XSS 성공이 팝업으로 표시됩니다.", 'info')
        self._log("⚠️ 주의: 권한이 있는 사이트에서만 사용하세요!", 'warning')
        self._log("", 'info')
    
    # ===== 유틸리티 함수 =====
    
    def _paste_url(self):
        try:
            self.url_entry.delete(0, tk.END)
            self.url_entry.insert(0, self.root.clipboard_get())
        except: pass
    
    def _on_cookie_focus(self, event):
        if "비워두면" in self.cookie_entry.get():
            self.cookie_entry.delete(0, tk.END)
            self.cookie_entry.config(fg=self.colors['fg'])
    
    def _log(self, message: str, level: str = 'info'):
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = {'time': timestamp, 'message': message, 'level': level}
        self.all_logs.append(log_entry)
        
        if level == 'info':
            self.log_text.insert(tk.END, f"{message}\n", level)
        else:
            self.log_text.insert(tk.END, f"[{timestamp}] {message}\n", level)
        self.log_text.see(tk.END)
    
    def _filter_log(self):
        filter_type = self.log_filter_var.get()
        self.log_text.delete('1.0', tk.END)
        
        level_map = {
            "전체": None,
            "위험": ['danger', 'critical'],
            "경고": ['warning'],
            "정보": ['info', 'success']
        }
        
        allowed = level_map.get(filter_type)
        
        for log in self.all_logs:
            if allowed is None or log['level'] in allowed:
                if log['level'] == 'info':
                    self.log_text.insert(tk.END, f"{log['message']}\n", log['level'])
                else:
                    self.log_text.insert(tk.END, f"[{log['time']}] {log['message']}\n", log['level'])
    
    def _copy_log(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.log_text.get('1.0', tk.END))
        messagebox.showinfo("복사 완료", "로그가 클립보드에 복사되었습니다.")
    
    def _callback(self, message, level, data=None):
        if level == 'crawl_progress':
            self.root.after(0, lambda: self._update_progress(data, "크롤링"))
        elif level == 'scan_progress':
            self.root.after(0, lambda: self._update_progress(data, "스캔"))
        elif level == 'content_progress':
            self.root.after(0, lambda: self._update_progress(data, "콘텐츠 분석"))
        elif message:
            self.root.after(0, lambda: self._log(message, level))
    
    def _update_progress(self, value: int, phase: str):
        self.progress_var.set(value)
        self.progress_label.config(text=f"{value}%")
        self.phase_label.config(text=f"{phase} 중...")
    
    def _parse_cookies(self):
        cookie_str = self.cookie_entry.get().strip()
        if not cookie_str or "비워두면" in cookie_str:
            return None
        cookies = {}
        try:
            for item in cookie_str.split(';'):
                if '=' in item:
                    k, v = item.strip().split('=', 1)
                    cookies[k] = v
            self._log(f"🍪 쿠키 적용됨: {list(cookies.keys())}", 'success')
            return cookies
        except Exception as e:
            self._log(f"⚠️ 쿠키 파싱 오류: {e}", 'warning')
            return None
    
    def _set_ui_scanning(self, scanning: bool):
        state = ['disabled'] if scanning else ['!disabled']
        self.start_btn.state(state)
        self.page_btn.state(state)
        self.stop_btn.state(['!disabled'] if scanning else ['disabled'])
    
    def _get_severity(self, pattern_name: str) -> tuple:
        """위험도 판정"""
        critical_patterns = ['쿠키 접근', 'document.cookie', 'eval()', 'localStorage', 'sessionStorage']
        high_patterns = ['리다이렉트', 'document.location', 'window.location', 'fetch', 'XMLHttpRequest', 'document.write']
        medium_patterns = ['alert()', 'console.log', 'onerror', 'onload', 'onclick']
        
        for p in critical_patterns:
            if p.lower() in pattern_name.lower():
                return ('치명', self.colors['critical'])
        for p in high_patterns:
            if p.lower() in pattern_name.lower():
                return ('높음', self.colors['high'])
        for p in medium_patterns:
            if p.lower() in pattern_name.lower():
                return ('중간', self.colors['medium'])
        return ('낮음', self.colors['low'])
    
    def _get_recommendation(self, pattern_name: str, payload: str = "") -> str:
        """권장 조치 생성"""
        recommendations = {
            'script': "• 입력값에 대해 HTML 엔티티 인코딩 적용\n• Content-Security-Policy 헤더 설정\n• XSS 필터 라이브러리 사용 (DOMPurify 등)",
            'onerror': "• 이벤트 핸들러 속성 필터링\n• 이미지 src 검증 강화\n• CSP에서 inline script 차단",
            'onload': "• 이벤트 핸들러 속성 제거\n• 태그 화이트리스트 적용",
            'onclick': "• 이벤트 핸들러 속성 필터링\n• 사용자 입력에서 on* 속성 제거",
            'javascript:': "• javascript: URI 스킴 차단\n• href/src 속성값 검증",
            'cookie': "• HttpOnly 쿠키 플래그 설정\n• Secure 플래그 설정\n• SameSite 속성 설정",
            'eval': "• eval() 사용 금지\n• JSON.parse() 등 안전한 대안 사용",
            'iframe': "• iframe src 화이트리스트 적용\n• X-Frame-Options 헤더 설정",
            'console': "• 입력값 검증 및 이스케이프\n• 프로덕션에서 console 출력 제거",
        }
        
        result = "📋 권장 조치:\n"
        for key, rec in recommendations.items():
            if key.lower() in pattern_name.lower() or key.lower() in payload.lower():
                result += rec + "\n"
                break
        else:
            result += "• 모든 사용자 입력값 검증\n• 출력 시 HTML 엔티티 인코딩\n• WAF(웹 방화벽) 도입 고려"
        
        return result
    
    # ===== 이벤트 핸들러 =====
    
    def _on_stored_select(self, event):
        selection = self.stored_tree.selection()
        if not selection:
            return
        
        item = self.stored_tree.item(selection[0])
        values = item['values']
        
        # 해당 결과 찾기
        for r in self.stored_results:
            if r.url in str(values[1]) and r.pattern_name == values[2]:
                severity, _ = self._get_severity(r.pattern_name)
                detail = f"""🔍 탐지 유형: {r.pattern_name}
📍 URL: {r.url}
📄 라인: {r.line_number if r.line_number > 0 else '알 수 없음'}
⚠️ 위험도: {severity}

📝 발견된 코드:
{r.matched_content}

{self._get_recommendation(r.pattern_name)}"""
                
                self.stored_detail_text.config(state='normal')
                self.stored_detail_text.delete('1.0', tk.END)
                self.stored_detail_text.insert('1.0', detail)
                self.stored_detail_text.config(state='disabled')
                break
    
    def _on_vuln_select(self, event):
        selection = self.vuln_tree.selection()
        if not selection:
            return
        
        item = self.vuln_tree.item(selection[0])
        values = item['values']
        
        # 해당 결과 찾기
        for r in self.results:
            if r.parameter == values[2] and r.payload[:30] in str(values[3]):
                status = "🔴 취약점 확인" if r.vulnerable else "🟡 반사만 감지"
                
                detail = f"""🔍 상태: {status}
📍 URL: {r.url}
📝 파라미터: {r.parameter}
💉 페이로드: {r.payload}
📊 응답 코드: {r.status_code}

📄 응답 스니펫:
{r.response_snippet if r.response_snippet else '없음'}

{self._get_recommendation('script', r.payload)}"""
                
                self.vuln_detail_text.config(state='normal')
                self.vuln_detail_text.delete('1.0', tk.END)
                self.vuln_detail_text.insert('1.0', detail)
                self.vuln_detail_text.config(state='disabled')
                break
    
    def _filter_vulnerable(self):
        """취약점만 필터링"""
        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)
        
        for r in self.results:
            if r.vulnerable:
                self.vuln_tree.insert('', tk.END, values=(
                    '🔴 취약',
                    r.url[:40] + '...' if len(r.url) > 40 else r.url,
                    r.parameter,
                    r.payload[:40] + '...' if len(r.payload) > 40 else r.payload,
                    r.status_code
                ), tags=('vulnerable',))
    
    # ===== 스캔 함수 =====
    
    def _start_full_scan(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("오류", "URL을 입력하세요.")
            return
        
        try:
            max_pages = int(self.max_pages_var.get())
            max_depth = int(self.max_depth_var.get())
        except:
            messagebox.showerror("오류", "최대 페이지/깊이는 숫자로 입력하세요.")
            return
        
        cookies = self._parse_cookies()
        self._set_ui_scanning(True)
        self._clear_results()
        self.scan_start_time = datetime.now()
        self.status_label.config(text="크롤링 중...")
        
        self._log("", 'info')
        self._log("=" * 50, 'info')
        self._log(f"🚀 스캔 시작: {url}", 'success')
        self._log(f"   최대 페이지: {max_pages}, 최대 깊이: {max_depth}", 'info')
        self._log("=" * 50, 'info')
        
        def worker():
            # 1단계: 크롤링
            headless = self.headless_var.get()
            
            if SELENIUM_AVAILABLE:
                self.crawler = SiteCrawler(url, cookies=cookies, max_pages=max_pages, 
                    max_depth=max_depth, headless=headless, callback=self._callback)
            else:
                self.crawler = SiteCrawler(url, cookies=cookies, max_pages=max_pages, 
                    max_depth=max_depth, callback=self._callback)
            
            self.pages = self.crawler.crawl()
            
            self.root.after(0, self._update_pages_tree)
            
            if self.crawler.stop_flag:
                self.root.after(0, lambda: self._scan_complete([], []))
                return
            
            # 2단계: 저장된 XSS 분석
            self.root.after(0, lambda: self.status_label.config(text="저장된 XSS 분석 중..."))
            
            alert_mode = self.alert_mode_var.get()  # [v5.5] Alert 모드 가져오기
            
            if SELENIUM_AVAILABLE:
                self.scanner = XSSScanner(cookies=cookies, headless=headless, callback=self._callback, alert_mode=alert_mode)
            else:
                self.scanner = XSSScanner(cookies=cookies, callback=self._callback)
            
            stored_results = self.scanner.scan_page_content(self.pages)
            
            if self.scanner.stop_flag:
                self.root.after(0, lambda: self._scan_complete([], stored_results))
                return
            
            # 3단계: 폼/파라미터 스캔
            self.root.after(0, lambda: self.status_label.config(text="XSS 스캔 중..."))
            results = self.scanner.scan_pages(self.pages, quick_mode=self.quick_mode_var.get())
            
            self.root.after(0, lambda: self._scan_complete(results, stored_results))
        
        threading.Thread(target=worker, daemon=True).start()
    
    def _start_page_scan(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("오류", "URL을 입력하세요.")
            return
        
        cookies = self._parse_cookies()
        self._set_ui_scanning(True)
        self._clear_results()
        self.scan_start_time = datetime.now()
        self.status_label.config(text="페이지 스캔 중...")
        
        self._log("", 'info')
        self._log(f"🚀 단일 페이지 스캔: {url}", 'success')
        
        def worker():
            headless = self.headless_var.get()
            
            if SELENIUM_AVAILABLE:
                self.crawler = SiteCrawler(url, cookies=cookies, max_pages=1, max_depth=0, 
                    headless=headless, callback=self._callback)
            else:
                self.crawler = SiteCrawler(url, cookies=cookies, max_pages=1, max_depth=0, 
                    callback=self._callback)
            
            self.pages = self.crawler.crawl()
            
            self.root.after(0, self._update_pages_tree)
            
            if not self.pages:
                self.root.after(0, lambda: self._scan_complete([], []))
                return
            
            alert_mode = self.alert_mode_var.get()  # [v5.5] Alert 모드 가져오기
            
            if SELENIUM_AVAILABLE:
                self.scanner = XSSScanner(cookies=cookies, headless=headless, callback=self._callback, alert_mode=alert_mode)
            else:
                self.scanner = XSSScanner(cookies=cookies, callback=self._callback)
            
            stored_results = self.scanner.scan_page_content(self.pages)
            results = self.scanner.scan_pages(self.pages, quick_mode=self.quick_mode_var.get())
            
            self.root.after(0, lambda: self._scan_complete(results, stored_results))
        
        threading.Thread(target=worker, daemon=True).start()
    
    def _stop_scan(self):
        if self.crawler:
            self.crawler.stop()
        if self.scanner:
            self.scanner.stop()
        self._log("⏹ 중단 요청됨...", 'warning')
    
    def _update_pages_tree(self):
        for item in self.pages_tree.get_children():
            self.pages_tree.delete(item)
        
        for page in self.pages:
            status = "입력필드 있음" if (page.forms or page.params) else "-"
            self.pages_tree.insert('', tk.END, values=(
                page.url[:70] + '...' if len(page.url) > 70 else page.url,
                len(page.forms),
                len(page.params),
                status
            ))
    
    def _scan_complete(self, results, stored_results):
        self.results = results
        self.stored_results = stored_results
        self._set_ui_scanning(False)
        self.progress_var.set(100)
        self.progress_label.config(text="100%")
        self.phase_label.config(text="완료")
        self.status_label.config(text="스캔 완료")
        
        # 소요 시간 계산
        if self.scan_start_time:
            elapsed = datetime.now() - self.scan_start_time
            elapsed_str = f"{elapsed.seconds}초"
        else:
            elapsed_str = "-"
        
        # 결과 분석
        vulnerable = [r for r in results if r.vulnerable]
        reflected = [r for r in results if r.reflected and not r.vulnerable]
        
        # 저장된 XSS 트리 업데이트
        for item in self.stored_tree.get_children():
            self.stored_tree.delete(item)
        
        for r in self.stored_results:
            severity, color = self._get_severity(r.pattern_name)
            tag = 'critical' if severity == '치명' else ('high' if severity == '높음' else 'medium')
            
            self.stored_tree.insert('', tk.END, values=(
                severity,
                r.url[:35] + '...' if len(r.url) > 35 else r.url,
                r.pattern_name,
                r.matched_content[:45] + '...' if len(r.matched_content) > 45 else r.matched_content,
                r.line_number if r.line_number > 0 else '-'
            ), tags=(tag,))
        
        # 취약점 트리 업데이트
        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)
        
        for r in vulnerable:
            self.vuln_tree.insert('', tk.END, values=(
                '🔴 취약',
                r.url[:35] + '...' if len(r.url) > 35 else r.url,
                r.parameter,
                r.payload[:35] + '...' if len(r.payload) > 35 else r.payload,
                r.status_code
            ), tags=('vulnerable',))
        
        for r in reflected:
            self.vuln_tree.insert('', tk.END, values=(
                '🟡 반사',
                r.url[:35] + '...' if len(r.url) > 35 else r.url,
                r.parameter,
                r.payload[:35] + '...' if len(r.payload) > 35 else r.payload,
                r.status_code
            ), tags=('reflected',))
        
        # 통계 업데이트
        self.vuln_stats_label.config(
            text=f"취약점: {len(vulnerable)} | 반사: {len(reflected)} | 테스트: {len(results)}"
        )
        self.count_label.config(
            text=f"페이지: {len(self.pages)} | 저장된XSS: {len(self.stored_results)} | 취약점: {len(vulnerable)} | 반사: {len(reflected)}"
        )
        
        # 결과 요약 로그
        self._log("", 'info')
        self._log("=" * 50, 'info')
        self._log("📊 스캔 완료!", 'success')
        self._log("=" * 50, 'info')
        self._log(f"⏱️ 소요 시간: {elapsed_str}", 'info')
        self._log(f"📄 크롤링된 페이지: {len(self.pages)}", 'info')
        self._log(f"🔍 총 테스트: {len(results)}", 'info')
        self._log("", 'info')
        
        if self.stored_results:
            critical_count = len([r for r in self.stored_results if self._get_severity(r.pattern_name)[0] == '치명'])
            high_count = len([r for r in self.stored_results if self._get_severity(r.pattern_name)[0] == '높음'])
            self._log(f"⚠️ 저장된 XSS 발견: {len(self.stored_results)}개", 'danger')
            if critical_count:
                self._log(f"   🔴 치명적: {critical_count}개", 'critical')
            if high_count:
                self._log(f"   🟠 높음: {high_count}개", 'danger')
        
        if vulnerable:
            self._log(f"🔴 폼/파라미터 취약점: {len(vulnerable)}개", 'danger')
        if reflected:
            self._log(f"🟡 반사 감지: {len(reflected)}개", 'warning')
        
        if not vulnerable and not reflected and not self.stored_results:
            self._log("🟢 취약점이 발견되지 않았습니다.", 'success')
        
        self._log("=" * 50, 'info')
    
    def _clear_results(self):
        for item in self.pages_tree.get_children():
            self.pages_tree.delete(item)
        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)
        for item in self.stored_tree.get_children():
            self.stored_tree.delete(item)
        
        self.progress_var.set(0)
        self.progress_label.config(text="0%")
        self.phase_label.config(text="대기 중")
        self.vuln_stats_label.config(text="취약점: 0 | 반사: 0 | 테스트: 0")
        self.count_label.config(text="페이지: 0 | 저장된XSS: 0 | 취약점: 0 | 반사: 0")
        
        self.stored_detail_text.config(state='normal')
        self.stored_detail_text.delete('1.0', tk.END)
        self.stored_detail_text.insert('1.0', '항목을 선택하면 상세 정보가 표시됩니다.')
        self.stored_detail_text.config(state='disabled')
        
        self.vuln_detail_text.config(state='normal')
        self.vuln_detail_text.delete('1.0', tk.END)
        self.vuln_detail_text.insert('1.0', '항목을 선택하면 상세 정보와 권장 조치가 표시됩니다.')
        self.vuln_detail_text.config(state='disabled')
    
    def _clear_all(self):
        self._clear_results()
        self.log_text.delete('1.0', tk.END)
        self.all_logs = []
        self.pages = []
        self.results = []
        self.stored_results = []
        self._log("🗑 초기화 완료", 'info')
    
    def _export_report(self):
        if not self.results and not self.stored_results:
            messagebox.showinfo("알림", "저장할 결과가 없습니다.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML 보고서", "*.html"), ("JSON", "*.json"), ("텍스트", "*.txt")],
            initialfilename=f"xss_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        
        if not filename:
            return
        
        vulnerable = [r for r in self.results if r.vulnerable]
        reflected = [r for r in self.results if r.reflected and not r.vulnerable]
        
        if filename.endswith('.html'):
            html = self._generate_html_report(vulnerable, reflected)
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html)
        elif filename.endswith('.json'):
            data = {
                'scan_time': datetime.now().isoformat(),
                'base_url': self.url_entry.get(),
                'pages_crawled': len(self.pages),
                'summary': {
                    'stored_xss': len(self.stored_results),
                    'vulnerabilities': len(vulnerable),
                    'reflections': len(reflected)
                },
                'stored_xss': [{'url': r.url, 'type': r.pattern_name, 'content': r.matched_content, 'line': r.line_number} for r in self.stored_results],
                'vulnerabilities': [{'url': r.url, 'param': r.parameter, 'payload': r.payload, 'status': r.status_code} for r in vulnerable]
            }
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        else:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"XSS 취약점 스캔 보고서\n")
                f.write(f"생성 시간: {datetime.now()}\n")
                f.write(f"대상 URL: {self.url_entry.get()}\n")
                f.write(f"크롤링된 페이지: {len(self.pages)}\n\n")
                f.write(f"=== 저장된 XSS ({len(self.stored_results)}개) ===\n")
                for r in self.stored_results:
                    f.write(f"  [{r.pattern_name}] {r.url}\n    {r.matched_content[:80]}\n\n")
                f.write(f"\n=== 폼/파라미터 취약점 ({len(vulnerable)}개) ===\n")
                for r in vulnerable:
                    f.write(f"  {r.url}\n    파라미터: {r.parameter}\n    페이로드: {r.payload}\n\n")
        
        messagebox.showinfo("저장 완료", f"보고서가 저장되었습니다:\n{filename}")
    
    def _generate_html_report(self, vulnerable, reflected):
        stored_rows = ""
        for r in self.stored_results:
            severity, color = self._get_severity(r.pattern_name)
            stored_rows += f"""<tr style="color:{color}">
                <td>{severity}</td>
                <td>{r.url[:50]}...</td>
                <td>{r.pattern_name}</td>
                <td><code>{r.matched_content[:60]}...</code></td>
            </tr>"""
        
        vuln_rows = ""
        for r in vulnerable:
            vuln_rows += f"""<tr style="color:#f44336">
                <td>🔴 취약</td>
                <td>{r.url[:50]}...</td>
                <td>{r.parameter}</td>
                <td><code>{r.payload[:50]}...</code></td>
            </tr>"""
        
        return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>XSS 스캔 보고서</title>
<style>
body {{ font-family: 'Segoe UI', sans-serif; background: #1e1e1e; color: #fff; padding: 30px; line-height: 1.6; }}
.container {{ max-width: 1200px; margin: 0 auto; }}
h1 {{ color: #007acc; border-bottom: 2px solid #007acc; padding-bottom: 10px; }}
h2 {{ color: #4caf50; margin-top: 40px; }}
.summary {{ background: #2d2d2d; padding: 20px; border-radius: 10px; margin: 20px 0; display: flex; gap: 30px; }}
.stat {{ text-align: center; }}
.stat-num {{ font-size: 36px; font-weight: bold; }}
.critical {{ color: #ff1744; }}
.high {{ color: #ff5722; }}
.medium {{ color: #ffc107; }}
table {{ width: 100%; border-collapse: collapse; margin: 20px 0; background: #2d2d2d; border-radius: 8px; overflow: hidden; }}
th {{ background: #3d3d3d; padding: 12px; text-align: left; }}
td {{ padding: 10px; border-bottom: 1px solid #3d3d3d; }}
code {{ background: #3d3d3d; padding: 2px 8px; border-radius: 4px; font-size: 12px; }}
.recommendation {{ background: #1a237e; padding: 15px; border-radius: 8px; margin: 20px 0; }}
</style></head>
<body><div class="container">
<h1>🔍 XSS 취약점 스캔 보고서</h1>
<p>생성 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<p>대상 URL: <code>{self.url_entry.get()}</code></p>

<div class="summary">
    <div class="stat"><div class="stat-num">{len(self.pages)}</div>크롤링된 페이지</div>
    <div class="stat critical"><div class="stat-num">{len(self.stored_results)}</div>저장된 XSS</div>
    <div class="stat high"><div class="stat-num">{len(vulnerable)}</div>폼 취약점</div>
    <div class="stat medium"><div class="stat-num">{len(reflected)}</div>반사 감지</div>
</div>

<h2>⚠️ 저장된 XSS ({len(self.stored_results)}개)</h2>
<table>
<tr><th>위험도</th><th>URL</th><th>유형</th><th>발견된 코드</th></tr>
{stored_rows if stored_rows else '<tr><td colspan="4">없음</td></tr>'}
</table>

<h2>🔴 폼/파라미터 취약점 ({len(vulnerable)}개)</h2>
<table>
<tr><th>상태</th><th>URL</th><th>파라미터</th><th>페이로드</th></tr>
{vuln_rows if vuln_rows else '<tr><td colspan="4">없음</td></tr>'}
</table>

<div class="recommendation">
<h3>📋 권장 조치</h3>
<ul>
<li>모든 사용자 입력값에 대해 서버 측 검증 수행</li>
<li>출력 시 HTML 엔티티 인코딩 적용 (&lt;, &gt;, &quot;, &#39;, &amp;)</li>
<li>Content-Security-Policy (CSP) 헤더 설정</li>
<li>HttpOnly, Secure, SameSite 쿠키 플래그 설정</li>
<li>XSS 필터 라이브러리 사용 (DOMPurify, sanitize-html 등)</li>
</ul>
</div>

</div></body></html>"""
    
    def run(self):
        self.root.mainloop()


if __name__ == '__main__':
    app = XSSScannerGUI()
    app.run()
