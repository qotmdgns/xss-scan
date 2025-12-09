"""
XSS Scanner Engine - Selenium 기반 (v5.5 - Alert 모드 추가)
수정 사항:
1. 이미지 로딩 차단 해제 (img onerror 탐지 위해 필수)
2. 페이지 로드 전략 Normal로 복구 (onload 이벤트 보장)
3. 대기 시간 0.8초 -> 2.0초로 안정화
4. [v5.5] Alert 모드 추가 - 팝업으로 XSS 실행 확인 가능
"""

import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple
from collections import deque

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException, NoAlertPresentException


# ============== XSS 페이로드 생성 함수 ==============

def get_payloads(quick_mode: bool = True, alert_mode: bool = False) -> List[str]:
    """
    XSS 테스트 페이로드 목록 생성
    
    Args:
        quick_mode: True면 빠른 스캔용 (7개), False면 전체 스캔용 (17개)
        alert_mode: True면 alert() 사용, False면 console.log() 사용
    
    Returns:
        페이로드 문자열 목록
    """
    # alert 모드: alert("XSS_TEST_1")
    # console 모드: console.log("XSS_TEST_1")
    func = 'alert' if alert_mode else 'console.log'
    
    # 빠른 스캔용 페이로드 (7개)
    quick_payloads = [
        f'<script>{func}("XSS_TEST_1")</script>',
        f'<img src=x onerror={func}("XSS_TEST_2")>',
        f'<svg onload={func}("XSS_TEST_3")>',
        f'" onmouseover="{func}(\'XSS_TEST_4\')"',
        f"' onmouseover='{func}(\"XSS_TEST_5\")'",
        f'javascript:{func}("XSS_TEST_6")',
        f'<body onload={func}("XSS_TEST_7")>',
    ]
    
    if quick_mode:
        return quick_payloads
    
    # 전체 스캔용 추가 페이로드 (10개 추가)
    full_payloads = quick_payloads + [
        f'<script>{func}("XSS_FULL_1")</script>',
        f'<input onfocus={func}("XSS_FULL_2") autofocus>',
        f'<details open ontoggle={func}("XSS_FULL_3")>',
        f'<marquee onstart={func}("XSS_FULL_4")>',
        f'<audio src=x onerror={func}("XSS_FULL_5")>',
        f'<video src=x onerror={func}("XSS_FULL_6")>',
        f'"><script>{func}("XSS_FULL_7")</script>',
        f"'><script>{func}('XSS_FULL_8')</script>",
        f'<iframe src="javascript:{func}(\'XSS_FULL_9\')">',
        f'<ScRiPt>{func}("XSS_FULL_10")</ScRiPt>',
    ]
    
    return full_payloads


# 기존 페이로드 (하위 호환성 유지)
XSS_PAYLOADS_QUICK = get_payloads(quick_mode=True, alert_mode=False)
XSS_PAYLOADS_FULL = get_payloads(quick_mode=False, alert_mode=False)

# 콘솔 로그로 탐지할 XSS 마커
XSS_MARKERS = ['XSS_TEST_', 'XSS_FULL_', 'XSS_ATTACK', 'XSS_SUCCESS']

# 저장된 XSS 탐지 패턴
STORED_XSS_PATTERNS = [
    (r'<img[^>]*\sonerror\s*=', 'img onerror XSS'),
    (r'<img[^>]*\sonload\s*=', 'img onload XSS'),
    (r'<svg[^>]*\sonload\s*=', 'svg onload XSS'),
    (r'<body[^>]*\sonload\s*=', 'body onload XSS'),
    (r'<[a-z]+[^>]*\sonerror\s*=', 'onerror 이벤트'),
    (r'<[a-z]+[^>]*\sonload\s*=', 'onload 이벤트'),
    (r'<[a-z]+[^>]*\sonclick\s*=', 'onclick 이벤트'),
    (r'<[a-z]+[^>]*\sonmouseover\s*=', 'onmouseover 이벤트'),
    (r'<script[^>]*>[\s\S]*?alert\s*\(', 'alert() 스크립트'),
    (r'<script[^>]*>[\s\S]*?console\s*\.', 'console 스크립트'),
    (r'href\s*=\s*["\']?\s*javascript\s*:', 'javascript: href'),
    (r'XSS[_\-]?(ATTACK|TEST|SUCCESS|PAYLOAD)', 'XSS 테스트 흔적'),
]

SAFE_DOMAINS = ['cdn.cloudflare.com', 'cdnjs.cloudflare.com', 'code.jquery.com', 
                'unpkg.com', 'cdn.jsdelivr.net', 'fonts.googleapis.com', 'google.com']


# ============== 데이터 클래스 ==============

@dataclass
class PageInfo:
    url: str
    title: str = ""
    forms: List[Dict] = field(default_factory=list)
    params: Dict = field(default_factory=dict)
    links: Set[str] = field(default_factory=set)
    console_logs: List[str] = field(default_factory=list)

@dataclass
class StoredXSSResult:
    url: str
    pattern_name: str
    matched_content: str
    line_number: int = 0
    console_evidence: str = ""
    
    def to_dict(self):
        return {
            'url': self.url,
            'pattern_name': self.pattern_name,
            'matched_content': self.matched_content,
            'line_number': self.line_number,
            'console_evidence': self.console_evidence
        }

@dataclass
class ScanResult:
    url: str
    parameter: str
    payload: str
    reflected: bool
    vulnerable: bool
    executed: bool = False
    console_output: str = ""
    response_snippet: Optional[str] = None
    status_code: int = 0
    
    def to_dict(self):
        return {
            'url': self.url,
            'parameter': self.parameter,
            'payload': self.payload,
            'reflected': self.reflected,
            'vulnerable': self.vulnerable,
            'executed': self.executed,
            'console_output': self.console_output
        }


# ============== Selenium 브라우저 관리 (탐지율 복구) ==============

class BrowserManager:
    """Selenium WebDriver 관리 - 탐지율 우선 설정"""
    
    def __init__(self, headless: bool = True, timeout: int = 10):
        self.headless = headless
        self.timeout = timeout
        self.driver = None
    
    def start(self) -> webdriver.Chrome:
        """브라우저 시작"""
        options = Options()
        
        if self.headless:
            options.add_argument('--headless=new')
        
        # 기본 옵션
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')
        options.add_argument('--window-size=1920,1080')
        options.add_argument('--log-level=0')
        
        # [복구] 이미지/JS 로딩 허용 (XSS 트리거를 위해 필수)
        # CSS와 폰트만 차단하여 최소한의 속도 확보
        prefs = {
            "profile.managed_default_content_settings.images": 1,      # 이미지 허용 (중요!)
            "profile.managed_default_content_settings.javascript": 1,  # JS 허용 (필수)
            "profile.managed_default_content_settings.stylesheets": 2, # CSS 차단 (속도)
            "profile.managed_default_content_settings.fonts": 2,       # 폰트 차단 (속도)
            "profile.managed_default_content_settings.popups": 2,
            "profile.managed_default_content_settings.geolocation": 2,
            "profile.managed_default_content_settings.media_stream": 2,
        }
        options.add_experimental_option("prefs", prefs)
        
        # [복구] 페이지 로드 전략 Normal (onload 이벤트 보장)
        options.page_load_strategy = 'normal'
        
        # 콘솔 로그 캡처 활성화
        options.set_capability('goog:loggingPrefs', {'browser': 'ALL'})
        
        try:
            try:
                import chromedriver_autoinstaller
                chromedriver_autoinstaller.install()
            except: pass
            
            self.driver = webdriver.Chrome(options=options)
            self.driver.set_page_load_timeout(self.timeout)
            return self.driver
        except Exception as e:
            raise Exception(f"Chrome 드라이버 시작 실패: {e}")
    
    def wait_for_ready(self, timeout=5):
        try:
            WebDriverWait(self.driver, timeout).until(
                lambda d: d.execute_script('return document.readyState') == 'complete'
            )
        except: pass

    def get_console_logs(self) -> List[str]:
        logs = []
        try:
            for entry in self.driver.get_log('browser'):
                logs.append(entry.get('message', ''))
        except: pass
        return logs
    
    def check_xss_in_console(self, logs: List[str] = None) -> Tuple[bool, str]:
        if logs is None:
            logs = self.get_console_logs()
        for log in logs:
            for marker in XSS_MARKERS:
                if marker in log:
                    return True, log
        return False, ""
    
    def check_dom_for_xss(self) -> List[Dict]:
        findings = []
        try:
            selectors = [
                ('img[onerror]', 'img onerror'),
                ('a[href^="javascript:"]', 'javascript: href'),
                ('[onload]', 'onload event')
            ]
            for selector, type_name in selectors:
                elements = self.driver.find_elements(By.CSS_SELECTOR, selector)
                for elem in elements[:3]:
                    findings.append({
                        'type': type_name,
                        'element': elem.get_attribute('outerHTML')[:150],
                        'severity': 'high'
                    })
        except: pass
        return findings
    
    def close(self):
        if self.driver:
            try: self.driver.quit()
            except: pass
            self.driver = None
    
    def add_cookies(self, cookies: Dict):
        if self.driver and cookies:
            for name, value in cookies.items():
                try: self.driver.add_cookie({'name': name, 'value': value})
                except: pass


# ============== 크롤러 ==============

class SeleniumCrawler:
    def __init__(self, base_url: str, cookies: Dict = None, max_pages: int = 30, 
                 max_depth: int = 3, headless: bool = True, timeout: int = 10, callback=None):
        self.base_url = self._normalize_url(base_url)
        self.cookies = cookies
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.headless = headless
        self.timeout = timeout
        self.callback = callback
        
        parsed = urlparse(self.base_url)
        self.domain = parsed.netloc
        self.scheme = parsed.scheme
        
        self.browser = BrowserManager(headless=headless, timeout=timeout)
        self.visited: Set[str] = set()
        self.pages: List[PageInfo] = []
        self.stop_flag = False
    
    @staticmethod
    def _normalize_url(url: str) -> str:
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url.rstrip('/')
    
    def log(self, message: str, level: str = 'info'):
        if self.callback: self.callback(message, level)
    
    def _is_same_domain(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            return parsed.netloc == self.domain or parsed.netloc == ''
        except: return False
    
    def _normalize_link(self, link: str, current_url: str) -> Optional[str]:
        try:
            link = link.split('#')[0].strip()
            if not link or link.startswith(('javascript:', 'mailto:', 'tel:')): return None
            
            if link.startswith('//'): full_url = f"{self.scheme}:{link}"
            elif link.startswith('/'): full_url = f"{self.scheme}://{self.domain}{link}"
            elif link.startswith('http'): full_url = link
            else: full_url = urljoin(current_url, link)
            
            if not self._is_same_domain(full_url): return None
            
            parsed = urlparse(full_url)
            normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                params = parse_qs(parsed.query)
                param_names = sorted(params.keys())
                if param_names: normalized += f"?{'&'.join(f'{k}=' for k in param_names)}"
            return normalized
        except: return None
    
    def _extract_page_info(self, url: str) -> Optional[PageInfo]:
        driver = self.browser.driver
        page_info = PageInfo(url=url)
        try:
            page_info.title = driver.title
            parsed = urlparse(url)
            if parsed.query:
                page_info.params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            
            forms = driver.find_elements(By.TAG_NAME, 'form')
            for form in forms:
                try:
                    action = form.get_attribute('action') or url
                    if action and not action.startswith('http'): action = urljoin(url, action)
                    
                    inputs = []
                    elements = form.find_elements(By.CSS_SELECTOR, 'input, textarea, select')
                    for elem in elements:
                        name = elem.get_attribute('name')
                        if name:
                            inputs.append({
                                'name': name,
                                'type': elem.get_attribute('type') or 'text',
                                'value': elem.get_attribute('value') or ''
                            })
                    if inputs:
                        page_info.forms.append({'action': action, 'method': (form.get_attribute('method') or 'get').lower(), 'inputs': inputs})
                except: pass
            
            links = driver.find_elements(By.TAG_NAME, 'a')
            for link in links:
                try:
                    href = link.get_attribute('href')
                    if href: page_info.links.add(href)
                except: pass
            return page_info
        except: return page_info
    
    def crawl(self) -> List[PageInfo]:
        self.log(f"\n🌐 크롤링 시작: {self.base_url}", 'info')
        
        try:
            driver = self.browser.start()
        except Exception as e:
            self.log(f"❌ 브라우저 시작 실패: {e}", 'danger')
            return []
        
        try:
            driver.get(self.base_url)
            self.browser.wait_for_ready()
            
            if self.cookies:
                self.browser.add_cookies(self.cookies)
                driver.refresh()
                self.browser.wait_for_ready()
            
            xss_found, evidence = self.browser.check_xss_in_console()
            if xss_found:
                self.log(f"   🔴 초기 페이지 XSS 감지!", 'danger')
                
        except Exception as e:
            self.browser.close()
            return []
        
        queue = deque([(self.base_url, 0)])
        self.visited.add(self._normalize_link(self.base_url, self.base_url) or self.base_url)
        
        while queue and len(self.pages) < self.max_pages and not self.stop_flag:
            url, depth = queue.popleft()
            if depth > self.max_depth: continue
            
            try:
                driver.get(url)
                self.browser.wait_for_ready()
            except: continue
            
            page_info = self._extract_page_info(url)
            if page_info:
                self.pages.append(page_info)
                self.log(f"  [{len(self.pages)}/{self.max_pages}] {url[:60]}...", 'info')
                
                if self.callback:
                    progress = int((len(self.pages) / self.max_pages) * 100)
                    self.callback(None, 'crawl_progress', progress)
                
                for link in page_info.links:
                    normalized = self._normalize_link(link, url)
                    if normalized and normalized not in self.visited:
                        self.visited.add(normalized)
                        queue.append((link, depth + 1))
        
        self.browser.close()
        self.log(f"\n✅ 크롤링 완료: {len(self.pages)}개 페이지", 'success')
        return self.pages
    
    def stop(self):
        self.stop_flag = True
        self.browser.close()


# ============== XSS 스캐너 ==============

class SeleniumXSSScanner:
    def __init__(self, cookies: Dict = None, headless: bool = True, timeout: int = 10, 
                 callback=None, alert_mode: bool = False):
        """
        XSS 스캐너 초기화
        
        Args:
            cookies: 로그인 쿠키
            headless: 브라우저 숨김 여부
            timeout: 타임아웃 (초)
            callback: GUI 콜백 함수
            alert_mode: True면 alert() 사용, False면 console.log() 사용
        """
        self.cookies = cookies
        self.headless = headless
        self.timeout = timeout
        self.callback = callback
        self.alert_mode = alert_mode  # [v5.5] Alert 모드 추가
        self.browser = None
        self.results: List[ScanResult] = []
        self.stored_xss_results: List[StoredXSSResult] = []
        self.stop_flag = False
    
    def log(self, message: str, level: str = 'info'):
        if self.callback: self.callback(message, level)
    
    def _start_browser(self):
        if not self.browser:
            self.browser = BrowserManager(headless=self.headless, timeout=self.timeout)
            self.browser.start()
            if self.cookies:
                try: self.browser.driver.get('about:blank')
                except: pass
    
    def _close_browser(self):
        if self.browser:
            self.browser.close()
            self.browser = None
    
    def scan_page_content(self, pages: List[PageInfo]) -> List[StoredXSSResult]:
        self.stored_xss_results = []
        self.log(f"\n🔎 저장된 XSS 분석 ({len(pages)}개 페이지)", 'info')
        
        if not pages: return []
        self._start_browser()
        
        for i, page in enumerate(pages):
            if self.stop_flag: break
            try:
                self.browser.driver.get(page.url)
                self.browser.wait_for_ready()
                
                # Alert 확인 (저장된 XSS가 alert를 실행했을 수 있음)
                try:
                    alert = self.browser.driver.switch_to.alert
                    evidence = f"Alert: {alert.text}"
                    alert.accept()
                    self.log(f"  [{i+1}] 🔴 XSS Alert 감지!", 'danger')
                    self.stored_xss_results.append(StoredXSSResult(
                        url=page.url, pattern_name='🔴 XSS Alert 실행됨!', 
                        matched_content=evidence[:100], console_evidence=evidence
                    ))
                    continue
                except NoAlertPresentException:
                    pass
                
                xss_found, evidence = self.browser.check_xss_in_console()
                if xss_found:
                    self.log(f"  [{i+1}] 🔴 XSS 실행됨! (콘솔)", 'danger')
                    self.stored_xss_results.append(StoredXSSResult(
                        url=page.url, pattern_name='🔴 XSS 실행됨!', 
                        matched_content=evidence[:100], console_evidence=evidence
                    ))
                
                if not xss_found:
                    dom_findings = self.browser.check_dom_for_xss()
                    if dom_findings:
                        for finding in dom_findings:
                            self.log(f"  [{i+1}] 🔴 DOM XSS: {finding['type']}", 'danger')
                            self.stored_xss_results.append(StoredXSSResult(
                                url=page.url, pattern_name=f"DOM: {finding['type']}", 
                                matched_content=finding['element']
                            ))
                
                if self.callback:
                    progress = int(((i + 1) / len(pages)) * 100)
                    self.callback(None, 'content_progress', progress)
            except: pass
        
        if self.stored_xss_results: self.log(f"\n⚠️ 저장된 XSS {len(self.stored_xss_results)}개 발견", 'danger')
        else: self.log(f"\n✅ 저장된 XSS 패턴 없음", 'success')
        return self.stored_xss_results
    
    def _inject_and_check(self, url: str, param: str, payload: str, method: str = 'get', form_data: Dict = None) -> ScanResult:
        result = ScanResult(url=url, parameter=param, payload=payload, reflected=False, vulnerable=False)
        try:
            driver = self.browser.driver
            
            if method == 'get':
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param] = [payload]
                injected_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(params, doseq=True), parsed.fragment))
                driver.get(injected_url)
            else:
                driver.get(url)
                self.browser.wait_for_ready()
                if form_data:
                    for k, v in form_data.items():
                        try: driver.find_element(By.NAME, k).send_keys(v)
                        except: pass
                try: driver.find_element(By.CSS_SELECTOR, 'input[type="submit"], button[type="submit"]').click()
                except: pass
            
            # [복구] 충분한 대기 시간 확보 (0.8초 -> 2.0초)
            # 네트워크가 느리거나 스크립트 실행이 지연될 경우를 대비
            start_time = time.time()
            executed = False
            evidence = ""
            
            while time.time() - start_time < 2.0:
                # Alert 확인 (alert 모드 또는 기존 alert 기반 페이로드)
                try:
                    alert = driver.switch_to.alert
                    evidence = f"Alert: {alert.text}"
                    alert.accept()
                    executed = True
                    break
                except NoAlertPresentException: 
                    pass
                
                # 콘솔 로그 확인 (console.log 모드)
                if not self.alert_mode:
                    executed, evidence = self.browser.check_xss_in_console()
                    if executed: break
                
                time.sleep(0.1)

            if executed:
                result.executed = True
                result.vulnerable = True
                result.console_output = evidence
            elif payload in driver.page_source:
                result.reflected = True
                
            return result
        except: return result
    
    def scan_pages(self, pages: List[PageInfo], quick_mode: bool = True) -> List[ScanResult]:
        """
        반사형 XSS 스캔
        
        Args:
            pages: 스캔할 페이지 목록
            quick_mode: True면 빠른 스캔 (7개 페이로드)
        
        Returns:
            ScanResult 목록
        """
        self.results = []
        self.stop_flag = False
        
        # [v5.5] Alert 모드에 따라 페이로드 선택
        payloads = get_payloads(quick_mode=quick_mode, alert_mode=self.alert_mode)
        
        # 모드 로그 출력
        mode_text = "🔔 Alert 모드 (팝업)" if self.alert_mode else "📋 Console 모드 (로그)"
        self.log(f"   {mode_text}", 'info')
        
        tasks = []
        for p in pages:
            for param in p.params: tasks.append(('url', p.url, param, None))
            for form in p.forms:
                for inp in form['inputs']: tasks.append(('form', form['action'], inp, form))
        
        if not tasks:
            self.log("⚠️ 스캔할 대상이 없습니다.", 'warning')
            return []
        
        self.log(f"\n🚀 스캔 시작 (총 {len(tasks) * len(payloads)}개 테스트)", 'info')
        self._start_browser()
        
        total = len(tasks) * len(payloads)
        current = 0
        
        for type_, url, target, extra in tasks:
            if self.stop_flag: break
            
            for payload in payloads:
                if self.stop_flag: break
                current += 1
                
                if type_ == 'url':
                    res = self._inject_and_check(url, target, payload, 'get')
                else:
                    form_data = {inp['name']: (payload if inp['name'] == target['name'] else inp.get('value', 'test')) for inp in extra['inputs']}
                    res = self._inject_and_check(extra['action'], f"{target['name']}", payload, extra['method'], form_data)
                
                self.results.append(res)
                
                if res.executed:
                    self.log(f"  🔴 XSS 성공! [{res.parameter}]", 'danger')
                elif res.vulnerable:
                    self.log(f"  🟠 취약점 의심 [{res.parameter}]", 'warning')
                
                if self.callback and current % 5 == 0:
                    self.callback(None, 'scan_progress', int((current / total) * 100))
        
        self._close_browser()
        return self.results
    
    def stop(self):
        self.stop_flag = True
        self._close_browser()

# 하위 호환성
SiteCrawler = SeleniumCrawler
XSSScanner = SeleniumXSSScanner
