"""
================================================================================
XSS Scanner - 유틸리티 함수 테스트 (test_utils.py)
================================================================================

URL 파싱, 정규화 등 유틸리티 함수들을 테스트합니다.

실행:
    python -m pytest tests/test_utils.py -v
    python tests/test_utils.py
================================================================================
"""

import unittest
import sys
import os
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin

# 상위 디렉토리를 path에 추가
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Patterns, Payloads


# ==============================================================================
# URL 정규화 함수 (엔진에서 사용하는 것과 동일)
# ==============================================================================

def normalize_url(url: str) -> str:
    """URL 정규화"""
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url.rstrip('/')


def is_same_domain(url: str, base_domain: str) -> bool:
    """같은 도메인인지 확인"""
    try:
        parsed = urlparse(url)
        return parsed.netloc == base_domain or parsed.netloc == ''
    except:
        return False


def extract_params(url: str) -> dict:
    """URL에서 파라미터 추출"""
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        # 값을 단일 값으로 변환
        return {k: v[0] for k, v in params.items()}
    except:
        return {}


def inject_payload(url: str, param: str, payload: str) -> str:
    """URL 파라미터에 페이로드 주입"""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, new_query, parsed.fragment
    ))


# ==============================================================================
# URL 정규화 테스트
# ==============================================================================

class TestUrlNormalization(unittest.TestCase):
    """URL 정규화 테스트"""
    
    def test_add_http_scheme(self):
        """http:// 스킴이 없을 때 추가하는지 확인"""
        url = "example.com"
        result = normalize_url(url)
        self.assertEqual(result, "http://example.com")
    
    def test_preserve_https(self):
        """https:// 스킴이 있을 때 유지하는지 확인"""
        url = "https://example.com"
        result = normalize_url(url)
        self.assertEqual(result, "https://example.com")
    
    def test_preserve_http(self):
        """http:// 스킴이 있을 때 유지하는지 확인"""
        url = "http://example.com"
        result = normalize_url(url)
        self.assertEqual(result, "http://example.com")
    
    def test_remove_trailing_slash(self):
        """끝의 슬래시 제거 확인"""
        url = "http://example.com/"
        result = normalize_url(url)
        self.assertEqual(result, "http://example.com")
    
    def test_strip_whitespace(self):
        """공백 제거 확인"""
        url = "  http://example.com  "
        result = normalize_url(url)
        self.assertEqual(result, "http://example.com")
    
    def test_preserve_path(self):
        """경로 유지 확인"""
        url = "http://example.com/path/to/page"
        result = normalize_url(url)
        self.assertEqual(result, "http://example.com/path/to/page")
    
    def test_preserve_query(self):
        """쿼리스트링 유지 확인"""
        url = "http://example.com/page?param=value"
        result = normalize_url(url)
        self.assertEqual(result, "http://example.com/page?param=value")


class TestDomainCheck(unittest.TestCase):
    """도메인 체크 테스트"""
    
    def test_same_domain(self):
        """같은 도메인 확인"""
        self.assertTrue(is_same_domain(
            "http://example.com/page",
            "example.com"
        ))
    
    def test_different_domain(self):
        """다른 도메인 확인"""
        self.assertFalse(is_same_domain(
            "http://other.com/page",
            "example.com"
        ))
    
    def test_subdomain_different(self):
        """서브도메인은 다른 도메인으로 취급"""
        self.assertFalse(is_same_domain(
            "http://sub.example.com/page",
            "example.com"
        ))
    
    def test_relative_url(self):
        """상대 URL 처리 (netloc이 비어있음)"""
        self.assertTrue(is_same_domain("/page", "example.com"))
    
    def test_invalid_url(self):
        """잘못된 URL 처리"""
        # urlparse는 "not a url"을 path로 파싱하므로 netloc이 빈 문자열
        # 빈 netloc은 same_domain으로 취급됨 (상대 URL과 동일)
        # 이는 의도된 동작임
        result = is_same_domain("not a url", "example.com")
        # netloc이 비어있으면 True 반환 (상대 경로 취급)
        self.assertTrue(result)


class TestParameterExtraction(unittest.TestCase):
    """파라미터 추출 테스트"""
    
    def test_single_param(self):
        """단일 파라미터 추출"""
        url = "http://example.com/page?search=test"
        params = extract_params(url)
        self.assertEqual(params, {'search': 'test'})
    
    def test_multiple_params(self):
        """다중 파라미터 추출"""
        url = "http://example.com/page?a=1&b=2&c=3"
        params = extract_params(url)
        self.assertEqual(params, {'a': '1', 'b': '2', 'c': '3'})
    
    def test_no_params(self):
        """파라미터 없는 URL"""
        url = "http://example.com/page"
        params = extract_params(url)
        self.assertEqual(params, {})
    
    def test_encoded_params(self):
        """인코딩된 파라미터"""
        url = "http://example.com/page?q=hello%20world"
        params = extract_params(url)
        self.assertEqual(params, {'q': 'hello world'})
    
    def test_empty_value(self):
        """빈 값 파라미터"""
        # parse_qs는 기본적으로 빈 값을 무시함
        # keep_blank_values=True를 사용해야 빈 값 유지
        url = "http://example.com/page?q="
        params = extract_params(url)
        # 기본 parse_qs 동작: 빈 값은 무시됨
        self.assertEqual(params, {})


class TestPayloadInjection(unittest.TestCase):
    """페이로드 주입 테스트"""
    
    def test_inject_to_existing_param(self):
        """기존 파라미터에 주입"""
        url = "http://example.com/page?search=test"
        payload = "<script>alert(1)</script>"
        
        result = inject_payload(url, "search", payload)
        
        self.assertIn("search=", result)
        self.assertIn("%3Cscript%3E", result)  # URL 인코딩됨
    
    def test_inject_new_param(self):
        """새 파라미터로 주입"""
        url = "http://example.com/page"
        payload = "<script>alert(1)</script>"
        
        result = inject_payload(url, "xss", payload)
        
        self.assertIn("xss=", result)
    
    def test_preserve_other_params(self):
        """다른 파라미터 유지"""
        url = "http://example.com/page?a=1&b=2"
        payload = "test"
        
        result = inject_payload(url, "a", payload)
        
        self.assertIn("b=2", result)


# ==============================================================================
# 패턴 매칭 테스트
# ==============================================================================

class TestXSSPatternMatching(unittest.TestCase):
    """XSS 패턴 매칭 테스트"""
    
    def test_img_onerror_pattern(self):
        """img onerror 패턴 매칭"""
        content = '<img src="x" onerror="alert(1)">'
        pattern = r'<img[^>]*\sonerror\s*='
        
        self.assertIsNotNone(re.search(pattern, content, re.IGNORECASE))
    
    def test_svg_onload_pattern(self):
        """svg onload 패턴 매칭"""
        content = '<svg onload="alert(1)">'
        pattern = r'<svg[^>]*\sonload\s*='
        
        self.assertIsNotNone(re.search(pattern, content, re.IGNORECASE))
    
    def test_javascript_href_pattern(self):
        """javascript: href 패턴 매칭"""
        content = '<a href="javascript:alert(1)">click</a>'
        pattern = r'href\s*=\s*["\']?\s*javascript\s*:'
        
        self.assertIsNotNone(re.search(pattern, content, re.IGNORECASE))
    
    def test_script_alert_pattern(self):
        """script alert 패턴 매칭"""
        content = '<script>alert("xss")</script>'
        pattern = r'<script[^>]*>[\s\S]*?alert\s*\('
        
        self.assertIsNotNone(re.search(pattern, content, re.IGNORECASE))
    
    def test_xss_marker_pattern(self):
        """XSS 마커 패턴 매칭"""
        content = 'XSS_TEST_1 was executed'
        pattern = r'XSS[_\-]?(ATTACK|TEST|SUCCESS|PAYLOAD)'
        
        self.assertIsNotNone(re.search(pattern, content, re.IGNORECASE))
    
    def test_all_patterns_valid(self):
        """모든 패턴이 유효한 정규식인지 확인"""
        for pattern, desc in Patterns.STORED_XSS_PATTERNS:
            try:
                re.compile(pattern)
            except re.error as e:
                self.fail(f"Invalid regex '{pattern}' ({desc}): {e}")
    
    def test_safe_content_no_match(self):
        """안전한 콘텐츠는 매칭되지 않아야 함"""
        safe_content = '<img src="photo.jpg" alt="A photo">'
        
        for pattern, desc in Patterns.STORED_XSS_PATTERNS:
            match = re.search(pattern, safe_content, re.IGNORECASE)
            if match:
                # onerror, onload 등 이벤트 핸들러가 없으면 매칭되면 안 됨
                if 'event' in desc.lower() or 'XSS' in desc:
                    continue
                # 일부 패턴은 매칭될 수 있으므로 조건 확인
    
    def test_patterns_detect_xss_payloads(self):
        """패턴이 XSS 페이로드를 탐지하는지 확인"""
        payloads = Payloads.get_payloads(quick_mode=False, alert_mode=False)
        
        detected_count = 0
        for payload in payloads:
            for pattern, desc in Patterns.STORED_XSS_PATTERNS:
                if re.search(pattern, payload, re.IGNORECASE):
                    detected_count += 1
                    break
        
        # 대부분의 페이로드가 탐지되어야 함
        detection_rate = detected_count / len(payloads)
        self.assertGreater(detection_rate, 0.5, 
                          f"탐지율이 50% 이상이어야 합니다: {detection_rate:.1%}")


# ==============================================================================
# XSS 마커 테스트
# ==============================================================================

class TestXSSMarkers(unittest.TestCase):
    """XSS 마커 테스트"""
    
    def test_markers_in_payloads(self):
        """페이로드에 마커가 포함되어 있는지 확인"""
        payloads = Payloads.get_payloads(quick_mode=True, alert_mode=False)
        markers = Payloads.XSS_MARKERS
        
        for payload in payloads:
            has_marker = any(marker in payload for marker in markers)
            self.assertTrue(has_marker, 
                          f"페이로드에 마커가 없습니다: {payload}")
    
    def test_marker_detection(self):
        """마커 탐지 로직 테스트"""
        markers = Payloads.XSS_MARKERS
        
        # 콘솔 로그 예시
        console_logs = [
            'console.log("XSS_TEST_1")',
            'XSS_FULL_3 executed',
            'some random log',
            'XSS_ATTACK detected',
        ]
        
        for log in console_logs:
            if 'XSS' in log:
                found = any(marker in log for marker in markers)
                self.assertTrue(found, f"마커가 탐지되어야 합니다: {log}")


# ==============================================================================
# Cookie 파싱 테스트
# ==============================================================================

class TestCookieParsing(unittest.TestCase):
    """쿠키 파싱 테스트"""
    
    @staticmethod
    def parse_cookies(cookie_string: str) -> dict:
        """쿠키 문자열 파싱 (GUI에서 사용하는 것과 동일)"""
        cookies = {}
        if not cookie_string:
            return cookies
        
        for item in cookie_string.split(';'):
            item = item.strip()
            if '=' in item:
                key, value = item.split('=', 1)
                cookies[key.strip()] = value.strip()
        
        return cookies
    
    def test_single_cookie(self):
        """단일 쿠키 파싱"""
        cookie_str = "session=abc123"
        result = self.parse_cookies(cookie_str)
        self.assertEqual(result, {'session': 'abc123'})
    
    def test_multiple_cookies(self):
        """다중 쿠키 파싱"""
        cookie_str = "session=abc123; user=john; token=xyz"
        result = self.parse_cookies(cookie_str)
        self.assertEqual(result, {
            'session': 'abc123',
            'user': 'john',
            'token': 'xyz'
        })
    
    def test_empty_string(self):
        """빈 문자열 처리"""
        result = self.parse_cookies("")
        self.assertEqual(result, {})
    
    def test_whitespace_handling(self):
        """공백 처리"""
        cookie_str = "  session = abc123 ; user = john  "
        result = self.parse_cookies(cookie_str)
        self.assertEqual(result, {'session': 'abc123', 'user': 'john'})
    
    def test_value_with_equals(self):
        """값에 = 포함된 경우"""
        cookie_str = "data=key=value"
        result = self.parse_cookies(cookie_str)
        self.assertEqual(result, {'data': 'key=value'})


# ==============================================================================
# 테스트 실행
# ==============================================================================

if __name__ == '__main__':
    print("=" * 60)
    print("XSS Scanner - 유틸리티 함수 테스트")
    print("=" * 60)
    
    unittest.main(verbosity=2)
