"""
================================================================================
XSS Scanner - 설정 파일 테스트 (test_config.py)
================================================================================

config.py의 설정값과 함수들을 테스트합니다.

실행:
    python -m pytest tests/test_config.py -v
    python tests/test_config.py
================================================================================
"""

import unittest
import sys
import os

# 상위 디렉토리를 path에 추가
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import (
    Config, Payloads, Patterns, Severity, BrowserConfig, GUIConfig, TestConfig,
    __version__, get_version, get_full_version, validate_config
)


class TestVersion(unittest.TestCase):
    """버전 정보 테스트"""
    
    def test_version_format(self):
        """버전 형식이 올바른지 확인"""
        # 버전은 x.y.z 형식이어야 함
        parts = __version__.split('.')
        self.assertEqual(len(parts), 3, "버전은 x.y.z 형식이어야 합니다")
        
        # 각 부분이 숫자인지 확인
        for part in parts:
            self.assertTrue(part.isdigit(), f"버전 부분 '{part}'는 숫자여야 합니다")
    
    def test_get_version(self):
        """get_version() 함수 테스트"""
        version = get_version()
        self.assertTrue(version.startswith('v'), "버전은 'v'로 시작해야 합니다")
        self.assertIn(__version__, version)
    
    def test_get_full_version(self):
        """get_full_version() 함수 테스트"""
        full_version = get_full_version()
        self.assertIn(__version__, full_version)
        self.assertIn("XSS Scanner", full_version)


class TestScannerConfig(unittest.TestCase):
    """스캐너 기본 설정 테스트"""
    
    def test_default_values(self):
        """기본값이 올바른지 확인"""
        self.assertGreater(Config.DEFAULT_MAX_PAGES, 0)
        self.assertGreaterEqual(Config.DEFAULT_MAX_DEPTH, 0)
        self.assertGreater(Config.DEFAULT_TIMEOUT, 0)
        self.assertGreater(Config.PAGE_LOAD_WAIT, 0)
    
    def test_boolean_defaults(self):
        """불리언 기본값 확인"""
        self.assertIsInstance(Config.DEFAULT_HEADLESS, bool)
        self.assertIsInstance(Config.DEFAULT_QUICK_MODE, bool)
        self.assertIsInstance(Config.DEFAULT_ALERT_MODE, bool)


class TestPayloads(unittest.TestCase):
    """페이로드 생성 테스트"""
    
    def test_quick_payloads_count(self):
        """빠른 스캔 페이로드 개수 확인"""
        payloads = Payloads.get_payloads(quick_mode=True, alert_mode=False)
        self.assertEqual(len(payloads), TestConfig.EXPECTED_QUICK_PAYLOADS,
                        f"빠른 스캔은 {TestConfig.EXPECTED_QUICK_PAYLOADS}개 페이로드여야 합니다")
    
    def test_full_payloads_count(self):
        """전체 스캔 페이로드 개수 확인"""
        payloads = Payloads.get_payloads(quick_mode=False, alert_mode=False)
        self.assertEqual(len(payloads), TestConfig.EXPECTED_FULL_PAYLOADS,
                        f"전체 스캔은 {TestConfig.EXPECTED_FULL_PAYLOADS}개 페이로드여야 합니다")
    
    def test_console_mode_payloads(self):
        """Console 모드 페이로드 내용 확인"""
        payloads = Payloads.get_payloads(quick_mode=True, alert_mode=False)
        
        # 모든 페이로드에 console.log가 포함되어야 함
        for payload in payloads:
            self.assertIn('console.log', payload,
                         f"Console 모드 페이로드에 'console.log'가 있어야 합니다: {payload}")
        
        # alert가 포함되면 안 됨
        for payload in payloads:
            self.assertNotIn('alert(', payload,
                            f"Console 모드 페이로드에 'alert('가 없어야 합니다: {payload}")
    
    def test_alert_mode_payloads(self):
        """Alert 모드 페이로드 내용 확인"""
        payloads = Payloads.get_payloads(quick_mode=True, alert_mode=True)
        
        # 모든 페이로드에 alert가 포함되어야 함
        for payload in payloads:
            self.assertIn('alert', payload,
                         f"Alert 모드 페이로드에 'alert'가 있어야 합니다: {payload}")
        
        # console.log가 포함되면 안 됨
        for payload in payloads:
            self.assertNotIn('console.log', payload,
                            f"Alert 모드 페이로드에 'console.log'가 없어야 합니다: {payload}")
    
    def test_payloads_contain_markers(self):
        """페이로드에 XSS 마커가 포함되어 있는지 확인"""
        payloads = Payloads.get_payloads(quick_mode=False, alert_mode=False)
        markers = Payloads.XSS_MARKERS
        
        for payload in payloads:
            has_marker = any(marker in payload for marker in markers)
            self.assertTrue(has_marker,
                          f"페이로드에 XSS 마커가 있어야 합니다: {payload}")
    
    def test_xss_markers_exist(self):
        """XSS 마커 목록이 존재하는지 확인"""
        self.assertIsInstance(Payloads.XSS_MARKERS, list)
        self.assertGreater(len(Payloads.XSS_MARKERS), 0, "XSS 마커가 최소 1개 이상 있어야 합니다")


class TestPatterns(unittest.TestCase):
    """탐지 패턴 테스트"""
    
    def test_stored_xss_patterns_exist(self):
        """저장된 XSS 패턴이 존재하는지 확인"""
        patterns = Patterns.STORED_XSS_PATTERNS
        self.assertIsInstance(patterns, list)
        self.assertGreater(len(patterns), 0, "XSS 패턴이 최소 1개 이상 있어야 합니다")
    
    def test_stored_xss_patterns_format(self):
        """저장된 XSS 패턴 형식 확인 (튜플: 정규식, 설명)"""
        for pattern in Patterns.STORED_XSS_PATTERNS:
            self.assertIsInstance(pattern, tuple, "패턴은 튜플이어야 합니다")
            self.assertEqual(len(pattern), 2, "패턴은 (정규식, 설명) 형식이어야 합니다")
            self.assertIsInstance(pattern[0], str, "정규식은 문자열이어야 합니다")
            self.assertIsInstance(pattern[1], str, "설명은 문자열이어야 합니다")
    
    def test_patterns_are_valid_regex(self):
        """패턴이 유효한 정규식인지 확인"""
        import re
        for pattern, desc in Patterns.STORED_XSS_PATTERNS:
            try:
                re.compile(pattern)
            except re.error as e:
                self.fail(f"유효하지 않은 정규식 '{pattern}': {e}")
    
    def test_dom_xss_selectors_exist(self):
        """DOM XSS 선택자가 존재하는지 확인"""
        selectors = Patterns.DOM_XSS_SELECTORS
        self.assertIsInstance(selectors, list)
        self.assertGreater(len(selectors), 0)
    
    def test_safe_domains_exist(self):
        """안전한 도메인 목록이 존재하는지 확인"""
        domains = Patterns.SAFE_DOMAINS
        self.assertIsInstance(domains, list)
        self.assertGreater(len(domains), 0)


class TestSeverity(unittest.TestCase):
    """위험도 분류 테스트"""
    
    def test_severity_levels(self):
        """위험도 레벨이 정의되어 있는지 확인"""
        self.assertEqual(Severity.CRITICAL, 'critical')
        self.assertEqual(Severity.HIGH, 'high')
        self.assertEqual(Severity.MEDIUM, 'medium')
        self.assertEqual(Severity.LOW, 'low')
        self.assertEqual(Severity.INFO, 'info')
    
    def test_classify_critical(self):
        """치명적 위험도 분류 테스트"""
        critical_content = "document.cookie 탈취 시도"
        self.assertEqual(Severity.classify(critical_content), Severity.CRITICAL)
        
        eval_content = "eval(userInput)"
        self.assertEqual(Severity.classify(eval_content), Severity.CRITICAL)
    
    def test_classify_high(self):
        """높은 위험도 분류 테스트"""
        high_content = "document.location = 'http://evil.com'"
        self.assertEqual(Severity.classify(high_content), Severity.HIGH)
    
    def test_classify_medium(self):
        """중간 위험도 분류 테스트"""
        medium_content = "alert('XSS')"
        self.assertEqual(Severity.classify(medium_content), Severity.MEDIUM)
    
    def test_classify_low(self):
        """낮은 위험도 분류 테스트"""
        low_content = "harmless content"
        self.assertEqual(Severity.classify(low_content), Severity.LOW)
    
    def test_classify_case_insensitive(self):
        """대소문자 구분 없이 분류하는지 확인"""
        upper_content = "DOCUMENT.COOKIE"
        lower_content = "document.cookie"
        
        self.assertEqual(Severity.classify(upper_content), Severity.CRITICAL)
        self.assertEqual(Severity.classify(lower_content), Severity.CRITICAL)


class TestBrowserConfig(unittest.TestCase):
    """브라우저 설정 테스트"""
    
    def test_chrome_arguments_exist(self):
        """Chrome 인자가 존재하는지 확인"""
        args = BrowserConfig.CHROME_ARGUMENTS
        self.assertIsInstance(args, list)
        self.assertGreater(len(args), 0)
    
    def test_content_settings_exist(self):
        """콘텐츠 설정이 존재하는지 확인"""
        settings = BrowserConfig.CONTENT_SETTINGS
        self.assertIsInstance(settings, dict)
        
        # 이미지와 JS는 허용(1)되어야 함
        self.assertEqual(settings.get("profile.managed_default_content_settings.images"), 1,
                        "이미지는 허용되어야 합니다 (XSS 탐지 필수)")
        self.assertEqual(settings.get("profile.managed_default_content_settings.javascript"), 1,
                        "JavaScript는 허용되어야 합니다")


class TestGUIConfig(unittest.TestCase):
    """GUI 설정 테스트"""
    
    def test_window_size_format(self):
        """윈도우 크기 형식 확인"""
        size = GUIConfig.WINDOW_SIZE
        self.assertIn('x', size, "윈도우 크기는 'WIDTHxHEIGHT' 형식이어야 합니다")
        
        parts = size.split('x')
        self.assertEqual(len(parts), 2)
        self.assertTrue(parts[0].isdigit())
        self.assertTrue(parts[1].isdigit())
    
    def test_colors_exist(self):
        """색상 정의가 존재하는지 확인"""
        colors = GUIConfig.COLORS
        self.assertIsInstance(colors, dict)
        
        # 필수 색상 확인
        required_colors = ['bg', 'fg', 'accent', 'danger', 'success', 'warning']
        for color in required_colors:
            self.assertIn(color, colors, f"'{color}' 색상이 정의되어야 합니다")


class TestConfigValidation(unittest.TestCase):
    """설정 유효성 검사 테스트"""
    
    def test_validate_config(self):
        """전체 설정 유효성 검사"""
        self.assertTrue(validate_config(), "설정 유효성 검사가 통과해야 합니다")


# ==============================================================================
# 테스트 실행
# ==============================================================================

if __name__ == '__main__':
    print("=" * 60)
    print("XSS Scanner - 설정 파일 테스트")
    print("=" * 60)
    
    # 테스트 실행
    unittest.main(verbosity=2)
