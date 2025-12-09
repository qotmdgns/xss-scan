"""
================================================================================
XSS Scanner - 설정 파일 (config.py)
================================================================================

모든 설정값을 중앙에서 관리합니다.
코드 수정 없이 이 파일만 수정하면 동작을 변경할 수 있습니다.

사용법:
    from config import Config, Payloads, Patterns
    
    payloads = Payloads.get_payloads(quick_mode=True, alert_mode=False)
    patterns = Patterns.STORED_XSS_PATTERNS
================================================================================
"""

from typing import List, Tuple
from dataclasses import dataclass


# ==============================================================================
# 버전 정보
# ==============================================================================

__version__ = "5.6.0"
__release_date__ = "2024-12-07"
__author__ = "XSS Scanner Team"


# ==============================================================================
# 스캐너 기본 설정
# ==============================================================================

@dataclass
class ScannerConfig:
    """스캐너 기본 설정"""
    
    # 크롤링 설정
    DEFAULT_MAX_PAGES: int = 30
    DEFAULT_MAX_DEPTH: int = 3
    DEFAULT_TIMEOUT: int = 10
    
    # 대기 시간 (초)
    PAGE_LOAD_WAIT: float = 2.0      # 페이지 로드 후 XSS 실행 대기
    POLL_INTERVAL: float = 0.1       # Alert/콘솔 체크 간격
    
    # 브라우저 설정
    DEFAULT_HEADLESS: bool = True
    DEFAULT_WINDOW_SIZE: str = "1920,1080"
    
    # 기본 모드
    DEFAULT_QUICK_MODE: bool = True
    DEFAULT_ALERT_MODE: bool = False


# 전역 설정 인스턴스
Config = ScannerConfig()


# ==============================================================================
# XSS 페이로드
# ==============================================================================

class Payloads:
    """XSS 테스트 페이로드 관리"""
    
    # XSS 마커 (콘솔/alert에서 탐지할 문자열)
    XSS_MARKERS: List[str] = [
        'XSS_TEST_',
        'XSS_FULL_',
        'XSS_ATTACK',
        'XSS_SUCCESS'
    ]
    
    @staticmethod
    def get_payloads(quick_mode: bool = True, alert_mode: bool = False) -> List[str]:
        """
        XSS 테스트 페이로드 목록 생성
        
        Args:
            quick_mode: True면 빠른 스캔용 (7개), False면 전체 스캔용 (17개)
            alert_mode: True면 alert() 사용, False면 console.log() 사용
        
        Returns:
            페이로드 문자열 목록
        """
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
        
        # 전체 스캔용 추가 페이로드 (10개 추가 = 총 17개)
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
    
    @staticmethod
    def get_custom_payloads(func: str = 'console.log') -> List[str]:
        """
        사용자 정의 페이로드 (확장용)
        
        이 메서드를 수정하여 커스텀 페이로드를 추가할 수 있습니다.
        """
        return [
            # 여기에 커스텀 페이로드 추가
            # f'<div onmouseenter={func}("CUSTOM_1")>',
        ]


# ==============================================================================
# 저장된 XSS 탐지 패턴
# ==============================================================================

class Patterns:
    """XSS 탐지 패턴 관리"""
    
    # 저장된 XSS 탐지용 정규식 패턴
    # 형식: (정규식, 설명)
    STORED_XSS_PATTERNS: List[Tuple[str, str]] = [
        # 이미지 태그
        (r'<img[^>]*\sonerror\s*=', 'img onerror XSS'),
        (r'<img[^>]*\sonload\s*=', 'img onload XSS'),
        
        # SVG/Body 태그
        (r'<svg[^>]*\sonload\s*=', 'svg onload XSS'),
        (r'<body[^>]*\sonload\s*=', 'body onload XSS'),
        
        # 일반 이벤트 핸들러
        (r'<[a-z]+[^>]*\sonerror\s*=', 'onerror 이벤트'),
        (r'<[a-z]+[^>]*\sonload\s*=', 'onload 이벤트'),
        (r'<[a-z]+[^>]*\sonclick\s*=', 'onclick 이벤트'),
        (r'<[a-z]+[^>]*\sonmouseover\s*=', 'onmouseover 이벤트'),
        
        # 스크립트 태그
        (r'<script[^>]*>[\s\S]*?alert\s*\(', 'alert() 스크립트'),
        (r'<script[^>]*>[\s\S]*?console\s*\.', 'console 스크립트'),
        
        # JavaScript URL
        (r'href\s*=\s*["\']?\s*javascript\s*:', 'javascript: href'),
        
        # XSS 테스트 흔적
        (r'XSS[_\-]?(ATTACK|TEST|SUCCESS|PAYLOAD)', 'XSS 테스트 흔적'),
    ]
    
    # DOM XSS 탐지용 CSS 선택자
    DOM_XSS_SELECTORS: List[Tuple[str, str]] = [
        ('img[onerror]', 'img onerror'),
        ('a[href^="javascript:"]', 'javascript: href'),
        ('[onload]', 'onload event'),
        ('[onclick]', 'onclick event'),
        ('[onmouseover]', 'onmouseover event'),
    ]
    
    # 안전한 도메인 (외부 스크립트 허용)
    SAFE_DOMAINS: List[str] = [
        'cdn.cloudflare.com',
        'cdnjs.cloudflare.com',
        'code.jquery.com',
        'unpkg.com',
        'cdn.jsdelivr.net',
        'fonts.googleapis.com',
        'google.com',
        'googleapis.com',
    ]


# ==============================================================================
# 위험도 분류
# ==============================================================================

class Severity:
    """위험도 분류 기준"""
    
    # 위험도 레벨
    CRITICAL = 'critical'
    HIGH = 'high'
    MEDIUM = 'medium'
    LOW = 'low'
    INFO = 'info'
    
    # 위험도별 키워드
    CRITICAL_KEYWORDS: List[str] = [
        'document.cookie',
        'eval(',
        'localStorage',
        'sessionStorage',
        'XMLHttpRequest',
        'fetch(',
    ]
    
    HIGH_KEYWORDS: List[str] = [
        'document.location',
        'window.location',
        'document.write',
        'innerHTML',
        '.src=',
    ]
    
    MEDIUM_KEYWORDS: List[str] = [
        'alert(',
        'console.log',
        'onerror',
        'onload',
    ]
    
    @classmethod
    def classify(cls, content: str) -> str:
        """콘텐츠 기반 위험도 분류"""
        content_lower = content.lower()
        
        for keyword in cls.CRITICAL_KEYWORDS:
            if keyword.lower() in content_lower:
                return cls.CRITICAL
        
        for keyword in cls.HIGH_KEYWORDS:
            if keyword.lower() in content_lower:
                return cls.HIGH
        
        for keyword in cls.MEDIUM_KEYWORDS:
            if keyword.lower() in content_lower:
                return cls.MEDIUM
        
        return cls.LOW


# ==============================================================================
# 브라우저 설정
# ==============================================================================

class BrowserConfig:
    """브라우저 관련 설정"""
    
    # Chrome 옵션
    CHROME_ARGUMENTS: List[str] = [
        '--no-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--log-level=0',
    ]
    
    # 콘텐츠 설정 (1=허용, 2=차단)
    CONTENT_SETTINGS: dict = {
        "profile.managed_default_content_settings.images": 1,      # 이미지 허용 (XSS 탐지 필수!)
        "profile.managed_default_content_settings.javascript": 1,  # JS 허용 (필수)
        "profile.managed_default_content_settings.stylesheets": 2, # CSS 차단 (속도)
        "profile.managed_default_content_settings.fonts": 2,       # 폰트 차단 (속도)
        "profile.managed_default_content_settings.popups": 2,
        "profile.managed_default_content_settings.geolocation": 2,
        "profile.managed_default_content_settings.media_stream": 2,
    }


# ==============================================================================
# GUI 설정
# ==============================================================================

class GUIConfig:
    """GUI 관련 설정"""
    
    # 윈도우 크기
    WINDOW_SIZE: str = "1200x800"
    MIN_WIDTH: int = 900
    MIN_HEIGHT: int = 600
    
    # 색상 테마 (다크 모드)
    COLORS: dict = {
        'bg': '#1e1e1e',
        'secondary': '#2d2d2d',
        'fg': '#ffffff',
        'accent': '#007acc',
        'danger': '#ff5555',
        'success': '#50fa7b',
        'warning': '#ffb86c',
    }
    
    # 폰트
    FONT_FAMILY: str = 'Consolas'
    FONT_SIZE: int = 10


# ==============================================================================
# 테스트용 설정
# ==============================================================================

class TestConfig:
    """단위 테스트용 설정"""
    
    # 테스트용 URL
    TEST_URLS: List[str] = [
        'http://localhost:3000',
        'http://example.com',
        'https://test.example.com/page?param=value',
    ]
    
    # 테스트용 페이로드 수
    EXPECTED_QUICK_PAYLOADS: int = 7
    EXPECTED_FULL_PAYLOADS: int = 17


# ==============================================================================
# 설정 유틸리티
# ==============================================================================

def get_version() -> str:
    """버전 문자열 반환"""
    return f"v{__version__}"


def get_full_version() -> str:
    """상세 버전 정보 반환"""
    return f"XSS Scanner v{__version__} ({__release_date__})"


# 설정 검증
def validate_config() -> bool:
    """설정값 유효성 검사"""
    errors = []
    
    if Config.DEFAULT_MAX_PAGES < 1:
        errors.append("DEFAULT_MAX_PAGES must be >= 1")
    
    if Config.DEFAULT_MAX_DEPTH < 0:
        errors.append("DEFAULT_MAX_DEPTH must be >= 0")
    
    if Config.PAGE_LOAD_WAIT < 0:
        errors.append("PAGE_LOAD_WAIT must be >= 0")
    
    if len(Payloads.get_payloads(quick_mode=True)) != TestConfig.EXPECTED_QUICK_PAYLOADS:
        errors.append(f"Quick payloads count mismatch")
    
    if len(Payloads.get_payloads(quick_mode=False)) != TestConfig.EXPECTED_FULL_PAYLOADS:
        errors.append(f"Full payloads count mismatch")
    
    if errors:
        for e in errors:
            print(f"Config Error: {e}")
        return False
    
    return True


# 모듈 로드 시 검증 실행 (선택적)
if __name__ == "__main__":
    print(get_full_version())
    print(f"Config validation: {'PASS' if validate_config() else 'FAIL'}")
