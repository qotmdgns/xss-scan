# 🔍 XSS 취약점 탐지 도구 v5.6

Selenium 기반의 XSS(Cross-Site Scripting) 취약점 자동 탐지 도구입니다.

---

## 📋 목차

1. [소개](#-소개)
2. [v5.6 새 기능](#-v56-새-기능)
3. [주요 기능](#-주요-기능)
4. [요구 사항](#-요구-사항)
5. [설치 방법](#-설치-방법)
6. [사용법](#-사용법)
7. [파일 구조](#-파일-구조)
8. [설정 커스터마이징](#-설정-커스터마이징)
9. [로깅 시스템](#-로깅-시스템)
10. [단위 테스트](#-단위-테스트)
11. [스캔 결과 해석](#-스캔-결과-해석)
12. [자주 묻는 질문](#-자주-묻는-질문)
13. [주의사항](#-주의사항)

---

## 🎯 소개

이 도구는 웹 애플리케이션의 XSS 취약점을 자동으로 탐지하는 보안 테스트 도구입니다.

### 왜 Selenium을 사용하나요?

| 방식 | JavaScript 실행 | XSS 실제 탐지 | 속도 |
|------|----------------|---------------|------|
| Requests (정적) | ❌ | 패턴 매칭만 | 빠름 |
| **Selenium (동적)** | ✅ | **실제 실행 확인** | 보통 |

---

## 🆕 v5.6 새 기능

### 1. 설정 파일 분리 (`config.py`)

모든 설정값을 중앙에서 관리합니다:
- 페이로드 정의
- 탐지 패턴
- 브라우저 설정
- GUI 테마

```python
from config import Config, Payloads, Patterns

# 페이로드 가져오기
payloads = Payloads.get_payloads(quick_mode=True, alert_mode=False)

# 설정값 사용
timeout = Config.DEFAULT_TIMEOUT
```

### 2. 로깅 시스템 (`logger.py`)

Python logging 모듈 기반 체계적인 로깅:
- 콘솔 + 파일 동시 출력
- 로그 레벨별 색상
- 로그 파일 자동 로테이션

```python
from logger import setup_logging, get_logger

setup_logging(log_dir="logs")
logger = get_logger("scanner")

logger.info("스캔 시작")
logger.warning("XSS 발견!")
logger.error("오류 발생")
```

### 3. 단위 테스트 (`tests/`)

78개의 테스트 케이스:
- 설정 파일 테스트
- 로깅 시스템 테스트
- URL 파싱/유틸리티 테스트

```bash
# 테스트 실행
python run_tests.py -v
```

---

## ✨ 주요 기능

| 기능 | 설명 |
|------|------|
| 🌐 사이트 크롤링 | BFS 방식으로 전체 페이지 수집 |
| 🔍 저장된 XSS 탐지 | 콘솔 로그 + DOM 검사 |
| 💉 반사형 XSS 테스트 | 폼/파라미터에 페이로드 주입 |
| 🔔 Alert 모드 | 팝업으로 XSS 확인 (NEW in v5.5) |
| 📝 보고서 생성 | HTML, JSON, TXT |
| 🍪 인증 지원 | 쿠키로 로그인 상태 유지 |

---

## 💻 요구 사항

### 필수
- Python 3.8 이상
- Google Chrome 브라우저

### Python 패키지
```
selenium>=4.0.0
chromedriver-autoinstaller
requests
beautifulsoup4
```

---

## 📥 설치 방법

```bash
# 1. 패키지 설치
pip install -r requirements.txt

# 2. 실행
python main_gui.py
```

---

## 📖 사용법

### 기본 사용법

1. 프로그램 실행: `python main_gui.py`
2. URL 입력
3. 옵션 설정 (최대 페이지, 깊이, 빠른 스캔, Alert 모드)
4. 스캔 시작

### 옵션 설명

| 옵션 | 설명 | 기본값 |
|------|------|--------|
| 최대 페이지 | 크롤링할 최대 페이지 수 | 30 |
| 최대 깊이 | 링크를 따라갈 최대 단계 | 3 |
| 빠른 스캔 | 7개 페이로드만 사용 | 체크됨 |
| Headless | 브라우저 창 숨김 | 체크됨 |
| 🔔 Alert 모드 | alert()로 XSS 확인 | 체크 안 됨 |

---

## 📁 파일 구조

```
xss_scanner_v5.6/
├── main_gui.py              # 메인 GUI
├── xss_engine_selenium.py   # Selenium 스캔 엔진
├── xss_engine.py            # Requests 폴백 엔진
├── config.py                # ⭐ 설정 파일 (NEW)
├── logger.py                # ⭐ 로깅 시스템 (NEW)
├── run_tests.py             # ⭐ 테스트 실행기 (NEW)
├── requirements.txt         # 의존성
├── README.md                # 문서
└── tests/                   # ⭐ 단위 테스트 (NEW)
    ├── __init__.py
    ├── test_config.py       # 설정 테스트 (27개)
    ├── test_logger.py       # 로깅 테스트 (17개)
    └── test_utils.py        # 유틸리티 테스트 (34개)
```

---

## ⚙️ 설정 커스터마이징

### 페이로드 추가

`config.py`의 `Payloads` 클래스에서 커스텀 페이로드 추가:

```python
@staticmethod
def get_custom_payloads(func: str = 'console.log') -> List[str]:
    return [
        f'<div onmouseenter={func}("CUSTOM_1")>',
        f'<marquee onstart={func}("CUSTOM_2")>',
    ]
```

### 탐지 패턴 추가

```python
# config.py의 Patterns 클래스
STORED_XSS_PATTERNS: List[Tuple[str, str]] = [
    # 기존 패턴들...
    (r'<custom[^>]*\sonclick\s*=', 'custom onclick XSS'),  # 추가
]
```

### 스캐너 설정 변경

```python
# config.py
@dataclass
class ScannerConfig:
    DEFAULT_MAX_PAGES: int = 50      # 30 → 50으로 변경
    DEFAULT_TIMEOUT: int = 15        # 10 → 15로 변경
    PAGE_LOAD_WAIT: float = 3.0      # 2.0 → 3.0으로 변경
```

---

## 📝 로깅 시스템

### 기본 사용

```python
from logger import setup_logging, get_logger

# 초기화 (한 번만)
setup_logging(
    log_dir="logs",
    log_file="scan.log",
    console_level=logging.INFO,
    file_level=logging.DEBUG
)

# 로거 가져오기
logger = get_logger("my_module")
logger.info("작업 시작")
```

### 로그 레벨

| 레벨 | 용도 | 색상 |
|------|------|------|
| DEBUG | 상세 디버깅 정보 | 청록 |
| INFO | 일반 정보 | 초록 |
| WARNING | 경고 | 노랑 |
| ERROR | 오류 | 빨강 |
| CRITICAL | 치명적 오류 | 마젠타 |

### 스캔 결과 로거

```python
from logger import ScanResultLogger

result_logger = ScanResultLogger()
result_logger.log_vulnerability(
    url="http://example.com",
    param="search",
    payload="<script>alert(1)</script>",
    severity="high"
)
```

---

## 🧪 단위 테스트

### 테스트 실행

```bash
# 기본 실행
python run_tests.py

# 상세 출력
python run_tests.py -v

# pytest 사용 (설치된 경우)
python run_tests.py --pytest

# 커버리지 측정 (pytest-cov 필요)
python run_tests.py --pytest --coverage
```

### 테스트 구조

| 파일 | 테스트 수 | 내용 |
|------|----------|------|
| test_config.py | 27개 | 설정값, 페이로드, 패턴, 위험도 분류 |
| test_logger.py | 17개 | 로그 레벨, 파일 출력, 색상 |
| test_utils.py | 34개 | URL 파싱, 패턴 매칭, 쿠키 파싱 |
| **총계** | **78개** | |

### 개별 테스트 실행

```bash
# 특정 테스트 파일만
python -m unittest tests.test_config -v

# 특정 테스트 클래스만
python -m unittest tests.test_config.TestPayloads -v

# 특정 테스트만
python -m unittest tests.test_config.TestPayloads.test_quick_payloads_count -v
```

---

## 📊 스캔 결과 해석

### 결과 유형

| 상태 | 의미 | 위험도 |
|------|------|--------|
| 🔴 XSS 실행됨 | JavaScript가 실제로 실행됨 | **높음** |
| 🔴 취약 | 페이로드가 실행됨 | **높음** |
| 🟡 반사 | 페이로드가 응답에 출력됨 | 중간 |
| DOM XSS | DOM에서 위험 요소 발견 | 중간~높음 |

### 위험도 분류 (`config.py`)

| 위험도 | 키워드 예시 |
|--------|-----------|
| 치명 | `document.cookie`, `eval()`, `localStorage` |
| 높음 | `document.location`, `innerHTML` |
| 중간 | `alert()`, `console.log` |
| 낮음 | 기타 |

---

## ❓ 자주 묻는 질문

### Q: 커스텀 페이로드를 추가하려면?

`config.py`의 `Payloads.get_custom_payloads()` 메서드를 수정하세요.

### Q: 로그 파일은 어디에 저장되나요?

기본적으로 `logs/xss_scanner.log`에 저장됩니다. `setup_logging()`으로 변경 가능합니다.

### Q: 테스트가 실패하면?

```bash
python run_tests.py -v
```
로 상세 출력을 확인하고, 실패한 테스트의 오류 메시지를 확인하세요.

---

## ⚠️ 주의사항

### 법적 고지

```
⚠️ 이 도구는 교육 및 합법적인 보안 테스트 목적으로만 사용하세요.
권한이 없는 시스템에 대한 스캔은 불법입니다.
```

---

## 🔄 버전 히스토리

| 버전 | 변경 사항 |
|------|----------|
| **v5.6** | **설정 파일 분리, 로깅 시스템, 단위 테스트 78개** |
| v5.5 | Alert 모드 추가 |
| v5.4 | 폼 수집 개선 |
| v5.3 | 디버그 버전 빌드 |
| v5.2 | 이미지 로딩 허용, 페이지 로드 전략 개선 |

---

**Made with ❤️ for Security Testing**
