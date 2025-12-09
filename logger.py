"""
================================================================================
XSS Scanner - 로깅 시스템 (logger.py)
================================================================================

Python logging 모듈을 사용한 체계적인 로깅 시스템입니다.

특징:
- 콘솔 + 파일 동시 출력
- 로그 레벨별 색상 (콘솔)
- 타임스탬프 자동 기록
- 로그 파일 자동 로테이션

사용법:
    from logger import get_logger, LogLevel
    
    logger = get_logger("scanner")
    logger.info("스캔 시작")
    logger.warning("경고 메시지")
    logger.error("오류 발생")
================================================================================
"""

import logging
import sys
import os
from datetime import datetime
from typing import Optional
from enum import Enum
from logging.handlers import RotatingFileHandler


# ==============================================================================
# 로그 레벨 정의
# ==============================================================================

class LogLevel(Enum):
    """로그 레벨"""
    DEBUG = logging.DEBUG       # 10
    INFO = logging.INFO         # 20
    WARNING = logging.WARNING   # 30
    ERROR = logging.ERROR       # 40
    CRITICAL = logging.CRITICAL # 50


# ==============================================================================
# 색상 코드 (콘솔 출력용)
# ==============================================================================

class Colors:
    """ANSI 색상 코드"""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    
    # 로그 레벨별 색상
    DEBUG = '\033[36m'      # Cyan
    INFO = '\033[32m'       # Green
    WARNING = '\033[33m'    # Yellow
    ERROR = '\033[31m'      # Red
    CRITICAL = '\033[35m'   # Magenta
    
    # 추가 색상
    GREY = '\033[90m'
    WHITE = '\033[97m'
    
    @classmethod
    def colorize(cls, text: str, color: str) -> str:
        """텍스트에 색상 적용"""
        return f"{color}{text}{cls.RESET}"


# ==============================================================================
# 커스텀 포맷터
# ==============================================================================

class ColoredFormatter(logging.Formatter):
    """콘솔용 색상 포맷터"""
    
    LEVEL_COLORS = {
        'DEBUG': Colors.DEBUG,
        'INFO': Colors.INFO,
        'WARNING': Colors.WARNING,
        'ERROR': Colors.ERROR,
        'CRITICAL': Colors.CRITICAL,
    }
    
    def format(self, record):
        # 로그 레벨에 색상 적용
        level_color = self.LEVEL_COLORS.get(record.levelname, Colors.WHITE)
        
        # 타임스탬프 (회색)
        timestamp = datetime.fromtimestamp(record.created).strftime('%H:%M:%S')
        colored_time = Colors.colorize(timestamp, Colors.GREY)
        
        # 로그 레벨 (색상)
        colored_level = Colors.colorize(f"[{record.levelname:^8}]", level_color)
        
        # 로거 이름 (회색)
        colored_name = Colors.colorize(f"({record.name})", Colors.GREY)
        
        # 메시지
        message = record.getMessage()
        
        return f"{colored_time} {colored_level} {colored_name} {message}"


class FileFormatter(logging.Formatter):
    """파일용 포맷터 (색상 없음)"""
    
    def __init__(self):
        super().__init__(
            fmt='%(asctime)s [%(levelname)-8s] (%(name)s) %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )


# ==============================================================================
# 로거 관리자
# ==============================================================================

class LoggerManager:
    """로거 인스턴스 관리"""
    
    _loggers: dict = {}
    _log_dir: str = "logs"
    _log_file: str = "xss_scanner.log"
    _max_bytes: int = 5 * 1024 * 1024  # 5MB
    _backup_count: int = 3
    _console_level: int = logging.INFO
    _file_level: int = logging.DEBUG
    _initialized: bool = False
    
    @classmethod
    def setup(cls, 
              log_dir: str = "logs",
              log_file: str = "xss_scanner.log",
              console_level: int = logging.INFO,
              file_level: int = logging.DEBUG,
              max_bytes: int = 5 * 1024 * 1024,
              backup_count: int = 3):
        """
        로깅 시스템 초기화
        
        Args:
            log_dir: 로그 파일 디렉토리
            log_file: 로그 파일명
            console_level: 콘솔 출력 레벨
            file_level: 파일 출력 레벨
            max_bytes: 로그 파일 최대 크기
            backup_count: 백업 파일 개수
        """
        cls._log_dir = log_dir
        cls._log_file = log_file
        cls._console_level = console_level
        cls._file_level = file_level
        cls._max_bytes = max_bytes
        cls._backup_count = backup_count
        cls._initialized = True
        
        # 로그 디렉토리 생성
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
    
    @classmethod
    def get_logger(cls, name: str = "xss_scanner") -> logging.Logger:
        """
        로거 인스턴스 반환
        
        Args:
            name: 로거 이름
            
        Returns:
            logging.Logger 인스턴스
        """
        if name in cls._loggers:
            return cls._loggers[name]
        
        # 새 로거 생성
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)
        logger.handlers = []  # 기존 핸들러 제거
        
        # 콘솔 핸들러
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(cls._console_level)
        console_handler.setFormatter(ColoredFormatter())
        logger.addHandler(console_handler)
        
        # 파일 핸들러 (초기화된 경우에만)
        if cls._initialized:
            log_path = os.path.join(cls._log_dir, cls._log_file)
            file_handler = RotatingFileHandler(
                log_path,
                maxBytes=cls._max_bytes,
                backupCount=cls._backup_count,
                encoding='utf-8'
            )
            file_handler.setLevel(cls._file_level)
            file_handler.setFormatter(FileFormatter())
            logger.addHandler(file_handler)
        
        cls._loggers[name] = logger
        return logger
    
    @classmethod
    def set_level(cls, level: int, console: bool = True, file: bool = True):
        """모든 로거의 레벨 변경"""
        for logger in cls._loggers.values():
            for handler in logger.handlers:
                if isinstance(handler, logging.StreamHandler) and console:
                    handler.setLevel(level)
                elif isinstance(handler, RotatingFileHandler) and file:
                    handler.setLevel(level)


# ==============================================================================
# 편의 함수
# ==============================================================================

def setup_logging(log_dir: str = "logs",
                  log_file: str = "xss_scanner.log",
                  console_level: int = logging.INFO,
                  file_level: int = logging.DEBUG) -> None:
    """
    로깅 시스템 초기화 (편의 함수)
    
    사용법:
        from logger import setup_logging, get_logger
        
        setup_logging(log_dir="logs", console_level=logging.DEBUG)
        logger = get_logger("scanner")
    """
    LoggerManager.setup(
        log_dir=log_dir,
        log_file=log_file,
        console_level=console_level,
        file_level=file_level
    )


def get_logger(name: str = "xss_scanner") -> logging.Logger:
    """
    로거 인스턴스 반환 (편의 함수)
    
    사용법:
        from logger import get_logger
        
        logger = get_logger("crawler")
        logger.info("크롤링 시작")
    """
    return LoggerManager.get_logger(name)


# ==============================================================================
# GUI 연동용 핸들러
# ==============================================================================

class GUILogHandler(logging.Handler):
    """
    GUI 텍스트 위젯에 로그를 출력하는 핸들러
    
    사용법:
        gui_handler = GUILogHandler(text_widget, root)
        logger.addHandler(gui_handler)
    """
    
    def __init__(self, text_widget, root, level=logging.INFO):
        """
        Args:
            text_widget: tkinter Text 위젯
            root: tkinter root 윈도우 (thread-safe 업데이트용)
            level: 로그 레벨
        """
        super().__init__(level)
        self.text_widget = text_widget
        self.root = root
        
        # 로그 레벨별 태그 색상
        self.level_tags = {
            'DEBUG': 'debug',
            'INFO': 'info',
            'WARNING': 'warning',
            'ERROR': 'error',
            'CRITICAL': 'critical',
        }
    
    def emit(self, record):
        """로그 레코드를 GUI에 출력"""
        try:
            msg = self.format(record)
            tag = self.level_tags.get(record.levelname, 'info')
            
            # thread-safe하게 GUI 업데이트
            self.root.after(0, self._append_log, msg, tag)
        except Exception:
            self.handleError(record)
    
    def _append_log(self, msg: str, tag: str):
        """GUI에 로그 추가 (메인 스레드에서 실행)"""
        try:
            self.text_widget.config(state='normal')
            self.text_widget.insert('end', msg + '\n', tag)
            self.text_widget.see('end')
            self.text_widget.config(state='disabled')
        except Exception:
            pass


# ==============================================================================
# 스캔 결과 로거
# ==============================================================================

class ScanResultLogger:
    """
    스캔 결과를 구조화된 형태로 기록하는 전용 로거
    
    사용법:
        result_logger = ScanResultLogger("scan_results.log")
        result_logger.log_vulnerability(url, param, payload, severity)
    """
    
    def __init__(self, log_file: str = "scan_results.log", log_dir: str = "logs"):
        self.log_dir = log_dir
        self.log_file = log_file
        self.log_path = os.path.join(log_dir, log_file)
        
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        self._logger = logging.getLogger("scan_results")
        self._logger.setLevel(logging.INFO)
        self._logger.handlers = []
        
        # 결과 전용 파일 핸들러
        handler = logging.FileHandler(self.log_path, encoding='utf-8')
        handler.setFormatter(logging.Formatter('%(asctime)s | %(message)s'))
        self._logger.addHandler(handler)
    
    def log_scan_start(self, url: str, options: dict = None):
        """스캔 시작 기록"""
        self._logger.info(f"SCAN_START | URL: {url} | Options: {options}")
    
    def log_scan_end(self, stats: dict = None):
        """스캔 종료 기록"""
        self._logger.info(f"SCAN_END | Stats: {stats}")
    
    def log_vulnerability(self, url: str, param: str, payload: str, 
                          severity: str = "medium", evidence: str = ""):
        """취약점 발견 기록"""
        self._logger.info(
            f"VULNERABILITY | Severity: {severity.upper()} | "
            f"URL: {url} | Param: {param} | Payload: {payload[:50]} | "
            f"Evidence: {evidence[:100]}"
        )
    
    def log_stored_xss(self, url: str, pattern: str, content: str):
        """저장된 XSS 발견 기록"""
        self._logger.info(
            f"STORED_XSS | URL: {url} | Pattern: {pattern} | "
            f"Content: {content[:100]}"
        )
    
    def log_error(self, url: str, error: str):
        """오류 기록"""
        self._logger.error(f"ERROR | URL: {url} | Error: {error}")


# ==============================================================================
# 테스트 및 예제
# ==============================================================================

if __name__ == "__main__":
    # 로깅 시스템 초기화
    setup_logging(
        log_dir="logs",
        log_file="test.log",
        console_level=logging.DEBUG
    )
    
    # 로거 가져오기
    logger = get_logger("test")
    
    # 다양한 레벨의 로그 출력
    print("\n" + "=" * 60)
    print("로깅 시스템 테스트")
    print("=" * 60 + "\n")
    
    logger.debug("디버그 메시지 - 상세 정보")
    logger.info("정보 메시지 - 일반 정보")
    logger.warning("경고 메시지 - 주의 필요")
    logger.error("오류 메시지 - 문제 발생")
    logger.critical("치명적 메시지 - 즉시 조치 필요")
    
    # 다른 이름의 로거
    crawler_logger = get_logger("crawler")
    crawler_logger.info("크롤링 시작: http://example.com")
    
    scanner_logger = get_logger("scanner")
    scanner_logger.warning("XSS 취약점 발견!")
    
    print("\n" + "=" * 60)
    print(f"로그 파일 저장됨: logs/test.log")
    print("=" * 60)
