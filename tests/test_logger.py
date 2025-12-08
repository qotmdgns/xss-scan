"""
================================================================================
XSS Scanner - 로깅 시스템 테스트 (test_logger.py)
================================================================================

logger.py의 로깅 기능을 테스트합니다.

실행:
    python -m pytest tests/test_logger.py -v
    python tests/test_logger.py
================================================================================
"""

import unittest
import sys
import os
import logging
import tempfile
import shutil

# 상위 디렉토리를 path에 추가
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from logger import (
    LogLevel, Colors, LoggerManager, 
    setup_logging, get_logger, ScanResultLogger
)


class TestLogLevel(unittest.TestCase):
    """로그 레벨 테스트"""
    
    def test_log_levels_defined(self):
        """로그 레벨이 정의되어 있는지 확인"""
        self.assertEqual(LogLevel.DEBUG.value, logging.DEBUG)
        self.assertEqual(LogLevel.INFO.value, logging.INFO)
        self.assertEqual(LogLevel.WARNING.value, logging.WARNING)
        self.assertEqual(LogLevel.ERROR.value, logging.ERROR)
        self.assertEqual(LogLevel.CRITICAL.value, logging.CRITICAL)
    
    def test_log_level_ordering(self):
        """로그 레벨 순서 확인"""
        self.assertLess(LogLevel.DEBUG.value, LogLevel.INFO.value)
        self.assertLess(LogLevel.INFO.value, LogLevel.WARNING.value)
        self.assertLess(LogLevel.WARNING.value, LogLevel.ERROR.value)
        self.assertLess(LogLevel.ERROR.value, LogLevel.CRITICAL.value)


class TestColors(unittest.TestCase):
    """색상 코드 테스트"""
    
    def test_ansi_codes_exist(self):
        """ANSI 색상 코드가 존재하는지 확인"""
        self.assertIsNotNone(Colors.RESET)
        self.assertIsNotNone(Colors.DEBUG)
        self.assertIsNotNone(Colors.INFO)
        self.assertIsNotNone(Colors.WARNING)
        self.assertIsNotNone(Colors.ERROR)
        self.assertIsNotNone(Colors.CRITICAL)
    
    def test_colorize_function(self):
        """colorize 함수 테스트"""
        text = "test"
        colored = Colors.colorize(text, Colors.INFO)
        
        self.assertIn(text, colored)
        self.assertIn(Colors.INFO, colored)
        self.assertIn(Colors.RESET, colored)
    
    def test_colorize_empty_string(self):
        """빈 문자열 colorize 테스트"""
        result = Colors.colorize("", Colors.INFO)
        self.assertIn(Colors.RESET, result)


class TestLoggerManager(unittest.TestCase):
    """로거 매니저 테스트"""
    
    def setUp(self):
        """테스트 전 임시 디렉토리 생성"""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """테스트 후 임시 디렉토리 삭제"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        # 로거 캐시 초기화
        LoggerManager._loggers = {}
        LoggerManager._initialized = False
    
    def test_setup_creates_log_directory(self):
        """setup이 로그 디렉토리를 생성하는지 확인"""
        log_dir = os.path.join(self.temp_dir, "logs")
        self.assertFalse(os.path.exists(log_dir))
        
        LoggerManager.setup(log_dir=log_dir)
        
        self.assertTrue(os.path.exists(log_dir))
    
    def test_get_logger_returns_logger(self):
        """get_logger가 로거를 반환하는지 확인"""
        logger = LoggerManager.get_logger("test")
        
        self.assertIsInstance(logger, logging.Logger)
        self.assertEqual(logger.name, "test")
    
    def test_get_logger_caching(self):
        """동일한 이름의 로거가 캐싱되는지 확인"""
        logger1 = LoggerManager.get_logger("test_cache")
        logger2 = LoggerManager.get_logger("test_cache")
        
        self.assertIs(logger1, logger2)
    
    def test_different_loggers_are_different(self):
        """다른 이름의 로거는 다른 인스턴스인지 확인"""
        logger1 = LoggerManager.get_logger("logger1")
        logger2 = LoggerManager.get_logger("logger2")
        
        self.assertIsNot(logger1, logger2)


class TestConvenienceFunctions(unittest.TestCase):
    """편의 함수 테스트"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        LoggerManager._loggers = {}
        LoggerManager._initialized = False
    
    def test_setup_logging(self):
        """setup_logging 함수 테스트"""
        log_dir = os.path.join(self.temp_dir, "logs")
        
        setup_logging(
            log_dir=log_dir,
            log_file="test.log",
            console_level=logging.DEBUG
        )
        
        self.assertTrue(os.path.exists(log_dir))
    
    def test_get_logger_convenience(self):
        """get_logger 편의 함수 테스트"""
        logger = get_logger("convenience_test")
        
        self.assertIsInstance(logger, logging.Logger)


class TestLoggerOutput(unittest.TestCase):
    """로거 출력 테스트"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = "test_output.log"
        LoggerManager.setup(
            log_dir=self.temp_dir,
            log_file=self.log_file,
            file_level=logging.DEBUG
        )
    
    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        LoggerManager._loggers = {}
        LoggerManager._initialized = False
    
    def test_log_to_file(self):
        """파일에 로그가 기록되는지 확인"""
        logger = get_logger("file_test")
        test_message = "테스트 메시지 12345"
        
        logger.info(test_message)
        
        # 파일 내용 확인
        log_path = os.path.join(self.temp_dir, self.log_file)
        
        # 핸들러 플러시
        for handler in logger.handlers:
            handler.flush()
        
        with open(log_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        self.assertIn(test_message, content)
    
    def test_log_levels_recorded(self):
        """다양한 로그 레벨이 기록되는지 확인"""
        logger = get_logger("level_test")
        
        logger.debug("DEBUG 메시지")
        logger.info("INFO 메시지")
        logger.warning("WARNING 메시지")
        logger.error("ERROR 메시지")
        
        # 파일 내용 확인
        log_path = os.path.join(self.temp_dir, self.log_file)
        
        for handler in logger.handlers:
            handler.flush()
        
        with open(log_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        self.assertIn("DEBUG", content)
        self.assertIn("INFO", content)
        self.assertIn("WARNING", content)
        self.assertIn("ERROR", content)


class TestScanResultLogger(unittest.TestCase):
    """스캔 결과 로거 테스트"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.result_logger = ScanResultLogger(
            log_file="results.log",
            log_dir=self.temp_dir
        )
    
    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_log_scan_start(self):
        """스캔 시작 로그 테스트"""
        self.result_logger.log_scan_start(
            url="http://example.com",
            options={'quick_mode': True}
        )
        
        log_path = os.path.join(self.temp_dir, "results.log")
        with open(log_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        self.assertIn("SCAN_START", content)
        self.assertIn("http://example.com", content)
    
    def test_log_vulnerability(self):
        """취약점 로그 테스트"""
        self.result_logger.log_vulnerability(
            url="http://example.com/page",
            param="search",
            payload="<script>alert(1)</script>",
            severity="high"
        )
        
        log_path = os.path.join(self.temp_dir, "results.log")
        with open(log_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        self.assertIn("VULNERABILITY", content)
        self.assertIn("HIGH", content)
        self.assertIn("search", content)
    
    def test_log_stored_xss(self):
        """저장된 XSS 로그 테스트"""
        self.result_logger.log_stored_xss(
            url="http://example.com/post/1",
            pattern="img onerror",
            content="<img src=x onerror=alert(1)>"
        )
        
        log_path = os.path.join(self.temp_dir, "results.log")
        with open(log_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        self.assertIn("STORED_XSS", content)
        self.assertIn("img onerror", content)


# ==============================================================================
# 테스트 실행
# ==============================================================================

if __name__ == '__main__':
    print("=" * 60)
    print("XSS Scanner - 로깅 시스템 테스트")
    print("=" * 60)
    
    unittest.main(verbosity=2)
