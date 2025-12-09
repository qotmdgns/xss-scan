#!/usr/bin/env python3
"""
================================================================================
XSS Scanner - 테스트 실행 스크립트 (run_tests.py)
================================================================================

모든 단위 테스트를 실행하고 결과를 출력합니다.

실행 방법:
    python run_tests.py
    python run_tests.py -v          # 상세 출력
    python run_tests.py --coverage  # 커버리지 측정 (pytest-cov 필요)
================================================================================
"""

import sys
import os
import unittest
import argparse
from datetime import datetime


def run_unittest(verbosity=2):
    """unittest로 테스트 실행"""
    # 테스트 디렉토리 경로
    test_dir = os.path.join(os.path.dirname(__file__), 'tests')
    
    # 테스트 로더
    loader = unittest.TestLoader()
    suite = loader.discover(test_dir, pattern='test_*.py')
    
    # 테스트 실행
    runner = unittest.TextTestRunner(verbosity=verbosity)
    result = runner.run(suite)
    
    return result


def run_pytest(verbose=False, coverage=False):
    """pytest로 테스트 실행 (설치된 경우)"""
    try:
        import pytest
    except ImportError:
        print("pytest가 설치되지 않았습니다. unittest로 실행합니다.")
        return None
    
    args = ['tests/', '-v' if verbose else '']
    
    if coverage:
        try:
            import pytest_cov
            args.extend(['--cov=.', '--cov-report=html'])
        except ImportError:
            print("pytest-cov가 설치되지 않았습니다. 커버리지 없이 실행합니다.")
    
    return pytest.main([arg for arg in args if arg])


def print_header():
    """테스트 헤더 출력"""
    print()
    print("=" * 70)
    print("  XSS Scanner v5.6 - 단위 테스트")
    print("=" * 70)
    print(f"  실행 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Python: {sys.version.split()[0]}")
    print("=" * 70)
    print()


def print_summary(result):
    """테스트 결과 요약 출력"""
    print()
    print("=" * 70)
    print("  테스트 결과 요약")
    print("=" * 70)
    
    total = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    skipped = len(result.skipped)
    success = total - failures - errors - skipped
    
    print(f"  총 테스트: {total}")
    print(f"  ✅ 성공: {success}")
    print(f"  ❌ 실패: {failures}")
    print(f"  ⚠️  오류: {errors}")
    print(f"  ⏭️  건너뜀: {skipped}")
    print()
    
    if failures == 0 and errors == 0:
        print("  🎉 모든 테스트 통과!")
    else:
        print("  ❌ 일부 테스트 실패")
        
        if result.failures:
            print("\n  실패한 테스트:")
            for test, trace in result.failures:
                print(f"    - {test}")
        
        if result.errors:
            print("\n  오류 발생 테스트:")
            for test, trace in result.errors:
                print(f"    - {test}")
    
    print("=" * 70)
    print()
    
    return failures == 0 and errors == 0


def main():
    """메인 함수"""
    parser = argparse.ArgumentParser(description='XSS Scanner 테스트 실행')
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='상세 출력')
    parser.add_argument('--coverage', action='store_true',
                       help='커버리지 측정 (pytest-cov 필요)')
    parser.add_argument('--pytest', action='store_true',
                       help='pytest 사용 (설치된 경우)')
    
    args = parser.parse_args()
    
    print_header()
    
    if args.pytest:
        result = run_pytest(verbose=args.verbose, coverage=args.coverage)
        if result is not None:
            sys.exit(result)
    
    # unittest로 실행
    verbosity = 2 if args.verbose else 1
    result = run_unittest(verbosity=verbosity)
    
    success = print_summary(result)
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
