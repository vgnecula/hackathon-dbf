import subprocess
import sys


def main() -> int:
    targets = sys.argv[1:] or ["tests"]
    result = subprocess.run([sys.executable, "-m", "pytest", "-q", *targets], check=False)
    return result.returncode


raise SystemExit(main())
