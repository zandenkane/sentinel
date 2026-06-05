import sys
from pathlib import Path

# Ensure the repo root is on sys.path so `import sentinel` works
# even when pytest is invoked from the tests/ directory.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
