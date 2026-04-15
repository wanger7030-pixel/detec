"""Launch cuckoo.py with a monkey-patched SQLAlchemy session.begin().

This wraps session.begin() to gracefully handle 'transaction already begun'
without modifying any CAPEv2 source files.
"""
import sqlalchemy.orm.session

# Save original begin method
_original_begin = sqlalchemy.orm.session.Session.begin

def _safe_begin(self, nested=False, **kwargs):
    """Wrapper that silently handles already-active transactions."""
    try:
        return _original_begin(self, nested=nested, **kwargs)
    except sqlalchemy.exc.InvalidRequestError as e:
        if "already begun" in str(e):
            # Transaction already active, return a dummy context manager
            import contextlib
            return contextlib.nullcontext()
        raise

# Monkey-patch
sqlalchemy.orm.session.Session.begin = _safe_begin
print("[PATCH] session.begin() monkey-patched to handle InvalidRequestError")

# Now launch cuckoo.py
import subprocess, sys, os

os.chdir("/opt/CAPEv2")
result = subprocess.run(
    ["python3", "-m", "poetry", "run", "python3", "-c",
     "import sqlalchemy.orm.session;"
     "from sqlalchemy.exc import InvalidRequestError;"
     "import contextlib;"
     "_orig = sqlalchemy.orm.session.Session.begin;"
     "def _safe(self, nested=False, **kw):\n"
     "  try:\n"
     "    return _orig(self, nested=nested, **kw)\n"
     "  except InvalidRequestError as e:\n"
     "    if 'already begun' in str(e): return contextlib.nullcontext()\n"
     "    raise\n;"
     "sqlalchemy.orm.session.Session.begin = _safe;"
     "print('[PATCH] Applied');"
     "exec(open('cuckoo.py').read())"
    ],
    capture_output=False
)
