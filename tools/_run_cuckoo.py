"""
Wrapper to launch CAPEv2 cuckoo.py with a monkey-patch for SQLAlchemy 2.x compatibility.

CAPEv2's scheduler.py calls `with self.db.session.begin():` which fails in SA 2.x
because autobegin creates a transaction immediately. This wrapper patches the
ScopedSession.begin() method to be a no-op contextmanager when a transaction is
already in progress.
"""
import contextlib
from sqlalchemy.orm import scoping

_orig_begin = scoping.ScopedSession.begin

@contextlib.contextmanager
def _safe_begin(self, **kw):
    """Wrap begin() to skip if a transaction is already active."""
    sess = self.registry()
    if sess.in_transaction():
        # Transaction already active — just yield, don't nest
        yield sess
    else:
        with _orig_begin(self, **kw) as s:
            yield s

# Monkey-patch
scoping.ScopedSession.begin = _safe_begin

# Now import and run cuckoo
import sys
sys.argv = ["cuckoo.py"]

# Execute cuckoo.py
exec(open("/opt/CAPEv2/cuckoo.py").read())
