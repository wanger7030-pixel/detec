"""Patch CAPEv2 scheduler.py for SQLAlchemy 2.x compatibility."""
import re

path = "/opt/CAPEv2/lib/cuckoo/core/scheduler.py"

with open(path, "r") as f:
    content = f.read()

# Replace 'with self.db.session.begin():' with a contextlib nullcontext
# This preserves the indentation of the block body
old = "with self.db.session.begin():"
new = "if True:  # SA2: auto-transaction"
count = content.count(old)
content = content.replace(old, new)

with open(path, "w") as f:
    f.write(content)

print(f"Replaced {count} occurrences")
