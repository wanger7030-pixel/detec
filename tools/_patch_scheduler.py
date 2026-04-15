"""More careful patch for CAPEv2 scheduler.py.

Instead of removing session.begin(), we add a try/except wrapper
that catches InvalidRequestError when a transaction is already active,
and just continues without starting a new one.
"""
import re

SCHEDULER_PATH = "/opt/CAPEv2/lib/cuckoo/core/scheduler.py"
BACKUP_PATH = SCHEDULER_PATH + ".bak"

# Restore from backup first
with open(BACKUP_PATH, "r") as f:
    content = f.read()
print(f"Restored from backup ({len(content)} chars)")

# Count occurrences
old_pattern = "with self.db.session.begin():"
count = content.count(old_pattern)
print(f"Found {count} occurrences of '{old_pattern}'")

# Strategy: Add import for InvalidRequestError at top of file,
# then replace each `with self.db.session.begin():` with a 
# try/except that silently handles the case when a transaction
# is already active.

# 1. Add import for InvalidRequestError (after existing sqlalchemy imports)
if "InvalidRequestError" not in content:
    # Find where to add the import
    import_line = "from sqlalchemy.exc import InvalidRequestError"
    # Add after the last import line
    lines = content.split("\n")
    last_import_idx = 0
    for i, line in enumerate(lines):
        if line.strip().startswith("import ") or line.strip().startswith("from "):
            last_import_idx = i
    lines.insert(last_import_idx + 1, import_line)
    content = "\n".join(lines)
    print(f"Added import for InvalidRequestError at line {last_import_idx + 2}")

# 2. Replace `with self.db.session.begin():` with a safe version
# We need to handle the indentation properly.
# The replacement wraps the begin() in a try/except
lines = content.split("\n")
new_lines = []
i = 0
replaced = 0
while i < len(lines):
    line = lines[i]
    stripped = line.rstrip()
    if old_pattern in stripped:
        # Get the indentation
        indent = len(line) - len(line.lstrip())
        indent_str = line[:indent]
        
        # Replace with try/except pattern
        new_lines.append(f"{indent_str}try:")
        new_lines.append(f"{indent_str}    self.db.session.begin()")
        new_lines.append(f"{indent_str}except InvalidRequestError:")
        new_lines.append(f"{indent_str}    pass  # Transaction already active, continue")
        new_lines.append(f"{indent_str}if True:  # Original: with self.db.session.begin():")
        replaced += 1
    else:
        new_lines.append(line)
    i += 1

content = "\n".join(new_lines)
print(f"Replaced {replaced} occurrences")

# Write patched file
with open(SCHEDULER_PATH, "w") as f:
    f.write(content)

print("Patch v2 applied successfully!")
print("session.begin() is now wrapped in try/except InvalidRequestError")
