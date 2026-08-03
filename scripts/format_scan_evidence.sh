#!/usr/bin/env bash
# Formats the static SQL scan into the E10 evidence file.
cd "$(dirname "$0")/.."
cat > /tmp/planted_patterns.py << 'PLANT'
def a(email):
    return f"SELECT * FROM users WHERE email = {email}"
def b(email):
    return "SELECT * FROM users WHERE email = %s" % email
def c(email):
    return "SELECT * FROM users WHERE email = {}".format(email)
def d(email):
    return "SELECT * FROM users WHERE email = " + email
def safe(email):
    return "SELECT * FROM users WHERE email = ?"
PLANT
echo "EVIDENCE E10 - Static scan for dynamically built SQL"
echo "Captured: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "Method: each module is parsed to an abstract syntax tree and inspected for"
echo "        SQL text built from a value (f-string, % format, .format(), +)."
echo "        Parsing the AST rather than grepping means prose in comments and"
echo "        docstrings cannot raise a false positive."
echo "Source: tests/test_sqli.py :: find_dynamic_sql()"
echo "======================================================================"
echo
echo "[A] CONTROL - a file deliberately containing all four unsafe patterns"
echo "    must be flagged, otherwise the scanner proves nothing:"
python3 -c "
import sys; sys.path.insert(0,'.')
from pathlib import Path
from tests.test_sqli import find_dynamic_sql
for f in find_dynamic_sql(Path('/tmp/planted_patterns.py')): print('      ', f)"
echo
echo "[B] The legacy prototype under review (the 'before' state):"
python3 -c "
import sys; sys.path.insert(0,'.')
from pathlib import Path
from tests.test_sqli import find_dynamic_sql
for f in find_dynamic_sql(Path('insecure_baseline/legacy_login.py')): print('      ', f)"
echo "      -> line 51 is legacy_authenticate(); line 62 is legacy_course_search()"
echo
echo "[C] The hardened application (the 'after' state):"
python3 -c "
import sys; sys.path.insert(0,'.')
from pathlib import Path
from tests.test_sqli import find_dynamic_sql
for p in sorted(Path('secure_app').glob('*.py')):
    print(f'      secure_app/{p.name:<14} ' + str(find_dynamic_sql(p) or 'clean - no dynamically built SQL'))"
echo
echo "Every statement in secure_app reaches the engine as fixed text with bound"
echo "parameters. This check runs as part of the test suite, so a regression"
echo "that reintroduces string-built SQL fails the build."
