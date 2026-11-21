# Semgrep rule tests for owasp-ai-code-rules.yaml. Run from inside .semgrep/: semgrep --test .
# This file is intentionally insecure test input. It is excluded from Ruff and from
# Semgrep scans of the repository; it is never imported or executed.
import ast
import asyncio
import hashlib
import marshal
import os
import pickle
import random
import secrets
import subprocess

import dill
import joblib
import sqlalchemy
import torch
import yaml
from sqlalchemy import text

user_input = input()

# ruleid: owasp-ai-python-no-eval-or-exec
eval(user_input)
# ruleid: owasp-ai-python-no-eval-or-exec
exec(user_input)
# ok: owasp-ai-python-no-eval-or-exec
ast.literal_eval(user_input)

# ruleid: owasp-ai-python-shell-command-execution
subprocess.run(user_input, shell=True)
# ruleid: owasp-ai-python-shell-command-execution
subprocess.check_call(f"ls {user_input}", shell=True, timeout=5)
# ruleid: owasp-ai-python-shell-command-execution
os.system(user_input)
# ruleid: owasp-ai-python-shell-command-execution
os.popen(user_input)
# ruleid: owasp-ai-python-shell-command-execution
asyncio.create_subprocess_shell(user_input)
# ok: owasp-ai-python-shell-command-execution
subprocess.run(["ls", user_input], check=True)

# ruleid: owasp-ai-python-unsafe-deserialization
pickle.loads(user_input)
# ruleid: owasp-ai-python-unsafe-deserialization
pickle.Unpickler(open("x", "rb"))
# ruleid: owasp-ai-python-unsafe-deserialization
dill.loads(user_input)
# ruleid: owasp-ai-python-unsafe-deserialization
marshal.loads(user_input)
# ruleid: owasp-ai-python-unsafe-deserialization
joblib.load("model.pkl")

# ruleid: owasp-ai-python-unsafe-yaml-load
yaml.load(user_input, Loader=yaml.Loader)
# ruleid: owasp-ai-python-unsafe-yaml-load
yaml.load(user_input, Loader=yaml.UnsafeLoader)
# ruleid: owasp-ai-python-unsafe-yaml-load
yaml.unsafe_load(user_input)
# ruleid: owasp-ai-python-unsafe-yaml-load
yaml.full_load(user_input)
# ok: owasp-ai-python-unsafe-yaml-load
yaml.load(user_input, Loader=yaml.SafeLoader)
# ok: owasp-ai-python-unsafe-yaml-load
yaml.load(user_input, yaml.CSafeLoader)
# ok: owasp-ai-python-unsafe-yaml-load
yaml.safe_load(user_input)

# ruleid: owasp-ai-python-torch-load-without-weights-only
torch.load("checkpoint.pt")
# ruleid: owasp-ai-python-torch-load-without-weights-only
torch.load("checkpoint.pt", weights_only=False)
# ok: owasp-ai-python-torch-load-without-weights-only
torch.load("checkpoint.pt", map_location="cpu", weights_only=True)


def query(cur, name):
    # ruleid: owasp-ai-python-sql-string-building
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    # ruleid: owasp-ai-python-sql-string-building
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
    # ruleid: owasp-ai-python-sql-string-building
    cur.execute("SELECT * FROM users WHERE name = '{}'".format(name))
    # ruleid: owasp-ai-python-sql-string-building
    cur.execute("SELECT * FROM users WHERE name = " + name)
    # ruleid: owasp-ai-python-sql-string-building
    sqlalchemy.text(f"SELECT * FROM users WHERE name = '{name}'")
    # ruleid: owasp-ai-python-sql-string-building
    text(f"SELECT * FROM users WHERE name = '{name}'")
    # ok: owasp-ai-python-sql-string-building
    cur.execute("SELECT * FROM users WHERE name = %s", (name,))
    # ok: owasp-ai-python-sql-string-building
    text("SELECT * FROM users WHERE name = :name")


# ruleid: owasp-ai-python-weak-crypto-hash
hashlib.md5(b"password")
# ruleid: owasp-ai-python-weak-crypto-hash
hashlib.new("sha1", b"password")
# ok: owasp-ai-python-weak-crypto-hash
hashlib.md5(b"cache-key", usedforsecurity=False)
# ok: owasp-ai-python-weak-crypto-hash
hashlib.sha256(b"data")

# ruleid: owasp-ai-python-insecure-random-for-security
token = random.randint(0, 2**32)
# ruleid: owasp-ai-python-insecure-random-for-security
session_id = random.choice("abcdef")
# ok: owasp-ai-python-insecure-random-for-security
token = secrets.token_urlsafe(32)
