"""Red battery + benign corpus for payload-aware CODE_EXEC modeling (jak-47d).

Every dangerous payload MUST stay opaque (ask). Every benign analysis cell
MUST come out clean. This test is the acceptance gate from the issue:
no previously-asking dangerous shape may loosen.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from jev_kit.code_payload import analyze_code_payload


def test_subprocess_with_literal_argv_is_a_child_command() -> None:
    code = 'subprocess.run(["ls", "-la"])'
    clean, children, reason = analyze_code_payload(code)
    assert clean and children == ["ls -la"] and reason is None


def test_subprocess_with_dynamic_argv_is_opaque() -> None:
    code = 'cmd = "rm -rf /"\nsubprocess.run(cmd.split())'
    clean, children, reason = analyze_code_payload(code)
    assert not clean and reason == "subprocess_dynamic_argv"


def test_subprocess_with_fstring_argv_is_opaque() -> None:
    code = 'subprocess.run([f"rm -rf {p}"])'
    clean, _, reason = analyze_code_payload(code)
    assert not clean


def test_eval_is_opaque() -> None:
    clean, _, reason = analyze_code_payload("eval('1+1')")
    assert not clean and "eval" in reason


def test_exec_is_opaque() -> None:
    clean, _, reason = analyze_code_payload("exec('import os')")
    assert not clean and "exec" in reason


def test_dunder_import_is_opaque() -> None:
    clean, _, reason = analyze_code_payload("__import__('os').system('id')")
    assert not clean


def test_os_system_is_a_child_command() -> None:
    clean, children, _ = analyze_code_payload("os.system('ls -la')")
    assert clean and children == ["ls -la"]


def test_os_remove_is_opaque() -> None:
    clean, _, reason = analyze_code_payload("os.remove('/tmp/f')")
    assert not clean and reason == "os_remove"


def test_os_popen_child_command() -> None:
    clean, children, _ = analyze_code_payload("os.popen('whoami')")
    assert clean and children == ["whoami"]


def test_unknown_import_is_opaque() -> None:
    clean, _, reason = analyze_code_payload("import ctypes")
    assert not clean and "ctypes" in reason


def test_relative_import_is_opaque() -> None:
    clean, _, reason = analyze_code_payload("from . import sibling")
    assert not clean and reason == "relative_import"


def test_unparsable_payload_is_opaque() -> None:
    clean, _, reason = analyze_code_payload("def broken(:")
    assert not clean and reason == "payload_syntax_error"


def test_benign_json_read_cell_is_clean() -> None:
    code = (
        "import json\n"
        "rows = [json.loads(l) for l in open('/tmp/x.jsonl')]\n"
        "print(len(rows))"
    )
    clean, children, reason = analyze_code_payload(code)
    assert clean and children == [] and reason is None


def test_benign_glob_read_cell_is_clean() -> None:
    code = (
        "import glob\n"
        "for f in glob.glob('/tmp/*.log'):\n"
        "    print(f)"
    )
    clean, children, reason = analyze_code_payload(code)
    assert clean and children == [] and reason is None


def test_benign_arithmetic_cell_is_clean() -> None:
    code = "x = sum(i*i for i in range(10))\nprint(x)"
    clean, children, reason = analyze_code_payload(code)
    assert clean and children == [] and reason is None


def test_open_write_mode_is_a_child_touch() -> None:
    clean, children, _ = analyze_code_payload('open("/tmp/out.txt", "w")')
    assert clean and children == ["touch /tmp/out.txt"]


def test_open_dynamic_path_is_opaque() -> None:
    clean, _, reason = analyze_code_payload("open(path_var, 'w')")
    assert not clean and reason == "open_dynamic_path"


def test_open_read_dynamic_path_is_opaque_too() -> None:
    # A dynamic read path cannot be judged either: opaque by one rule.
    clean, _, reason = analyze_code_payload("open(p)")
    assert not clean and reason == "open_dynamic_path"


def test_shutil_rmtree_is_opaque() -> None:
    clean, _, reason = analyze_code_payload("shutil.rmtree('/tmp/x')")
    assert not clean and reason == "shutil_rmtree"


def test_shutil_which_is_clean() -> None:
    clean, children, reason = analyze_code_payload("shutil.which('git')")
    assert clean and children == [] and reason is None


def test_sqlite3_read_is_clean() -> None:
    code = (
        "import sqlite3\n"
        "con = sqlite3.connect('/tmp/x.db')\n"
        "print(con.execute('SELECT 1').fetchall())"
    )
    clean, children, reason = analyze_code_payload(code)
    assert clean and children == [] and reason is None


def test_network_module_call_stays_parseable() -> None:
    # http/urllib calls are allowed to be SEEN; the egress facts fire from
    # the extracted literals downstream. The payload itself is not opaque
    # just for touching the module.
    code = "import urllib.request\nprint(urllib.request.urlopen('https://x').status)"
    clean, children, reason = analyze_code_payload(code)
    assert clean


def test_method_call_is_opaque() -> None:
    clean, _, reason = analyze_code_payload("obj.run_thing()")
    assert not clean


def test_lambda_eval_reference_is_opaque() -> None:
    clean, _, reason = analyze_code_payload("map(eval, ['1'])")
    assert not clean


def test_empty_payload_is_clean() -> None:
    clean, children, reason = analyze_code_payload("")
    assert clean and children == [] and reason is None


def test_benign_mixed_cell_with_listdir() -> None:
    code = (
        "import os\n"
        "files = os.listdir('/Users/pjbeyer/notes')\n"
        "print(sorted(files))"
    )
    clean, children, reason = analyze_code_payload(code)
    assert clean and children == [] and reason is None