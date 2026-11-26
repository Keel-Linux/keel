# Copyright (c) 2026 KeelLinux maintainers
"""The pasted line and the served script stop and fail loud (keel#331)

The line that keel access invite prints, and the script it fetches, run
under sh with curl, sudo and the tools of the script replaced by fakes
on PATH. A closed port, a wrong pin, a refusal or a failed step gives a
non-zero exit and a message; the line waits a limited time. No test
opens a port or changes the machine.
"""

import os
import shutil
import subprocess
import tempfile
import unittest

from helpers import spec  # noqa: F401  (puts the repository on sys.path)
from test_access_enrol import SECRET
from test_access_network import ACCESS, KEY_B

from keel.access import enrol

# curl's exit codes of the real test: 28 a closed port (time-out), 90 a
# pin that does not match, 22 an HTTP error (the node refused)
TIMED_OUT = 28
WRONG_PIN = 90
REFUSED = 22
# curl writes -o's file from FAKE_BODY, then exits FAKE_EXIT (or, for
# the second request of the script, FAKE_POST_EXIT)
FAKE_CURL = """#!/bin/sh
printf '%s\\n' "$*" >> "$FAKE_DIR/curl.argv"
out=''
post=''
while [ $# -gt 0 ]; do
    case "$1" in
        -o) out=$2; shift ;;
        --data) post=yes; shift ;;
    esac
    shift
done
if [ -n "$post" ]; then
    code=${FAKE_POST_EXIT:-0}
    [ "$code" = 0 ] && printf '%s' "$FAKE_ANSWER"
    [ "$code" = 0 ] || echo "curl: ($code) fake failure" >&2
    exit "$code"
fi
code=${FAKE_EXIT:-0}
if [ "$code" != 0 ]; then
    echo "curl: ($code) fake failure" >&2
    exit "$code"
fi
[ -z "$out" ] || printf '%s\\n' "$FAKE_BODY" > "$out"
"""


class FakeBin(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        self.bin = os.path.join(self.dir, "bin")
        self.tmp = os.path.join(self.dir, "tmp")
        os.mkdir(self.bin)
        os.mkdir(self.tmp)
        self.fake("curl", FAKE_CURL)
        self.fake("sudo", '#!/bin/sh\nexec "$@"\n')

    def fake(self, name: str, body: str) -> None:
        path = os.path.join(self.bin, name)
        with open(path, "w") as fob:
            fob.write(body)
        os.chmod(path, 0o755)

    def env(self, **values) -> dict:
        return {"PATH": f"{self.bin}:{os.environ['PATH']}",
                "TMPDIR": self.tmp, "FAKE_DIR": self.dir, **values}

    def curl_argv(self) -> list[str]:
        try:
            with open(os.path.join(self.dir, "curl.argv")) as fob:
                return fob.read().splitlines()
        except FileNotFoundError:
            return []


class TestLine(FakeBin):
    def line(self) -> str:
        return enrol.command("2001:db8::1", 50000, "PIN=",
                             "0123456789abcdef", SECRET)

    def paste(self, **values) -> subprocess.CompletedProcess:
        return subprocess.run(["sh", "-c", self.line()], capture_output=True,
                              text=True, env=self.env(**values), timeout=60,
                              check=False)

    def test_a_closed_port_fails_with_curl_s_status_and_a_message(self):
        done = self.paste(FAKE_EXIT=str(TIMED_OUT))
        self.assertEqual(done.returncode, TIMED_OUT, done.stderr)
        self.assertIn("keel access: the script did not come from the node",
                      done.stderr)
        self.assertIn("used, expired", done.stderr)
        self.assertEqual(os.listdir(self.tmp), [])

    def test_a_wrong_pin_fails_with_curl_s_status(self):
        done = self.paste(FAKE_EXIT=str(WRONG_PIN))
        self.assertEqual(done.returncode, WRONG_PIN, done.stderr)
        self.assertIn(f"curl exit {WRONG_PIN}", done.stderr)
        self.assertEqual(os.listdir(self.tmp), [])

    def test_a_script_that_fails_gives_its_status(self):
        done = self.paste(FAKE_BODY="exit 3")
        self.assertEqual(done.returncode, 3, done.stderr)
        self.assertIn("keel access: the enrolment failed (exit 3)",
                      done.stderr)
        self.assertEqual(os.listdir(self.tmp), [])

    def test_a_script_that_succeeds_exits_0_and_cleans_up(self):
        done = self.paste(FAKE_BODY=f'read -r s; [ "$s" = "{SECRET}" ]')
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stderr, "")
        self.assertEqual(os.listdir(self.tmp), [])

    def test_the_wait_is_limited(self):
        self.paste(FAKE_BODY="exit 0")
        (argv,) = self.curl_argv()
        self.assertIn(f"--connect-timeout {enrol.CONNECT_TIMEOUT}", argv)
        self.assertIn(f"--max-time {enrol.SCRIPT_TIME}", argv)

    def test_the_line_runs_in_a_subshell(self):
        """An exit at the top level would close the administrator's
        terminal: the line's exit is its subshell's"""
        line = self.line()
        self.assertTrue(line.startswith("(f=$(mktemp) || exit 1;"), line)
        self.assertTrue(line.endswith("; exit $s)"), line)
        # zsh reserves `status`
        self.assertNotIn("status", line)


class TestServedScript(FakeBin):
    """The script up to its POST: the steps before wg-quick write
    nothing outside a temporary directory"""

    def setUp(self):
        super().setUp()
        if shutil.which("openssl") is None:
            self.skipTest("no openssl")
        self.script = enrol.script(
            endpoint="2001:db8::1", port=50000, pin="PIN=",
            invite_id="0123456789abcdef", node_key=KEY_B, access=ACCESS)
        conf = (f"/etc/wireguard/"
                f"{enrol.client_interface(str(ACCESS['address']))}.conf")
        if os.path.exists(conf):
            self.skipTest(f"{conf} is on this machine")
        self.fake("id", "#!/bin/sh\necho 0\n")
        self.fake("wg", '#!/bin/sh\n[ "$1" = genkey ] && echo '
                  'aWtleWlrZXlpa2V5aWtleWlrZXlpa2V5aWtleWlrZXk=\n'
                  '[ "$1" = pubkey ] && cat >/dev/null && echo '
                  f'{KEY_B}\nexit 0\n')
        self.fake("wg-quick", "#!/bin/sh\nexit 1\n")

    def run_script(self, **values) -> subprocess.CompletedProcess:
        return subprocess.run(["sh", "-c", self.script, "sh"],
                              input=SECRET + "\n", capture_output=True,
                              text=True, env=self.env(**values), timeout=60,
                              check=False)

    def test_a_node_it_cannot_reach_is_said_as_such(self):
        done = self.run_script(FAKE_POST_EXIT=str(TIMED_OUT))
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("keel access: the node did not answer the enrolment"
                      f" (curl exit {TIMED_OUT})", done.stderr)

    def test_a_refusal_is_said_as_such(self):
        done = self.run_script(FAKE_POST_EXIT=str(REFUSED))
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("the node refused the enrolment", done.stderr)

    def test_an_answer_with_no_address_fails(self):
        done = self.run_script(FAKE_ANSWER='{"error": "x"}')
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("the node's answer has no address", done.stderr)

    def test_the_post_s_wait_is_limited(self):
        self.run_script(FAKE_POST_EXIT=str(TIMED_OUT))
        (argv,) = self.curl_argv()
        self.assertIn(f"--connect-timeout {enrol.CONNECT_TIMEOUT}", argv)
        self.assertIn(f"--max-time {enrol.ENROL_TIME}", argv)

    def test_a_missing_openssl_digest_fails_before_the_request(self):
        self.fake("openssl", "#!/bin/sh\ncat >/dev/null\nexit 1\n")
        done = self.run_script()
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("keel access: openssl could not make the proof",
                      done.stderr)
        self.assertEqual(self.curl_argv(), [])

    def test_wg_quick_that_fails_is_said(self):
        """wg-quick is the last step: the script names it on failure"""
        self.assertIn('wg-quick up "$iface" \\\n        || fail', self.script)


if __name__ == "__main__":
    unittest.main()
