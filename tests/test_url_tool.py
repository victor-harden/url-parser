import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import url_tool


class UrlToolTests(unittest.TestCase):
    def test_components(self):
        data = url_tool.components("https://user:secret@example.com:8443/a?x=1#frag")
        self.assertEqual(data["scheme"], "https")
        self.assertEqual(data["host"], "example.com")
        self.assertEqual(data["port"], 8443)
        self.assertEqual(data["query"]["x"], "1")
        self.assertEqual(data["password"], "***")

    def test_query_multiple(self):
        data = url_tool.components("https://example.com/?a=1&b=2&a=3")
        self.assertEqual(data["query"]["a"], "3")

    def test_normalize_sorts_query_and_drops_default_port(self):
        result = url_tool.normalize("HTTPS://Example.COM:443/a?b=2&a=1")
        self.assertEqual(result, "https://example.com/a?a=1&b=2")

    def test_normalize_adds_root_path(self):
        self.assertEqual(url_tool.normalize("https://example.com"), "https://example.com/")

    def test_check_credentials(self):
        notes = url_tool.check("https://user:pass@example.com")
        self.assertIn("credentials-in-url", {n["issue"] for n in notes})

    def test_check_scheme(self):
        notes = url_tool.check("javascript:alert(1)")
        self.assertIn("unusual-scheme", {n["issue"] for n in notes})

    def test_check_ip_literal(self):
        notes = url_tool.check("http://192.168.1.1/")
        self.assertIn("ip-literal", {n["issue"] for n in notes})

    def test_check_clean_url(self):
        self.assertEqual(url_tool.check("https://example.com/path"), [])

    def test_cli_json(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = url_tool.main(["--json", "https://example.com"])
        self.assertEqual(code, 0)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["components"]["host"], "example.com")

    def test_cli_high_severity_exit_code(self):
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()):
            code = url_tool.main(["--check", "javascript:alert(1)"])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
