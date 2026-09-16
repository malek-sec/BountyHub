"""
Regression tests for the PDF report HTML sanitiser (services/pdf_service.py).

Why this exists
---------------
templates/scan_pdf_report.html renders the report body with `| safe`, so
whatever render_scan_pdf() hands it is emitted verbatim. Scan reports are
stored Markdown that can legitimately quote attacker-supplied strings -- a
reflected XSS proof of concept is literally a <script> tag -- so the body is
untrusted by construction.

The risk is not only XSS. WeasyPrint resolves URLs while laying out the PDF,
so a surviving <img src="file:///etc/passwd"> or <link href="file://...">
would pull local file content into the generated document.

Two properties are asserted here, and they pull in opposite directions:

  1. No DANGEROUS ELEMENT OR ATTRIBUTE survives as a live node.
  2. A payload quoted as evidence stays READABLE. Dropping the markup would
     turn "<script>alert(1)</script>" into a bare "alert(1)" and quietly
     destroy the evidence the report exists to present.

Escaping satisfies both: the payload renders as literal text and parses as
text, never as an element. That is why pdf_service uses strip=False.
"""

import unittest
from html.parser import HTMLParser

try:
    import bleach
    import markdown as _md
    _DEPS = True
except ImportError:  # pragma: no cover
    _DEPS = False

if _DEPS:
    from services.pdf_service import (
        _ALLOWED_ATTRS, _ALLOWED_PROTOCOLS, _ALLOWED_TAGS,
    )


# Elements that must never reach WeasyPrint as live nodes.
_DANGEROUS_ELEMENTS = {
    "script", "iframe", "object", "embed", "style",
    "link", "meta", "base", "svg", "form",
}
_DANGEROUS_PROTOCOLS = ("file:", "javascript:", "php:", "jar:", "data:text/html")


class _DomAudit(HTMLParser):
    """
    Walk the real parse tree and record live dangerous nodes.

    Substring matching is not good enough here: escaped text such as
    "&lt;iframe src=&quot;file://...&quot;&gt;" contains every scary substring
    while being completely inert. Only a parser can tell the two apart.
    """

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.problems: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in _DANGEROUS_ELEMENTS:
            self.problems.append(f"live <{tag}> element")
        for name, value in attrs:
            if name.lower().startswith("on"):
                self.problems.append(f"live event handler {name}= on <{tag}>")
            if value and value.strip().lower().startswith(_DANGEROUS_PROTOCOLS):
                self.problems.append(f"live {name}={value[:40]} on <{tag}>")


def _render(md_text: str) -> str:
    """Mirror exactly what render_scan_pdf() feeds the template."""
    return bleach.clean(
        _md.markdown(md_text, extensions=["tables", "fenced_code"]),
        tags=_ALLOWED_TAGS,
        attributes=_ALLOWED_ATTRS,
        protocols=_ALLOWED_PROTOCOLS,
        strip=False,
    )


def _live_problems(md_text: str) -> list[str]:
    audit = _DomAudit()
    audit.feed(_render(md_text))
    return audit.problems


@unittest.skipUnless(_DEPS, "bleach/markdown not installed")
class TestPdfSanitiserBlocksLiveVectors(unittest.TestCase):

    def test_no_dangerous_vector_survives_as_a_live_node(self):
        vectors = {
            "lfi_via_img":      '<img src="file:///etc/passwd">',
            "lfi_via_link":     '<link rel=stylesheet href="file:///etc/shadow">',
            "script_tag":       '<script>alert(1)</script>',
            "iframe_file":      '<iframe src="file:///etc/passwd"></iframe>',
            "onerror_handler":  '<img src="https://x/y.png" onerror="alert(1)">',
            "js_protocol":      '[click](javascript:alert(1))',
            "object_data":      '<object data="file:///etc/passwd"></object>',
            "style_import":     '<style>@import url("file:///etc/passwd");</style>',
            "base_href":        '<base href="file:///etc/">',
            "svg_onload":       '<svg onload="alert(1)"></svg>',
            "meta_refresh":     '<meta http-equiv="refresh" content="0;url=file:///etc/passwd">',
            "form_action":      '<form action="file:///x"><input name=a></form>',
            "data_text_html":   '<img src="data:text/html;base64,PHNjcmlwdD4=">',
        }
        for name, payload in vectors.items():
            with self.subTest(vector=name):
                self.assertEqual(
                    [], _live_problems(payload),
                    f"{name} survived sanitisation as a live node")

    def test_external_image_keeps_src_but_loses_handler(self):
        html = _render('<img src="https://cdn.example.com/a.png" onerror="alert(1)">')
        self.assertIn('src="https://cdn.example.com/a.png"', html)
        self.assertNotIn("onerror", html)


@unittest.skipUnless(_DEPS, "bleach/markdown not installed")
class TestPdfSanitiserPreservesReportContent(unittest.TestCase):

    def test_quoted_xss_payload_stays_readable_as_evidence(self):
        html = _render(
            "Reflected XSS:\n\n```\n<script>alert(document.domain)</script>\n```\n")
        # Escaped, so it displays verbatim in the PDF...
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("alert(document.domain)", html)
        # ...but never parses as an element.
        self.assertEqual([], _live_problems(
            "Reflected XSS:\n\n```\n<script>alert(document.domain)</script>\n```\n"))

    def test_ordinary_report_markdown_survives(self):
        html = _render(
            "# Finding\n\n"
            "Severity **critical** on `/api/v1/user`.\n\n"
            "| Host | Port |\n|------|------|\n| a.example.com | 443 |\n\n"
            "```bash\ncurl -s https://example.com\n```\n\n"
            "- item one\n\n"
            "See [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-1234).\n"
        )
        for fragment in ("<h1", "<strong", "<code", "<table", "<th", "<td",
                         "<pre", "<ul", "<li", 'href="https://nvd.nist.gov'):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, html)


if __name__ == "__main__":
    unittest.main()
