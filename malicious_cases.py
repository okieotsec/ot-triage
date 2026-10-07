"""Generate hostile batch CSV files for security testing."""
import os

HEADER = b"id,name,cvss,threat,asset,exposure,patch,controls\n"
GOOD_ROW = b"X-1,Example,9.8,active,crown,high,available,none\n"


def _write(directory, name, data):
    path = os.path.join(directory, name)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def build(directory):
    """Write every hostile file into `directory` and return {case name: path}."""
    cases = {}

    def add(name, data):
        cases[name] = _write(directory, name + ".csv", data)

    add("empty", b"")
    add("header_only", HEADER)
    add("many_rows", HEADER + GOOD_ROW * 1_000_000)
    add("one_huge_line", b"id,name,cvss,threat,asset,exposure\n" + b"A" * (50 * 1024 * 1024))
    add("long_field", HEADER + b"X-1," + b"A" * 200_000 + b",9.8,active,crown,high,available,none\n")
    add("utf16", (HEADER + GOOD_ROW).decode().encode("utf-16"))
    add("latin1", HEADER + b"X-1,Caf\xe9 server,9.8,active,crown,high,available,none\n")
    add("bom_utf8", b"\xef\xbb\xbf" + HEADER + GOOD_ROW)
    add("null_bytes", HEADER + b"X-1,na\x00me,9.8,active,crown,high,available,none\n")
    add("unterminated_quote", HEADER + b'X-1,"never closed,9.8,active,crown,high,available,none\n')
    payloads = [b'=HYPERLINK("http://example.invalid","x")', b"+cmd|' /C calc'!A0", b"-2+3", b"@SUM(1+1)",
                b"\t=1+1", b"\r=1+1"]
    rows = b"".join(b'"' + p.replace(b'"', b'""') + b'","' + p.replace(b'"', b'""')
                    + b'",9.8,active,crown,high,available,none\n' for p in payloads)
    add("formula_payloads", HEADER + rows)
    add("missing_column", b"id,cvss,threat,asset\nX-1,9.8,active,crown\n")
    add("extra_columns", HEADER.rstrip() + b",extra1,extra2\n" + GOOD_ROW.rstrip() + b",a,b\n")
    add("duplicate_column", b"cvss,cvss,threat,asset,exposure\n1.0,9.8,active,crown,high\n")
    add("reordered_columns", b"exposure,asset,threat,cvss\nhigh,crown,active,9.8\n")
    for label, value in (("nan", "nan"), ("inf", "inf"), ("negative", "-1"), ("over_ten", "10.1"),
                         ("huge", "1e308"), ("blank", ""), ("text", "high")):
        add("cvss_" + label, HEADER + f"X-1,Example,{value},active,crown,high,available,none\n".encode())
    return cases
