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


def build_settings(directory):
    """Write hostile settings files into `directory` and return {case name: path}."""
    good = (b'{"version": 1, "cvss_high": 7.0, "cvss_critical": 9.0, '
            b'"epss_percentile_cutoff": 0.95, "stale_days": 7}')
    cases = {
        "empty": b"",
        "truncated": good[:30],
        "wrong_types": good.replace(b"7.0", b'"7.0"').replace(b': 7}', b": true}"),
        "out_of_range": good.replace(b"7.0", b"1.0"),
        "inconsistent": good.replace(b"9.0", b"7.2"),
        "extra_keys": good[:-1] + b', "extra": 1}',
        "nan": good.replace(b"7.0", b"NaN"),
        "huge_integer": good.replace(b": 7}", b": " + b"9" * 5000 + b"}"),
        "huge_file": good + b" " * (1024 * 1024),
        "utf16": good.decode().encode("utf-16"),
        "invalid_utf8": b"\xff\xfe\xfd",
        "null_bytes": good.replace(b"7.0", b"7.0\x00"),
        "deep_nesting": b'{"version": 1, "cvss_high": ' + b"[" * 5000 + b"]" * 5000 + b"}",
        "not_an_object": b"[1, 2, 3]",
    }
    return {name: _write(directory, name + ".json", data) for name, data in cases.items()}
