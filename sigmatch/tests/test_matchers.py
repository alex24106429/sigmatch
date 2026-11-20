from __future__ import annotations

import pytest

from sigmatch.matchers import (
    RuleCompileError,
    compile_detection_item,
    compile_value,
    match_sigma_string,
    _base64offset_values,
)


def _field_match(field: str, pattern, modifiers=(), value=None, *, present=True):
    matcher = compile_value(field, pattern, list(modifiers))
    fields = {}
    if present and value is not None:
        fields[field.lower()] = value
    return matcher.matches(value, fields, present)


def test_equality_is_case_insensitive_and_anchored():
    assert _field_match("Image", r"C:\Windows\System32\cmd.exe", value=r"c:\windows\system32\CMD.EXE")
    assert not _field_match("Image", "cmd.exe", value=r"C:\Windows\System32\cmd.exe")
    assert not _field_match("Image", "cmd.exe", value="cmd.exe.extra")


def test_backslashes_are_literal():
    assert match_sigma_string(r"C:\Windows\System32\cmd.exe", r"C:\Windows\System32\cmd.exe")
    assert not match_sigma_string(r"C:\Windows\System32\cmd.exe", r"C:\Windows\System32\cmd.exe.old")


def test_wildcards_and_escaping():
    assert match_sigma_string(
        r"C:\Users\Public\MEGAsyncSetup32_123RC.exe",
        r"\MEGAsyncSetup32_*RC.exe",
        mode="endswith",
    )
    assert match_sigma_string("aXYZb", "a*b")
    assert match_sigma_string("a_b", "a?b")
    assert match_sigma_string("a*b", r"a\*b")
    assert not match_sigma_string("aXYZb", r"a\*b")
    assert match_sigma_string(r"a\b", r"a\\b")
    assert match_sigma_string("a?b", r"a\?b")


def test_modes():
    assert match_sigma_string("xx findstr yy", "findstr", mode="contains")
    assert match_sigma_string("findstr yy", "findstr", mode="startswith")
    assert match_sigma_string("xx findstr", "findstr", mode="endswith")
    assert not match_sigma_string("xx findstr", "findstr", mode="startswith")
    assert not match_sigma_string("xx FINDSTR", "findstr", mode="endswith", case_sensitive=True)
    assert match_sigma_string("xx FINDSTR", "findstr", mode="contains", case_sensitive=True) is False


def test_cased_modifier():
    matcher = compile_value("CommandLine", "FindStr", ["contains", "cased"])
    assert not matcher.matches("xx findstr yy", {"commandline": "xx findstr yy"}, True)
    assert matcher.matches("xx FindStr yy", {"commandline": "xx FindStr yy"}, True)


def test_list_all_and_any():
    any_matcher = compile_detection_item(
        "selection",
        {"CommandLine|contains": ["alpha", "beta"]},
    )
    assert any_matcher.matches({"commandline": "has alpha"})
    assert any_matcher.matches({"commandline": "has beta"})
    assert not any_matcher.matches({"commandline": "has gamma"})

    all_matcher = compile_detection_item(
        "selection",
        {"CommandLine|contains|all": ["alpha", "beta"]},
    )
    assert all_matcher.matches({"commandline": "alpha then beta"})
    assert not all_matcher.matches({"commandline": "alpha only"})


def test_or_list_of_mappings():
    selection = compile_detection_item(
        "selection",
        [
            {"Image|endswith": r"\cmd.exe", "CommandLine|contains": "one"},
            {"Image|endswith": r"\powershell.exe", "CommandLine|contains": "two"},
        ],
    )
    assert selection.matches({"image": r"C:\Windows\System32\cmd.exe", "commandline": "one"})
    assert selection.matches({"image": r"C:\Windows\System32\powershell.exe", "commandline": "two"})
    assert not selection.matches({"image": r"C:\Windows\System32\cmd.exe", "commandline": "two"})


def test_windash_variants():
    for dash in ("-", "/", "\u2013", "\u2014", "\u2015"):
        assert match_sigma_string(f"cmd.exe {dash}all", "cmd.exe -all", windash=True)
    assert not match_sigma_string("cmd.exe --all", "cmd.exe -all", windash=True)


def test_regex_modifier_is_case_sensitive_unless_i():
    matcher = compile_value("CommandLine", r"Invoke-Expression", ["re"])
    assert matcher.matches("x Invoke-Expression y", {"commandline": "x Invoke-Expression y"}, True)
    assert not matcher.matches("x invoke-expression y", {"commandline": "x invoke-expression y"}, True)
    insensitive = compile_value("CommandLine", r"Invoke-Expression", ["re", "i"])
    assert insensitive.matches("x invoke-expression y", {"commandline": "x invoke-expression y"}, True)


def test_cidr():
    matcher = compile_value("DestinationIp", "10.0.0.0/8", ["cidr"])
    assert matcher.matches("10.1.2.3", {"destinationip": "10.1.2.3"}, True)
    assert not matcher.matches("192.168.1.1", {"destinationip": "192.168.1.1"}, True)
    v6 = compile_value("DestinationIp", "2001:db8::/32", ["cidr"])
    assert v6.matches("2001:db8::1", {"destinationip": "2001:db8::1"}, True)
    assert not v6.matches("not-an-ip", {"destinationip": "not-an-ip"}, True)


def test_fieldref():
    matcher = compile_value("TargetFilename", "Image", ["fieldref"])
    fields = {"targetfilename": r"C:\x\a.exe", "image": r"c:\X\A.EXE"}
    assert matcher.matches(fields["targetfilename"], fields, True)
    assert not matcher.matches(fields["targetfilename"], {"targetfilename": fields["targetfilename"]}, True)


def test_exists_and_null():
    exists_true = compile_value("CommandLine", True, ["exists"])
    exists_false = compile_value("CommandLine", False, ["exists"])
    assert exists_true.matches("x", {"commandline": "x"}, True)
    assert not exists_true.matches(None, {}, False)
    assert exists_false.matches(None, {}, False)
    assert not exists_false.matches("x", {"commandline": "x"}, True)

    null = compile_value("CommandLine", None, [])
    assert null.matches(None, {}, False)
    assert null.matches("", {"commandline": ""}, True)
    assert not null.matches("x", {"commandline": "x"}, True)


def test_numeric_compare():
    matcher = compile_value("DestinationPort", 1024, ["gt"])
    assert matcher.matches("1025", {"destinationport": "1025"}, True)
    assert not matcher.matches("1024", {"destinationport": "1024"}, True)
    assert not matcher.matches("not-a-number", {"destinationport": "not-a-number"}, True)


def test_base64_value():
    matcher = compile_value("CommandLine", "IEX ([", ["base64offset", "contains"])
    for encoded in _base64offset_values("IEX (["):
        assert matcher.matches(f"x {encoded} y", {"commandline": f"x {encoded} y"}, True)
    assert not matcher.matches("nothing", {"commandline": "nothing"}, True)

    plain = compile_value("CommandLine", "IEX ([", ["base64", "contains"])
    import base64

    encoded = base64.b64encode(b"IEX ([").decode()
    assert plain.matches(f"x {encoded} y", {"commandline": f"x {encoded} y"}, True)


def test_expand_env(monkeypatch):
    monkeypatch.setenv("SIGMATCH_TEST_DIR", r"C:\SigmaTest")
    matcher = compile_value("CommandLine", r"%SIGMATCH_TEST_DIR%\x.exe", ["expand", "contains"])
    assert matcher.matches(r"cmd /c C:\SigmaTest\x.exe", {"commandline": r"cmd /c C:\SigmaTest\x.exe"}, True)


def test_keyword_selection():
    selection = compile_detection_item(
        "keywords",
        ["sekurlsa::", "mimidrv.sys", "mimikatz"],
    )
    assert selection.matches({"commandline": "x sekurlsa::logonpasswords y"})
    assert selection.matches({"targetfilename": r"C:\Windows\mimidrv.sys"})
    assert not selection.matches({"commandline": "nothing relevant"})


def test_unknown_modifier_is_rejected():
    with pytest.raises(RuleCompileError):
        compile_value("Image", "x", ["definitely-not-a-modifier"])


def test_invalid_regex_is_rejected():
    with pytest.raises(RuleCompileError):
        compile_value("Image", "(", ["re"])


def test_literal_fast_path_preserves_unicode_case_semantics():
    # re.IGNORECASE treats the long s and dotless i as case variants of ASCII
    # letters; the string fast path must fall back to regex for those values.
    contains = compile_value("Image", "s", ["contains"])
    assert contains.matches("ſ", {"image": "ſ"}, True)
    equals = compile_value("Image", "i", [])
    assert equals.matches("ı", {"image": "ı"}, True)
    assert compile_value("Image", "s", ["contains", "cased"]).matches(
        "ſ", {"image": "ſ"}, True
    ) is False
