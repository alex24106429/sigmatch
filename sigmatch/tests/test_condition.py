from __future__ import annotations

import pytest

from sigmatch.condition import compile_condition
from sigmatch.matchers import RuleCompileError


class Static:
    def __init__(self, result: bool) -> None:
        self.result = result

    def matches(self, fields) -> bool:
        return self.result


class Counting:
    def __init__(self, name: str, calls: list[str]) -> None:
        self.name = name
        self.calls = calls

    def matches(self, fields) -> bool:
        self.calls.append(self.name)
        return True


def _eval(condition, values):
    selections = {name: Static(value) for name, value in values.items()}
    return compile_condition(condition, list(values)).evaluate({}, selections, {})


def test_and_or_not_precedence():
    # and binds tighter than or
    assert _eval("a or b and c", {"a": True, "b": False, "c": False}) is True
    assert _eval("a or b and c", {"a": False, "b": True, "c": False}) is False
    assert _eval("(a or b) and c", {"a": True, "b": False, "c": False}) is False
    assert _eval("a and not b", {"a": True, "b": False}) is True
    assert _eval("a and not b", {"a": True, "b": True}) is False


def test_of_patterns():
    values = {"selection_a": True, "selection_b": False, "filter_x": False, "filter_y": True}
    assert _eval("1 of selection_*", values) is True
    assert _eval("all of selection_*", values) is False
    assert _eval("any of selection_*", values) is True
    assert _eval("1 of filter_*", values) is True
    assert _eval("all of filter_*", values) is False
    assert _eval("1 of them", values) is True
    assert _eval("all of them", values) is False
    assert _eval("all of selection_*", {"selection_a": True, "selection_b": True}) is True
    # The threshold must be based on names matching the pattern, not on all
    # detection items (filters are present and all false).
    assert (
        _eval(
            "all of selection_*",
            {"selection_a": True, "selection_b": True, "filter_x": False},
        )
        is True
    )


def test_not_of():
    values = {"selection": True, "filter_main_1": False, "filter_main_2": False}
    assert _eval("selection and not 1 of filter_main_*", values) is True
    assert _eval("selection and not 1 of filter_main_*", {**values, "filter_main_1": True}) is False


def test_complex_parentheses():
    values = {
        "selection_img": True,
        "selection_group_a": True,
        "selection_group_b": True,
        "filter_group_add": False,
        "selection_accounts_a": True,
        "selection_accounts_b": False,
    }
    condition = (
        "selection_img and ((all of selection_group_* and not filter_group_add) "
        "or all of selection_accounts_*)"
    )
    assert _eval(condition, values) is True
    assert _eval(condition, {**values, "selection_group_b": False, "selection_accounts_b": True}) is True
    assert _eval(condition, {**values, "selection_group_b": False, "selection_accounts_b": False}) is False


def test_numeric_of_threshold():
    values = {"selection_a": True, "selection_b": True, "selection_c": False}
    assert _eval("2 of selection_*", values) is True
    assert _eval("3 of selection_*", values) is False


def test_condition_list_is_or():
    node = compile_condition(["selection_a", "selection_b"], ["selection_a", "selection_b"])
    assert node.evaluate({}, {"selection_a": Static(False), "selection_b": Static(True)}, {})
    assert not node.evaluate({}, {"selection_a": Static(False), "selection_b": Static(False)}, {})


def test_cache_avoids_repeated_evaluation():
    calls: list[str] = []
    selections = {"a": Counting("a", calls), "b": Counting("b", calls)}
    node = compile_condition("(a and b) or (a and b)", ["a", "b"])
    assert node.evaluate({}, selections, {})
    assert calls == ["a", "b"]


def test_unknown_selection_is_an_error():
    with pytest.raises(RuleCompileError):
        compile_condition("selection and missing", ["selection"])


def test_pattern_without_matches_is_an_error():
    with pytest.raises(RuleCompileError):
        compile_condition("1 of filter_*", ["selection"])


def test_aggregation_is_explicitly_rejected():
    with pytest.raises(RuleCompileError):
        compile_condition("selection | count() > 5", ["selection"])


def test_malformed_conditions_are_rejected():
    for condition in ("", "selection and", "(selection", "selection)", "1 selection", "of selection"):
        with pytest.raises(RuleCompileError):
            compile_condition(condition, ["selection"])
