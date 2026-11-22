from __future__ import annotations

import pytest

from app.static.openapi.loader import (
    MAX_BYTES,
    LineRange,
    LoadError,
    join_pointer,
    load_document,
    unescape_pointer_token,
)

SPEC = """\
openapi: 3.0.3
paths:
  /users/{id}:
    get:
      responses:
        200:
          description: OK
on: true
"""


def test_line_ranges_start_at_key_and_end_at_last_descendant() -> None:
    loaded = load_document(SPEC)
    assert loaded.lines["/openapi"] == LineRange(1, 1)
    assert loaded.lines["/paths/~1users~1{id}/get"] == LineRange(4, 7)
    assert loaded.lines["/paths/~1users~1{id}/get/responses/200/description"] == LineRange(7, 7)


def test_keys_are_raw_strings_not_yaml11_types() -> None:
    data = load_document(SPEC).data
    assert "200" in data["paths"]["/users/{id}"]["get"]["responses"]
    assert "on" in data  # YAML 1.1 would make this key True


def test_values_keep_yaml_types() -> None:
    assert load_document("a: 1\nb: true\nc: null\n").data == {"a": 1, "b": True, "c": None}


def test_pointer_escaping_round_trip() -> None:
    assert join_pointer("", "a/b", "c~d", 0) == "/a~1b/c~0d/0"
    assert unescape_pointer_token("a~1b~0c") == "a/b~c"


def test_flow_collections_have_exact_ranges() -> None:
    loaded = load_document("x: {a: 1, b: 2}\ny: [1, 2]\n")
    assert loaded.lines["/x"] == LineRange(1, 1)
    assert loaded.lines["/y"] == LineRange(2, 2)


def test_alias_bomb_is_rejected() -> None:
    bomb = "a: &a [x, x, x, x, x, x, x, x, x, x]\n"
    prev = "a"
    for i in range(8):
        name = f"l{i}"
        bomb += f"{name}: &{name} [" + ", ".join([f"*{prev}"] * 10) + "]\n"
        prev = name
    with pytest.raises(LoadError, match="nodes"):
        load_document(bomb)


def test_deep_nesting_is_rejected() -> None:
    deep = "a: " + "[" * 100 + "]" * 100
    with pytest.raises(LoadError):
        load_document(deep)


def test_oversized_input_is_rejected() -> None:
    with pytest.raises(LoadError, match="larger"):
        load_document("a: " + "x" * (MAX_BYTES + 1))


@pytest.mark.parametrize("bad", ["", "   \n", "a: [unclosed", "? [complex, key]\n: v\n"])
def test_bad_input_raises_load_error(bad: str) -> None:
    with pytest.raises(LoadError):
        load_document(bad)


def test_unsafe_tags_are_not_constructed() -> None:
    with pytest.raises(LoadError):
        load_document("a: !!python/object/apply:os.system ['echo pwned']\n")


def test_json_with_tabs_falls_back_without_positions() -> None:
    loaded = load_document('{\n\t"openapi": "3.0.0"\n}')
    assert loaded.data == {"openapi": "3.0.0"}


def test_bom_is_ignored() -> None:
    assert load_document("﻿a: 1\n").data == {"a": 1}
