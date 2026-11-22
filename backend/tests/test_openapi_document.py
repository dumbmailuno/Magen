from __future__ import annotations

import pytest

from app.static.openapi.document import OpenApiDocument, OpenApiParseError

BASE = """\
openapi: 3.0.3
info: {title: t, version: "1"}
security:
  - bearerAuth: []
paths:
  /b:
    parameters:
      - {name: q, in: query, description: path-level}
    post:
      parameters:
        - {name: q, in: query, description: op-level}
      responses: {"200": {description: ok}}
    get:
      security: []
      responses: {"200": {$ref: "#/components/responses/Ok"}}
  /a:
    $ref: "#/components/pathItems/A"
components:
  responses:
    Ok: {description: ok}
  pathItems:
    A:
      get:
        responses: {"200": {description: ok}}
  schemas:
    Loop1: {$ref: "#/components/schemas/Loop2"}
    Loop2: {$ref: "#/components/schemas/Loop1"}
"""


def doc() -> OpenApiDocument:
    return OpenApiDocument("spec.yaml", BASE)


@pytest.mark.parametrize(
    ("text", "match"),
    [
        ("swagger: '2.0'\n", "Swagger 2.0"),
        ("openapi: 2.0\n", "unsupported"),
        ("info: {}\n", "missing"),
        ("- a\n- b\n", "mapping"),
        ("a: [", "not valid"),
    ],
)
def test_rejects_non_openapi3(text: str, match: str) -> None:
    with pytest.raises(OpenApiParseError, match=match):
        OpenApiDocument("x.yaml", text)


def test_operations_sorted_and_path_item_refs_followed() -> None:
    ops = doc().operations()
    assert [o.label for o in ops] == ["GET /a", "GET /b", "POST /b"]
    assert ops[0].pointer == "/components/pathItems/A/get"


def test_effective_security_operation_overrides_root() -> None:
    d = doc()
    get_b = next(o for o in d.operations() if o.label == "GET /b")
    post_b = next(o for o in d.operations() if o.label == "POST /b")
    assert d.effective_security(get_b) == ([], "/paths/~1b/get/security")
    assert d.effective_security(post_b) == ([{"bearerAuth": []}], "/security")


def test_operation_parameters_override_path_level() -> None:
    d = doc()
    post_b = next(o for o in d.operations() if o.label == "POST /b")
    params = list(d.parameters(post_b))
    assert len(params) == 1
    assert params[0].value["description"] == "op-level"


def test_resolve_follows_refs_and_stops_on_cycles_and_external() -> None:
    d = doc()
    ok = d.resolve({"$ref": "#/components/responses/Ok"}, "/x")
    assert ok.pointer == "/components/responses/Ok"
    loop = d.resolve({"$ref": "#/components/schemas/Loop1"}, "/x")
    assert "$ref" in loop.value  # stopped, did not hang
    ext = {"$ref": "https://evil.example/x.yaml"}
    assert d.resolve(ext, "/x").value is ext


def test_location_and_excerpt() -> None:
    d = OpenApiDocument(r"dir\spec.yaml", BASE)
    loc = d.location("/paths/~1b/get/security")
    assert loc.file == "dir/spec.yaml"
    assert loc.line == 14
    assert d.excerpt("/paths/~1b/get/security").strip() == "security: []"


def test_excerpt_is_capped() -> None:
    long_spec = "openapi: 3.0.0\npaths:\n" + "".join(f"  /p{i}: {{}}\n" for i in range(20))
    ex = OpenApiDocument("s.yaml", long_spec).excerpt("/paths")
    assert ex.endswith("…")
    assert len(ex.split("\n")) == 9


def test_get_missing_pointer_is_none() -> None:
    assert doc().get("/nope/x") is None
    assert doc().get("/paths/~1b/parameters/9") is None
