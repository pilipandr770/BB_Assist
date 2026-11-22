from backend.services.js_endpoints import extract_js_endpoints


def test_extracts_relative_and_absolute_api_paths():
    js = '''fetch("/api/v2/users/me"); axios.get('/graphql'); const u="https://api.example.com/v1/orders";
    const s="/static/app.js"; const t=`/api/items/${id}`; const o="https://example.com/";'''
    out = extract_js_endpoints(js, "https://www.example.com/assets/main.js")
    assert "https://www.example.com/api/v2/users/me" in out
    assert "https://www.example.com/graphql" in out
    assert "https://api.example.com/v1/orders" in out
    assert not any(u.endswith(".js") for u in out)
    assert not any("${" in u for u in out)
    assert "https://example.com/" not in out


def test_bad_base_url_returns_empty():
    assert extract_js_endpoints('"/api/x"', "not-a-url") == []
