from collections.abc import Mapping


def authorization_headers(
    token: str | None,
    headers: Mapping[str, str] | None = None,
) -> dict[str, str]:
    result = dict(headers or {})
    if token:
        result["Authorization"] = f"Bearer {token}"
    else:
        result.pop("Authorization", None)
    return result
