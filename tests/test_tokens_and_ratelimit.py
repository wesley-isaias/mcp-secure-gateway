import json

import pytest

from mcp_secure_gateway.ratelimit import RateLimiter
from mcp_secure_gateway.tokens import (
    HashedTokenVerifier,
    TokenFileError,
    generate_token,
    hash_token,
    load_token_file,
)

from .conftest import TESTER_TOKEN, VIEWER_TOKEN


async def test_valid_token_maps_to_client_and_role(token_file):
    verifier = HashedTokenVerifier.from_file(token_file)
    access = await verifier.verify_token(TESTER_TOKEN)
    assert access.client_id == "ci-bot"
    assert access.claims["role"] == "tester"


@pytest.mark.parametrize("token", ["", "wrong", VIEWER_TOKEN + "x", hash_token(VIEWER_TOKEN)])
async def test_invalid_tokens_are_rejected(token_file, token):
    verifier = HashedTokenVerifier.from_file(token_file)
    assert await verifier.verify_token(token) is None


def test_token_file_never_contains_plaintext(token_file):
    content = token_file.read_text()
    assert VIEWER_TOKEN not in content and TESTER_TOKEN not in content


@pytest.mark.parametrize(
    "content",
    [
        {},
        {"plaintext-token": {"client_id": "a", "role": "viewer"}},
        {hash_token("t"): {"client_id": "a", "role": "admin"}},
        {hash_token("t"): {"client_id": "a b", "role": "viewer"}},
        {hash_token("t"): {"client_id": "a", "role": "viewer", "extra": 1}},
    ],
)
def test_bad_token_files_fail_at_startup(tmp_path, content):
    path = tmp_path / "tokens.json"
    path.write_text(json.dumps(content))
    with pytest.raises(TokenFileError):
        load_token_file(path)


def test_generated_tokens_are_long_and_unique():
    tokens = {generate_token() for _ in range(50)}
    assert len(tokens) == 50 and all(len(t) >= 40 for t in tokens)


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def test_burst_then_refill():
    clock = FakeClock()
    limiter = RateLimiter(per_second=2, burst=3, clock=clock)
    assert [limiter.allow("a") for _ in range(4)] == [True, True, True, False]
    clock.now += 0.5
    assert limiter.allow("a") is True
    assert limiter.allow("a") is False


def test_clients_have_separate_buckets():
    limiter = RateLimiter(per_second=1, burst=1, clock=FakeClock())
    assert limiter.allow("a") and limiter.allow("b")
    assert not limiter.allow("a")


def test_tracked_clients_are_bounded():
    clock = FakeClock()
    limiter = RateLimiter(per_second=1, burst=1, clock=clock, max_clients=3)
    for i in range(10):
        clock.now += 1
        limiter.allow(f"c{i}")
    assert len(limiter._buckets) == 3
