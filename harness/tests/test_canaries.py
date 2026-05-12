"""Tests for the HTTP canary server."""

from __future__ import annotations

import aiohttp
import pytest

from harness.canaries import CanaryServer


@pytest.mark.asyncio
async def test_allocate_unique_tokens_and_urls():
    srv = CanaryServer()
    await srv.start()
    try:
        c1 = srv.allocate("first")
        c2 = srv.allocate("second")
        assert c1.token != c2.token
        assert c1.url != c2.url
        assert c1.url.startswith(f"http://{srv.host}:{srv.port}/")
    finally:
        await srv.stop()


@pytest.mark.asyncio
async def test_records_hit_with_method_path_query():
    srv = CanaryServer()
    await srv.start()
    try:
        c = srv.allocate("hit_test")
        async with aiohttp.ClientSession() as session:
            async with session.get(c.url + "/probe?x=1") as resp:
                assert resp.status == 204
        assert len(c.hits) == 1
        hit = c.hits[0]
        assert hit.method == "GET"
        assert "probe" in hit.path
        assert hit.query == "x=1"
    finally:
        await srv.stop()


@pytest.mark.asyncio
async def test_records_body_on_post():
    srv = CanaryServer()
    await srv.start()
    try:
        c = srv.allocate("post_test")
        async with aiohttp.ClientSession() as session:
            async with session.post(c.url, data=b"secret=value") as resp:
                assert resp.status == 204
        assert len(c.hits) == 1
        assert c.hits[0].method == "POST"
        assert c.hits[0].body == b"secret=value"
    finally:
        await srv.stop()


@pytest.mark.asyncio
async def test_unknown_token_returns_404():
    srv = CanaryServer()
    await srv.start()
    try:
        async with aiohttp.ClientSession() as session:
            url = f"http://{srv.host}:{srv.port}/this-is-not-a-real-token"
            async with session.get(url) as resp:
                assert resp.status == 404
    finally:
        await srv.stop()


@pytest.mark.asyncio
async def test_by_id_lookup():
    srv = CanaryServer()
    await srv.start()
    try:
        c = srv.allocate("lookup_test")
        assert srv.by_id("lookup_test") is c
        assert srv.by_id("does_not_exist") is None
    finally:
        await srv.stop()
