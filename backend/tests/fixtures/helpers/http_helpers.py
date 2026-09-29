"""HTTP mock helpers: deterministic, transport-level, network-free."""

from collections.abc import Callable, Mapping

import httpx

Handler = Callable[[httpx.Request], httpx.Response]


def json_response(payload: object, status_code: int = 200) -> httpx.Response:
    """Build a deterministic JSON response for mock transports."""
    return httpx.Response(status_code, json=payload)


def route_transport(routes: Mapping[str, Handler]) -> httpx.MockTransport:
    """Route requests to handlers by URL path; unknown paths get 404."""

    def handler(request: httpx.Request) -> httpx.Response:
        route = routes.get(request.url.path)
        if route is None:
            return httpx.Response(404, json={"message": "No mock route"})
        return route(request)

    return httpx.MockTransport(handler)
