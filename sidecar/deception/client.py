from fastapi import Request, Response
import httpx

DECEPTION_BASE_URL = "http://deception:8000"

async def route_to_deception(request: Request, identity, decision):
    async with httpx.AsyncClient() as client:
        upstream_url = f"{DECEPTION_BASE_URL}{request.url.path}"
        resp = await client.request(
            request.method,
            upstream_url,
            headers=request.headers,
            content=await request.body()
        )
        return Response(
            content=resp.content,
            status_code=resp.status_code,
            headers=resp.headers
        )
