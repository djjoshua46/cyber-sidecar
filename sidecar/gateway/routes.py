from fastapi import APIRouter, Request, Response
from .proxy.reverse_proxy import proxy_request
from .middleware.auth_middleware import get_identity
from .middleware.risk_middleware import evaluate_risk

router = APIRouter()

@router.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def handle_all(request: Request, full_path: str):
    identity = await get_identity(request)
    decision = await evaluate_risk(request, identity)

    if decision.action == "BLOCK":
        return Response(status_code=403, content="Access denied")

    if decision.action == "DECEIVE":
        from deception.client import route_to_deception
        return await route_to_deception(request, identity, decision)

    # Otherwise, forward to upstream app
    return await proxy_request(request, full_path, identity, decision)
