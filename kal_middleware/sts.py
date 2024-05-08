from typing import Callable
from functools import wraps
from fastapi import Request
from starlette.responses import Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from google.auth.transport import requests
from google.oauth2 import id_token

security = HTTPBearer()

def sts_authenticated(func: Callable) -> Callable:
    """Use the service to service authentication to parse Authorization header to verify the
    The server extracts the Identity Platform uid for that user.
    """
    @wraps(func)
    async def decorated_function(*args, **kwargs):
        credentials: HTTPAuthorizationCredentials = await security(kwargs.get("request"))
        scheme, token = credentials.credentials.split()
        if scheme.lower() != "bearer":
            return Response(status_code=401, content="Invalid authentication scheme.")
        try:
            claims = await id_token.verify_token(token, requests.Request())
            if not claims.get("email_verified", False):
                return Response(status_code=401, content="Email not verified.")
            else:
                # can add more logic to validate the service
                return await func(*args, **kwargs)
        except Exception as e:
            return Response(status_code=403, content=f"Error with authentication: {e}")
    return decorated_function
