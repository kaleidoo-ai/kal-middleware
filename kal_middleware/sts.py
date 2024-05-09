
from fastapi import Request, Response, status
from fastapi.security import HTTPBearer
import google.auth.transport.requests
import google.oauth2.id_token
from functools import wraps
from . import get_env_var

HTTP_REQUEST = google.auth.transport.requests.Request()
security = HTTPBearer()

def get_allowed_accounts():
    allowed_accounts = get_env_var("ALLOWED_SERVICE_ACCOUNTS", "")
    return [acc.strip() for acc in allowed_accounts.split(",")]

def sts_authenticated(func):
    @wraps(func)
    async def decorated_function(*args, **kwargs):
        allowed_accounts_list = get_allowed_accounts()

        request: Request = kwargs.get("request")
        header = request.headers.get("Authorization", None)

        if header is None:
            return Response(status_code=status.HTTP_401_UNAUTHORIZED)

        auth_type, token = header.split(" ", 1)
        if auth_type.lower() != "bearer":
            return Response(status_code=status.HTTP_401_UNAUTHORIZED)

        try:
            id_info = google.oauth2.id_token.verify_oauth2_token(token, HTTP_REQUEST)

            if id_info.get("email") not in allowed_accounts_list:
                return Response(status_code=status.HTTP_403_FORBIDDEN)

            return await func(*args, **kwargs)
        except ValueError as e:
            print(e)
            return Response(status_code=status.HTTP_403_FORBIDDEN)

    return decorated_function

