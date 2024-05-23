from functools import wraps
from fastapi import Request, status
from starlette.responses import Response
import firebase_admin
from firebase_admin import auth
from typing import Callable, Optional, Any, Awaitable

default_app = firebase_admin.initialize_app()

def firebase_jwt_authenticated(
    get_user_capabilities: Callable[[str], Any],
    check_access: Optional[Callable[[str, Any, list], Awaitable[bool, str]]] = None,
):
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def decorated_function(request: Request, *args, **kwargs):
            # verify the token exists and validate with firebase
            header = request.headers.get("Authorization", None)
            if header:
                token = header.split(" ")[1]
                try:
                    decoded_token = auth.verify_id_token(token)
                except Exception as e:
                    return Response(
                        status_code=status.HTTP_403_FORBIDDEN, content=f"Error with authentication: {e}"
                    )
            else:
                return Response(status_code=status.HTTP_401_UNAUTHORIZED, content="Error, token not found.")

            # verify that the service and action exists in the config map
            service = kwargs.get('service')
            action = kwargs.get('action')
            user_id = None

            # verify that the user has the permission to execute the request
            user_uid = decoded_token["uid"]
            user_capabilities = await get_user_capabilities(user_uid)
            access = any(
                capability["service"] == service and capability["action"] == action for capability in user_capabilities
            )

            if not access:
                return Response(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content=f"The user cannot access {service}/{action}."
                )

            # if the request has body and there is a need to verify the user access to the elements - verify it
            if request.method in ["POST", "PUT"]:
                if check_access:
                    body = await request.json()
                    access, user_id = await check_access(user_uid, body, user_capabilities)
                    if not access:
                        return Response(
                            status_code=status.HTTP_403_FORBIDDEN,
                            content="User not permitted to perform this action.",
                        )

            request.state.uid = user_uid  # Attach the Firebase id to the request state for later use.
            if user_id:
                request.state.user_id = user_id
            request.state.user_capabilities = user_capabilities

            # Process the request
            response = await func(request, *args, **kwargs)
            return response

        return decorated_function

    return decorator



