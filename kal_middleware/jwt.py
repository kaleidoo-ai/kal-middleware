from typing import Callable
from functools import wraps
from fastapi import Request
from starlette.responses import Response
import firebase_admin
from firebase_admin import auth

default_app = firebase_admin.initialize_app()

def jwt_authenticated(
    get_user_role_function,
    config_map,
    check_id_access=None,
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
                        status_code=403, content=f"Error with authentication: {e}"
                    )
            else:
                return Response(status_code=401, content="Error, token not found.")

            # verify that the service and action exists in the config map
            service = request.path_params.get("service")
            action = request.path_params.get("action")
            if service not in config_map:
                return Response(
                    status_code=404, content=f"Service {service} not found."
                )
            if action not in config_map[service]:
                return Response(
                    status_code=404,
                    content=f"Action {action} not found in service {service}.",
                )

            # verify that the user has the permission to execute the request
            user_uid = decoded_token["uid"]
            permissions = config_map[service][action]["permissions"]
            user_role = await get_user_role_function(user_uid)

            if user_role not in permissions:
                return Response(
                    status_code=403,
                    content=f"User not permitted to call {service}/{action}.",
                )

            # if the request has body and there is a need to verify the user access to the elements - verify it
            if request.method in ["POST", "PUT"]:
                if check_id_access:
                    body = await request.json()
                    if not check_id_access(user_uid, body):
                        return Response(
                            status_code=403,
                            content="User not permitted to perform this action.",
                        )

            request.state.uid = user_uid  # Attach the Firebase id to the request state for later use.

            # Process the request
            response = await func(request, *args, **kwargs)
            return response

        return decorated_function

    return decorator
