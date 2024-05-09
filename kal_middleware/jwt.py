from functools import wraps
from fastapi import Request, status
from starlette.responses import Response
import firebase_admin
from firebase_admin import auth
from typing import Callable, Optional, Dict, Any, List, Union

default_app = firebase_admin.initialize_app()

def jwt_authenticated(
    get_user_role_function: Callable[[str], Any],
    config_map: Dict[str, Dict[str, Union[str, Dict[str, Dict[str, List[str]]]]]],
    check_access: Optional[Callable[[str, Any], bool]] = None,
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
            if service not in config_map:
                return Response(
                    status_code=status.HTTP_404_NOT_FOUND, content=f"Service {service} not found."
                )
            if action not in config_map[service]["actions"]:
                return Response(
                    status_code=status.HTTP_404_NOT_FOUND,
                    content=f"Action {action} not found in service {service}.",
                )

            # verify that the user has the permission to execute the request
            user_uid = decoded_token["uid"]
            permissions = config_map[service]["actions"][action]["permissions"]
            user_role = await get_user_role_function(user_uid)

            if not user_role:
                return Response(
                    status_code=status.HTTP_404_NOT_FOUND,
                    content=f"User not exist.",
                )

            if user_role not in permissions:
                return Response(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content=f"User not permitted to call {service}/{action}.",
                )

            # if the request has body and there is a need to verify the user access to the elements - verify it
            if request.method in ["POST", "PUT"]:
                if check_access:
                    body = await request.json()
                    if not check_access(user_uid, body):
                        return Response(
                            status_code=status.HTTP_403_FORBIDDEN,
                            content="User not permitted to perform this action.",
                        )

            request.state.uid = user_uid  # Attach the Firebase id to the request state for later use.

            # Process the request
            response = await func(request, *args, **kwargs)
            return response

        return decorated_function

    return decorator
