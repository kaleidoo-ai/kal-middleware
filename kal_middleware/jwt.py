from functools import wraps
from fastapi import Request, status
from fastapi.security import HTTPBearer
from starlette.responses import Response
import firebase_admin
from firebase_admin import auth
from typing import Callable, Optional, Any, Awaitable, Tuple, List
# from firebaseApi import is_token_expired, refresh_access_token
import google.auth.transport.requests
import google.oauth2.id_token
from . import get_env_var
default_app = firebase_admin.initialize_app()

HTTP_REQUEST = google.auth.transport.requests.Request()
security = HTTPBearer()

def get_allowed_accounts() -> List[str]:
    allowed_accounts = get_env_var("ALLOWED_SERVICE_ACCOUNTS", "")
    return [acc.strip() for acc in allowed_accounts.split(",")]

def firebase_jwt_authenticated(
    get_user_by_fb_uid: Callable[[str], Any],
    get_capability: Callable[[str, str], Any],
    check_access: Optional[Callable[[dict, Any], Awaitable[Tuple[bool, dict]]]] = None,
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
            objects = {}

            # verify that the user has the permission to execute the request
            user_uid = decoded_token["uid"]
            user = await get_user_by_fb_uid(user_uid)

            if not user:
                return Response(
                    status_code=status.HTTP_404_NOT_FOUND,
                    content="User not found"
                )
            capabilities = [capability.get("id") for capability in user.get("capabilities")]
            capability = await get_capability(service, action)
            access = capability and capability.get("id") in capabilities

            if not access:
                return Response(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content=f"The user cannot access {service}/{action}."
                )

            # if the request has body and there is a need to verify the user access to the elements - verify it
            if request.method in ["POST", "PUT"]:
                if check_access:
                    # Determine content type and parse accordingly
                    if request.headers.get('Content-Type') == 'application/json':
                        body = await request.json()
                    elif 'multipart/form-data' in request.headers.get('Content-Type'):
                        body = await request.form()
                        body = dict(body)
                    else:
                        return Response(
                            status_code=status.HTTP_401_UNAUTHORIZED,
                            content=f"Headers not allowed"
                        )
                    access, objects  = await check_access(user, body)
                    if not access:
                        return Response(
                            status_code=status.HTTP_403_FORBIDDEN,
                            content=f"User not permitted to perform this action. reason: {objects}",
                        )

            request.state.user = user
            for key, value in objects.items():
                setattr(request.state, key, value)

            # Process the request
            response = await func(request, *args, **kwargs)
            return response

        return decorated_function

    return decorator



# handle refresh token when the UI sends the request
# def firebase_refresh_jwt_authenticated(
#     get_full_user: Callable[[str], Any],
#     refresh_authority: List[str],
#     set_user_refresh_token: Callable[[str,str], any],
#     api_key: str,
#     get_capability: Callable[[str, str], Any],
#     check_access: Optional[Callable[[dict, Any], Awaitable[Tuple[bool, dict]]]] = None,
# ):
#     def decorator(func: Callable) -> Callable:
#         @wraps(func)
#         async def decorated_function(request: Request, *args, **kwargs):
#             # verify the token exists and validate with firebase
#             header = request.headers.get("Authorization", None)
#
#             if request.headers.get('Content-Type') == 'application/json':
#                 body = await request.json()
#             elif 'multipart/form-data' in request.headers.get('Content-Type'):
#                 body = await request.form()
#                 body = dict(body)
#             else:
#                 return Response(
#                     status_code=status.HTTP_401_UNAUTHORIZED,
#                     content=f"Headers not allowed"
#                 )
#
#             if "user_id" not in body:
#                 return Response(content={"message": "user_id required."}, status_code=status.HTTP_403_FORBIDDEN)
#
#             user_id = body.get("user_id")
#             user = await get_full_user(user_id)
#             refresh_token = user.get("refresh_token", None)
#             if not user:
#                 return Response(content={"message": "User not found."}, status_code=status.HTTP_403_FORBIDDEN)
#
#             if header:
#                 token = header.split(" ")[1]
#
#                 if(refresh_token is not None):
#                     if is_token_expired(token):
#                         token, refresh_token = refresh_access_token(refresh_token, api_key)
#                         await set_user_refresh_token(user_id, refresh_token)
#                 try:
#                     decoded_token = auth.verify_id_token(token)
#                 except Exception as e:
#                     return Response(
#                         status_code=status.HTTP_403_FORBIDDEN, content=f"Error with authentication: {e}"
#                     )
#             else:
#                 return Response(status_code=status.HTTP_401_UNAUTHORIZED, content="Error, token not found.")
#
#             # verify that the service and action exists in the config map
#             service = kwargs.get('service')
#             action = kwargs.get('action')
#             objects = {}
#
#             capabilities = [capability.get("id") for capability in user.get("capabilities")]
#             capability = await get_capability(service, action)
#             access = capability and capability.get("id") in capabilities
#
#             if not access:
#                 return Response(
#                     status_code=status.HTTP_403_FORBIDDEN,
#                     content=f"The user cannot access {service}/{action}."
#                 )
#
#             # if the request has body and there is a need to verify the user access to the elements - verify it
#             if request.method in ["POST", "PUT"]:
#                 if check_access:
#                     # Determine content type and parse accordingly
#                     access, objects  = await check_access(user, body)
#                     if not access:
#                         return Response(
#                             status_code=status.HTTP_403_FORBIDDEN,
#                             content=f"User not permitted to perform this action. reason: {objects}",
#                         )
#
#             request.state.user = user
#             for key, value in objects.items():
#                 setattr(request.state, key, value)
#
#             # Process the request
#             response = await func(request, *args, **kwargs)
#             return response
#
#         return decorated_function
#
#     return decorator



