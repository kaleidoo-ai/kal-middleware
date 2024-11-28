import json
from functools import wraps
from fastapi import Request, WebSocket, status
from fastapi.security import HTTPBearer
from starlette.responses import Response
import firebase_admin
from firebase_admin import auth
from typing import Callable, Optional, Any, Awaitable, Tuple, List
import os
from jose import jwt
from jose.exceptions import JWTError
import requests
import google.auth.transport.requests
import google.oauth2.id_token
from . import get_env_var
default_app = firebase_admin.initialize_app()

HTTP_REQUEST = google.auth.transport.requests.Request()
security = HTTPBearer()

def get_allowed_accounts() -> List[str]:
    allowed_accounts = get_env_var("ALLOWED_SERVICE_ACCOUNTS", "")
    return [acc.strip() for acc in allowed_accounts.split(",")]


def decode_firebase_token(token):
    try:
        decoded_token = auth.verify_id_token(token)
        return decoded_token, decoded_token['uid'], None
    except Exception as e:
        return None, None, str(e)


def decode_keycloak_token(token):
    try:
        # Get Keycloak configuration from environment variables
        keycloak_url = os.getenv('KEYCLOAK_URL')
        realm_name = os.getenv('KEYCLOAK_REALM')
        client_id = os.getenv('KEYCLOAK_CLIENT_ID')

        if not all([keycloak_url, realm_name, client_id]):
            raise ValueError("Keycloak configuration is incomplete. Please check your environment variables.")

        # Construct the full URL for the Keycloak server's public key
        key_url = f"{keycloak_url}/realms/{realm_name}/protocol/openid-connect/certs"

        # Fetch the public key
        response = requests.get(key_url)
        response.raise_for_status()
        keys = response.json()['keys']
        key_id = jwt.get_unverified_header(token)['kid']
        public_key = next((key for key in keys if key['kid'] == key_id), None)

        if not public_key:
            raise ValueError("Matching public key not found")

        # Decode and verify the token
        options = {
            'verify_signature': True,
            'verify_aud': True,
            'verify_exp': True
        }
        decoded_token = jwt.decode(token, public_key, algorithms=['RS256'], options=options, audience=client_id)
        return decoded_token, decoded_token['sub'], None
    except JWTError as e:
        return None, None, f"JWT decode error: {str(e)}"
    except requests.RequestException as e:
        return None, None, f"Failed to fetch public key: {str(e)}"
    except ValueError as e:
        return None, None, str(e)
    except Exception as e:
        return None, None, f"Unexpected error: {str(e)}"


def firebase_jwt_authenticated(
    get_user_by_fb_uid: Callable[[str], Any],
    get_capability: Callable[[str, str], Any],
    check_access: Optional[Callable[[dict, Any], Awaitable[Tuple[bool, dict, any]]]] = None,
):
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def decorated_function(request: Request, *args, **kwargs):

            if request.headers is None:
                return Response(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content="Headers required"
                )

            if request.headers.get('Content-Type') is None:
                return Response(
                    status_code=status.HTTP_403_UNAUTHORIZED,
                    content=f"Content-Type header required"
                )

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
                    access, objects, status_code  = await check_access(user, body)
                    if not access:
                        if status_code:
                            return Response(
                                status_code=status_code,
                                content=f"User not permitted to perform this action. Reason: {objects}",
                            )
                        else:
                            return Response(
                                status_code=status.HTTP_403_FORBIDDEN,
                                content=f"User not permitted to perform this action. Reason: {objects}",
                            )

            request.state.user = user
            for key, value in objects.items():
                setattr(request.state, key, value)

            # Process the request
            response = await func(request, *args, **kwargs)
            return response

        return decorated_function

    return decorator


provider_function = {
    "firebase": decode_firebase_token,
    "keycloak": decode_keycloak_token
}

def authenticate(
    get_user_by_uid: Callable[[str], Any],
    get_capability: Callable[[str, str, str], Any],
    check_access: Optional[Callable[[dict, Any], Awaitable[Tuple[bool, dict, any]]]] = None,
    product_check: Optional[bool] = True
):
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def decorated_function(request: Request, *args, **kwargs):
            # Determine which provider to use
            provider = os.getenv('PROVIDER', 'firebase').lower()

            if request.headers is None:
                return Response(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content="Headers required"
                )

            if request.headers.get('Content-Type') is None:
                return Response(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content=f"Content-Type header required"
                )

            # verify the token exists and validate with the appropriate provider
            header = request.headers.get("Authorization", None)
            if header:
                token = header.split(" ")[1]
                try:
                    if provider in provider_function.keys():
                        decoded_token, user_uid, error = provider_function[provider](token)
                        if error is not None:
                            return Response(
                                status_code=status.HTTP_403_FORBIDDEN,
                                content=f"Error with authentication: {error}"
                            )
                    else:
                        return Response(
                            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            content=f"Invalid authentication provider configured: {provider}"
                        )
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
            user = await get_user_by_uid(user_uid)

            if not user:
                return Response(
                    status_code=status.HTTP_404_NOT_FOUND,
                    content="User not found"
                )

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

            if product_check:
                product = body.get("product")
                if product is None:
                    return Response(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        content=f"Product type is missing from the body"
                    )
            else:
                product = "kalsense"

            capability = await get_capability(service, action, product)
            capabilities = [capability.get("id") for capability in user.get("capabilities").get(product, [])]
            access = capability and (capability.get("id") in capabilities)

            if not access:
                return Response(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content=f"The user cannot access {service}/{action} in {product}."
                )

            # if the request has body and there is a need to verify the user access to the elements - verify it
            if request.method in ["POST", "PUT"]:
                if check_access:
                    access, objects, status_code = await check_access(user, body)
                    if not access:
                        if status_code:
                            return Response(
                                status_code=status_code,
                                content=f"User not permitted to perform this action. Reason: {objects}",
                            )
                        else:
                            return Response(
                                status_code=status.HTTP_403_FORBIDDEN,
                                content=f"User not permitted to perform this action. Reason: {objects}",
                            )

            request.state.user = user
            for key, value in objects.items():
                setattr(request.state, key, value)

            # Process the request
            response = await func(request, *args, **kwargs)
            return response

        return decorated_function

    return decorator


def websocket_authenticate(
        get_user_by_uid: Callable[[str], Any],
        get_capability: Callable[[str, str, str], Any],
        check_access: Optional[Callable[[dict, Any], Awaitable[Tuple[bool, dict, any]]]] = None,
        product_check: Optional[bool] = True
):
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def decorated_function(websocket: WebSocket, *args, **kwargs):
            # Receive the initial message from the WebSocket (which contains the token)
            try:
                await websocket.accept()
                message = await websocket.receive_text()
                message_data = json.loads(message)
                token = message_data.get("token")  # Extract the token from the message

                if not token:
                    await websocket.send_json({
                        "status_code": status.HTTP_401_UNAUTHORIZED,
                        "message": "Token not provided."
                    })
                    await websocket.close()
                    return

                # Determine the provider and authenticate the token
                provider = os.getenv('PROVIDER', 'firebase').lower()

                if provider in provider_function.keys():
                    decoded_token, user_uid, error = provider_function[provider](token)
                    if error:
                        await websocket.send_json({
                            "status_code": status.HTTP_403_FORBIDDEN,
                            "message": f"Error with authentication: {error}",
                        })
                        await websocket.close()
                        return
                else:
                    await websocket.send_json({
                        "status_code": status.HTTP_500_INTERNAL_SERVER_ERROR,
                        "message": f"Invalid authentication provider configured: {provider}",
                    })
                    await websocket.close()
                    return

                # Fetch user data based on the UID
                user = await get_user_by_uid(user_uid)
                if not user:
                    await websocket.send_json({
                        "status_code": status.HTTP_404_NOT_FOUND,
                        "message": "User not found.",
                    })
                    await websocket.close()
                    return

                # Save authenticated user to WebSocket state
                websocket.state.user = user

                # Optional product check based on the body of the message
                product = message_data.get("product", "kalsense" if not product_check else None)
                if product_check and not product:
                    await websocket.send_json({
                        "status_code": status.HTTP_401_UNAUTHORIZED,
                        "message": "Product type is missing.",
                    })
                    await websocket.close()
                    return

                # Verify capability
                service = kwargs.get('service')
                action = kwargs.get('action')
                capability = await get_capability(service, action, product)
                user_capabilities = [
                    cap.get("id") for cap in user.get("capabilities").get(product, [])
                ]
                access = capability and (capability.get("id") in user_capabilities)

                if not access:
                    await websocket.send_json({
                        "status_code": status.HTTP_403_FORBIDDEN,
                        "message": f"User cannot access {service}/{action} in {product}.",
                    })
                    await websocket.close()
                    return

                message = await websocket.receive_text()
                message_data = json.loads(message)
                websocket.state.body = message_data
                # Optional: Additional access checks using check_access callback
                if check_access:
                    access, objects, status_code = await check_access(user, message_data)
                    if not access:
                        if status_code:
                            return Response(
                                status_code=status_code,
                                content=f"User not permitted to perform this action. Reason: {objects}",
                            )
                        else:
                            return Response(
                                status_code=status.HTTP_403_FORBIDDEN,
                                content=f"User not permitted to perform this action. Reason: {objects}",
                            )

                    # Attach additional data to websocket state
                    for key, value in objects.items():
                        setattr(websocket.state, key, value)

                # Proceed with the WebSocket handler function
                return await func(websocket, *args, **kwargs)

            except Exception as e:
                await websocket.send_json({
                    "status_code": status.HTTP_500_INTERNAL_SERVER_ERROR,
                    "message": f"Error processing WebSocket request: {str(e)}",
                })
                await websocket.close()

        return decorated_function

    return decorator

