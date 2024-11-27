from fastapi import HTTPException, Request, Depends, status
from typing import Callable, Optional, Any, Awaitable, Tuple
from functools import wraps
from fastapi.security import OAuth2PasswordBearer
from keycloak import KeycloakOpenID
from .keycloakConfig import keycloak_config
from .keycloakSchemas import UserPayload
import requests
import os
import jwt

# Initially set settings and keycloak_openid to None
settings = None
keycloak_openid = None

# Set up OAuth2 (the tokenUrl can be set later when settings are initialized)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='None')


def get_settings():
    global settings
    if settings is None:
        os.environ["KEYCLOAK_CREDENTIALS"] = keycloak_config.KEYCLOAK_CREDENTIALS
        settings = keycloak_config.load_keycloak_credentials(keycloak_config.decoded_keycloak_credentials)
        # Update the tokenUrl for oauth2_scheme after settings are loaded
        oauth2_scheme.model.tokenUrl = settings.token_url
    return settings


def get_keycloak_openid():
    global keycloak_openid
    if keycloak_openid is None:
        settings = get_settings()
        keycloak_openid = KeycloakOpenID(
            server_url=settings.server_url,
            client_id=settings.client_id,
            realm_name=settings.realm,
            client_secret_key=settings.client_secret,
            verify=True
        )
    return keycloak_openid


async def get_idp_public_key():
    keycloak_openid = get_keycloak_openid()
    return (
        "-----BEGIN PUBLIC KEY-----\n"
        f"{keycloak_openid.public_key()}\n"
        "-----END PUBLIC KEY-----"
    )


async def get_payload(token: str = Depends(oauth2_scheme)) -> dict:
    try:
        key = await get_idp_public_key()
        settings = get_settings()
        audience = 'account'

        decoded_token = jwt.decode(
            token,
            key=key,
            algorithms=['RS256'],
            audience=audience,
            leeway=0  # Ensure no leeway is applied
        )
        return decoded_token
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except jwt.InvalidAudienceError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid audience: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"}
        )


async def get_user_info(token: str = Depends(oauth2_scheme)) -> UserPayload:
    try:
        payload = await get_payload(token)
        return UserPayload(
            id=payload.get("sub"),
            username=payload.get("preferred_username"),
            email=payload.get("email"),
            first_name=payload.get("given_name"),
            last_name=payload.get("family_name"),
            realm_roles=payload.get("realm_access", {}).get("roles", []),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Error getting user info: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"}
        )


def check_entitlement(token: str, resource_id: str) -> bool:
    settings = get_settings()
    token_url = f"{settings.server_url}/realms/{settings.realm}/protocol/openid-connect/token"
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': f'Bearer {token}',
    }
    data = {
        'grant_type': 'urn:ietf:params:oauth:grant-type:uma-ticket',
        'client_id': settings.client_id,
        'client_secret': settings.client_secret,
        'audience': settings.client_id,
        'permission': resource_id,
    }
    response = requests.post(token_url, data=data, headers=headers, verify=True)
    response_data = response.json()
    if response.status_code == 200 and 'access_token' in response_data:
        return True
    else:
        return False


def authenticate(
        get_user_by_uid: Callable[[str], Any],
        get_capability: Callable[[str, str, str], Any],
        check_access: Optional[Callable[[dict, Any], Awaitable[Tuple[bool, dict, any]]]] = None,
        product_check: Optional[bool] = True
):
    def decorator(func):
        @wraps(func)
        async def wrapper(request: Request, *args, **kwargs):
            token = request.headers.get("Authorization")
            if not token:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authorization token missing")
            token = token.replace("Bearer ", "")
            key_user = await get_user_info(token)
            service = kwargs.get("service")
            action = kwargs.get("action")

            # Verify that the user has the permission to execute the request
            user = await get_user_by_uid(key_user.id)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )

            if request.headers.get('Content-Type') == 'application/json':
                body = await request.json()
            elif 'multipart/form-data' in request.headers.get('Content-Type', ''):
                body = await request.form()
                body = dict(body)
            else:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Headers not allowed"
                )

            if product_check:
                product = body.get("product")
                if product is None:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail=f"Product type is missing from the body"
                    )
            else:
                product = "kalsense"

            capability = await get_capability(service, action, product)
            capabilities = [capability.get("id") for capability in user.get("capabilities").get(product, [])]
            access = capability and (capability.get("id") in capabilities)

            if not access:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"The user cannot access {service}/{action} in {product}."
                )

            # If the request has a body and there is a need to verify the user's access to the elements - verify it
            if request.method in ["POST", "PUT"]:
                if check_access:
                    access, objects, status_code = await check_access(user, body)
                    if not access:
                        if status_code:
                            raise HTTPException(
                                status_code=status_code,
                                detail=f"User not permitted to perform this action. Reason: {objects}",
                            )
                        else:
                            raise HTTPException(
                                status_code=status.HTTP_403_FORBIDDEN,
                                detail=f"User not permitted to perform this action. Reason: {objects}",
                            )

            request.state.user = user
            for key, value in objects.items():
                setattr(request.state, key, value)

            # Call the original function if authorization is successful
            return await func(request, *args, **kwargs)

        return wrapper
    return decorator
