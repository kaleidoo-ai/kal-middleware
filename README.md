# kal-middleware


[![image](https://img.shields.io/pypi/v/kal-middleware.svg)](https://pypi.python.org/pypi/kal-middleware)

`kal-middleware` is a Python package designed for FastAPI applications to provide robust JWT and Service-to-Service (STS) authentication using Firebase and Google Identity Platform.

## Features

- **JWT Authentication**: Ensures that the JWTs are valid and checks user roles against provided configurations.
- **STS Authentication**: Validates tokens for service-to-service communication ensuring that only verified services can communicate.

## Installation

Install `kal-middleware` using pip:

```bash
pip install kal-middleware
```

# Usage

## JWT Authentication

To add JWT authentication to your FastAPI endpoints, you can use the `jwt_authenticated` decorator provided by `kal-middleware`. This decorator checks if the JWT token in the `Authorization` header is valid and whether the user has the appropriate role based on a configuration map.

Here's an example of how to apply the `firebase_jwt_authenticated` decorator:

**Notice:** After the JWT is processed, the `request.state` holds:
1. `user_uid` - The Firebase unique ID.
2. `user_capabilities` - A list of capabilities for later use in the request processing, if needed.
3. `user` - If `check_access` is used, the user object will be attached to the request, so the entire process does not need to call the request again.

```python
from kal_middleware.jwt import firebase_jwt_authenticated
from typing import List
from utils import get_org, get_user_by_fb_uid, get_capability_by_service_action

async def get_user(firebase_uid):
    user = await get_user_by_fb_uid(firebase_uid)
    return user

# if there is specific variable in the body that needed checks of who access its data only
async def check_access(user: dict, body: dict):
    # check in the db the user and his parameters
    # for example:
    capabilities = user.get("capabilities")
    if "capability_id" in body:
        access =  any(capability for capability in capabilities if capability.get("id") == body["capability_id"] )
        if not access:
            return False, f"User can't access the request."
    if "org_id" in body:
        org = get_org(body["org_id"])
        if not org:
            return False, f"Org not found"
        return True, {"org": org}
    return False, f"User {user.get('id')} from another organization then the one that was requested."


async def get_capability(service, action):
    capability = await get_capability_by_service_action(service, action)
    return capability

@app.get("/your-route/<service>/<action>")
@firebase_jwt_authenticated(get_user, check_access)
async def your_route_function(
        request: Request = None,
        service: Union[str, None] = None,
        action: Union[str, None] = None
):
    # Your route logic
    return {"message": "This is a protected route"}

# Or - if there is no need to check for specific data in the body
@app.get("/your-route-without-check-access/<service>/<action>")
@firebase_jwt_authenticated(get_user)
async def your_route_function_without_check_access(
        request: Request = None,
        service: Union[str, None] = None,
        action: Union[str, None] = None
):
    # Your route logic
    return {"message": "This is a protected route"}
```

## STS Authentication
For service-to-service (STS) authentication using Google's Identity Platform, you can use the `sts_authenticated` decorator. This ensures that the calling service's token is verified to enable secure interactions between services.

Here's how to use the `sts_authenticated` decorator in your FastAPI app:
- Make sure first you have env variable named `ALLOWED_SERVICE_ACCOUNTS` with the following structure: `example1@gserviceaccount.com, example2@gserviceaccount.com`
```python
from kal_middleware.sts import sts_authenticated

@app.get("/secure-service")
@sts_authenticated
async def secure_service_function():
    # Logic that requires service-to-service authentication
    return {"message": "Service-to-service call is authenticated"}
```
This configuration will parse and verify the Authorization header, ensuring that only requests with a verified bearer token can access the endpoint.

