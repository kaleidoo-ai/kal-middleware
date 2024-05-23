# kal-middleware


[![image](https://img.shields.io/pypi/v/kal-middleware.svg)](https://pypi.python.org/pypi/kal-middleware)

`kal-middleware` is a Python package designed for FastAPI applications to provide robust JWT and Service-to-Service (STS) authentication using Firebase and Google Identity Platform.

## Features

- **JWT Authentication**: Ensures that the JWTs are valid and checks user roles against provided configurations.
- **STS Authentication**: Validates tokens for service-to-service communication ensuring that only verified services can communicate.

## Installation

Install `kal-middleware` using pip:

```bash
pip install kal_middleware
```

# Usage

## JWT Authentication

To add JWT authentication to your FastAPI endpoints, you can use the `jwt_authenticated` decorator provided by `kal-middleware`. This decorator checks if the JWT token in the `Authorization` header is valid and whether the user has the appropriate role based on a configuration map.

Here's an example of how to apply the `jwt_authenticated` decorator:

```python
from kal_middleware.jwt import firebase_jwt_authenticated
from typing import List

# Define a function to retrieve the user's role based on their user ID
def get_user_capabilities(user_id: str):
    # Implement your logic to retrieve the user's capabilities
    # If the user not found, return "".

    # Example - the user can access the get action in example service only.
    example_capabilities = [{
        "service": "example_service",
        "action": "get"
    }]
    return example_capabilities

# if there is specific variable in the body that needed checks of who access its data only
def check_access(firebase_uid: str, body: dict, user_capabilities_list: List):
    # check in the db the user and his parameters
    # for example if in the db the user with that exactly firebase_uid is:
    user = {
        "user_id": "333444",
        "firebase_uid": "12345",
        "org_id": "12345"
    }
    if body["org_id"] == user["org_id"]:
        return True, user
    return False, None

@app.get("/your-route/<service>/<action>")
@firebase_jwt_authenticated(get_user_capabilities, check_access)
async def your_route_function(
        request: Request = None,
        service: Union[str, None] = None,
        action: Union[str, None] = None
):
    # Your route logic
    return {"message": "This is a protected route"}

# Or - if there is no need to check for specific data in the body
@app.get("/your-route-without-check-access/<service>/<action>")
@firebase_jwt_authenticated(get_user_capabilities)
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

