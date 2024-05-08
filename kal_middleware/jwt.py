from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
import firebase_admin
from firebase_admin import auth
default_app = firebase_admin.initialize_app()

class JwtMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, get_user_role_function, config_map, check_id_access=None):
        super().__init__(app)
        self.user_role_function = get_user_role_function
        self.config_map = config_map
        self.check_id_access = check_id_access

    async def dispatch(self, request: Request, call_next):
        header = request.headers.get("Authorization", None)
        if header:
            token = header.split(" ")[1]
            try:
                decoded_token = firebase_admin.auth.verify_id_token(token)
            except Exception as e:
                return Response(status=403, response=f"Error with authentication: {e}")
        else:
            return Response(status=401, response="Error, token not found.")

        service = request.path_params.get("service")
        action = request.path_params.get("action")
        if service not in self.config_map:
            return Response(status=404, response=f"Service {service} not found.")
        if action not in self.config_map[service]:
            return Response(status=404, response=f"Action {action} not found in service {service}.")

        user_uid = decoded_token["uid"]
        permissions = self.config_map[service][action]["permissions"]
        user_role = await self.user_role_function(user_uid)

        if user_role not in permissions:
            return Response(status=403, response=f"User not permitted to call {service}/{action}.")

        if request.method in ["POST", "PUT"]:
            if self.check_id_access:
                body = await request.json()
                if not self.check_id_access(user_uid, body):
                    return Response(status=403, response="User not permitted to perform this action.")

        request.state.uid = user_uid  # Attach the Firebase id to the request state for later use.

        # Process the request
        response = await call_next(request)
        return response
