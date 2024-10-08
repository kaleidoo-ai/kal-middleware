from .keycloakSchemas import AuthConfigurations
import json
import os
import base64
import tempfile


class KeycloakConfig:
    ENVIRONMENT = os.getenv("ENVIRONMENT", "local")
    KEYCLOAK_CREDENTIALS = os.getenv("KEYCLOAK_CREDENTIALS", "keycloak_credentials.json")

    @staticmethod
    def load_keycloak_credentials(credentials_json=None) -> AuthConfigurations:
        if not credentials_json:
            raise ValueError("Credentials JSON path must be provided.")

        try:
            with open(credentials_json, 'r') as f:
                keycloak_info = json.load(f)
        except FileNotFoundError:
            raise FileNotFoundError(f"File {credentials_json} not found.")
        except json.JSONDecodeError:
            raise ValueError(f"File {credentials_json} is not a valid JSON.")

        required_fields = ['server_url', 'realm', 'client_id', 'client_secret', 'authorization_url', 'token_url']
        missing_fields = [field for field in required_fields if field not in keycloak_info]

        if missing_fields:
            raise ValueError(f"Missing required fields: {', '.join(missing_fields)}")

        return AuthConfigurations(
            server_url=keycloak_info['server_url'],
            realm=keycloak_info['realm'],
            client_id=keycloak_info['client_id'],
            client_secret=keycloak_info['client_secret'],
            authorization_url=keycloak_info['authorization_url'],
            token_url=keycloak_info['token_url'],
        )

    @property
    def decoded_keycloak_credentials(self):
        if self.ENVIRONMENT == "local":
            return self.KEYCLOAK_CREDENTIALS
        try:
            decoded_str = base64.b64decode(self.KEYCLOAK_CREDENTIALS).decode('utf-8')
            with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as temp_file:
                temp_file.write(decoded_str.encode('utf-8'))
                temp_path = temp_file.name
            return temp_path

        except (base64.binascii.Error, ValueError):
            return self.KEYCLOAK_CREDENTIALS


keycloak_config = KeycloakConfig()
