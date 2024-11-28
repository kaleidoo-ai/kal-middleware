"""Top-level package for kal-middleware."""
__author__ = """Bar Lander"""
__email__ = "barh@kaleidoo.ai"
__version__ = "2.0.5.2"

import os
from dotenv import load_dotenv

from kal_middleware import keycloakAuth, keycloakSchemas, keycloakConfig
# Load environment variables from .env file
load_dotenv()

def get_env_var(name, default=None):
    return os.environ.get(name, default)
