"""Top-level package for kal-middleware."""
__author__ = """Bar Lander"""
__email__ = "barh@kaleidoo.ai"
__version__ = "1.0.4"
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def get_env_var(name, default=None):
    return os.environ.get(name, default)
