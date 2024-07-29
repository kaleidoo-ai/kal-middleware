import time
from typing import Tuple
from kal_utils.requests import post
from firebase_admin import auth

async def login_with_email_password(email: str, password: str, api_key: str):
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
    payload = {
        "email": email,
        "password": password,
        "returnSecureToken": True
    }

    response = await post(url, json=payload)
    if "idToken" in response:
        return response["idToken"], response["refreshToken"], response["localId"]
    else:
        return None

def is_token_expired(token: str) -> bool:
    expiration_time_in_seconds_since_epoch = auth.verify_id_token(token)['exp']
    current_time_in_seconds_since_epoch = int(time.time())
    return current_time_in_seconds_since_epoch >= expiration_time_in_seconds_since_epoch


async def refresh_access_token(refresh_token: str, api_key: str) -> Tuple[str, str]:
    url = f"https://securetoken.googleapis.com/v1/token?key={api_key}"
    response = await post(url, data={
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token
    })
    return response["id_token"], response["refresh_token"]


def reset_password(email: str):
    try:
        link = auth.generate_password_reset_link(email)
        # Send this link to the user via email
        print(f"Password reset link: {link}")
    except Exception as e:
        print(f"Error sending password reset email: {e}")
        raise
