import uvicorn
import os
from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from authlib.integrations.starlette_client import OAuth, OAuthError
from jose import jwt, JWTError
from starlette.middleware.sessions import SessionMiddleware
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# --- App & Middleware Configuration ---
app = FastAPI()

# Add the SessionMiddleware
# The secret key is used to sign the session cookie.
# You should use the APP_SECRET_KEY from your .env file for this.
app.add_middleware(SessionMiddleware, secret_key=os.getenv("APP_SECRET_KEY"))

# This allows your Angular frontend (running on http://localhost:4200)
# to communicate with your backend.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:4200"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Settings ---
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
APP_SECRET_KEY = os.getenv("APP_SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# In a real app, this would be a database lookup.
ADMIN_USERS = ["your.admin.email@gmail.com"]

# --- Authlib Setup ---
oauth = OAuth()
oauth.register(
    name="google",
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    client_kwargs={"scope": "openid email profile"},
)


# --- Internal JWT Functions ---
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, APP_SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# --- Authentication Endpoints ---
@app.get("/api/auth/login")
async def login(request: Request):
    """Redirects the user to Google's login page."""
    # The URL must match *exactly* what you've configured in your Google Cloud Console
    redirect_uri = request.url_for("auth_callback")
    return await oauth.google.authorize_redirect(request, redirect_uri)


@app.get("/api/auth/callback", name="auth_callback")
async def auth(request: Request):
    """Processes the callback from Google and redirects back to Angular with a token."""
    try:
        token = await oauth.google.authorize_access_token(request)
    except OAuthError as error:
        return RedirectResponse(
            url=f"http://localhost:4200/login-failed?error={error.error}"
        )

    user_info = token.get("userinfo")
    if not user_info:
        return RedirectResponse(
            url="http://localhost:4200/login-failed?error=NoUserInfo"
        )

    # --- Authorization: Check role and create internal JWT ---
    user_role = "admin" if user_info["email"] in ADMIN_USERS else "user"

    internal_access_token = create_access_token(
        data={
            "sub": user_info["email"],
            "role": user_role,
            "name": user_info["name"],
            "picture": user_info["picture"],
        }
    )

    # Redirect back to Angular with the token in the URL fragment
    redirect_url = (
        f"http://localhost:4200/auth/callback#access_token={internal_access_token}"
    )

    # DEBUGGING: Log the final redirect URL
    print(f"DEBUG: Redirecting to Angular with URL: {redirect_url}")

    return RedirectResponse(url=redirect_url)


# --- Protected API Endpoints ---
# Note: In a real app, you would use FastAPI's Depends() with a proper security scheme
# to extract and verify the token for each protected endpoint.
# For simplicity here, we'll just show the concept.
@app.get("/api/profile/me")
async def read_current_user():
    # In a real scenario, a dependency would extract the user from the token.
    # This is just a placeholder to show a protected endpoint.
    return {"message": "This is a protected profile endpoint."}


@app.get("/api/admin/dashboard")
async def read_admin_dashboard():
    # A dependency would check for the 'admin' role from the token.
    return {"message": "Welcome to the protected admin dashboard!"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
