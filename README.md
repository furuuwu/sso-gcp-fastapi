# steps

## Running

```sh
# Backend
uvicorn backend_fastapi.main:app --reload --env-file backend_fastapi/.env

# Frontend
cd frontend_angular
ng serve
```

## Setting up the project

* backend: fastapi
  * authentication: using <https://github.com/authlib/authlib>, set up Google as the provider
* frontend: Angular v20

```sh
# --- Backend

# Install uv 
# https://docs.astral.sh/uv/getting-started/installation/
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

# Create a uv project
mkdir backend_fastapi && cd backend_fastapi
uv init --python=3.12

# Install dependencies and run it
uv add "fastapi[all]" authlib python-dotenv python-jose langchain langchain-openai sqlalchemy alembic
uv run uvicorn main:app --reload

cd ..

# --- Frontend

# Install Node
# https://nodejs.org/en/download

# Install the Angular cli
# https://angular.dev/installation
npm install -g @angular/cli

# Create a Angular project
ng new frontend_angular --directory ./frontend_angular --routing --style=css
# ✔ Do you want to create a 'zoneless' application without zone.js (Developer Preview)? No
# ✔ Do you want to enable Server-Side Rendering (SSR) and Static Site Generation (SSG/Prerendering)? No

# Install dependencies and run it
cd frontend_angular
npm install
npm install jwt-decode
ng serve
```

## Setting up Google OAuth 2.0 Credentials

Follow these steps to get the **Client ID** and **Client Secret** you'll need.

1. **Go to the Google Cloud Console:** Navigate to [https://console.cloud.google.com/](https://console.cloud.google.com/).
2. **Create or Select a Project:** Use an existing project or click the project dropdown at the top and select "New Project". Give it a name like "My FastAPI App".
3. **Navigate to Credentials:** In the left sidebar menu (☰), go to **APIs & Services** \> **Credentials**.
4. **Configure OAuth Consent Screen:** Before creating credentials, you must configure the consent screen.
      * Click **Configure Consent Screen**.
      * Choose **External** for the User Type and click **Create**.
      * Fill out the required fields:
          * **App name:** The name of your application.
          * **User support email:** Your email address.
          * **Developer contact information:** Your email address.
      * Click **Save and Continue** through the "Scopes" and "Test Users" sections for now. You can refine these later. Finally, click **Back to Dashboard**.
5. **Create OAuth Client ID:**
      * Back on the **Credentials** page, click **+ Create Credentials** at the top and select **OAuth client ID**.
      * For **Application type**, select **Web application**.
      * Give it a name (e.g., "FastAPI Backend").
      * Under **Authorized redirect URIs**, click **+ Add URI**. This is crucial. It's the callback URL in your app that Google will send the user back to after they log in. For local development, enter: `http://localhost:8000/api/auth/callback`
      * Click **Create**.
6. **Get Your Credentials:** A window will pop up showing your **Client ID** and **Client Secret**. Copy these and keep them safe. You'll need them for your FastAPI application.

## Testing the endpoints

**Log in:** Go to `http://localhost:8000/`. Click the link, log in with your Google account. You'll be redirected back and shown your access token.

Use a tool like `curl` or an API client (Postman, Insomnia).

* **Get your profile** (works for any logged-in user):

```bash
curl -X GET "http://localhost:8000/profile/me" -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

* **Access the admin dashboard:**
  * If you logged in with an email from the `ADMIN_USERS` list, this will succeed.
  * If you logged in with a regular user's email, this will fail with a `403 Forbidden` error.

```bash
curl -X GET "http://localhost:8000/admin/dashboard" -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

## Database management with alembic

```sh
# Create a migration plan
alembic revision --autogenerate -m "Create conversation history table"

# Apply the migration
alembic upgrade head
```
