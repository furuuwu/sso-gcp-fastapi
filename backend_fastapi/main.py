# backend_fastapi/main.py
import uvicorn
import os
import json

from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth, OAuthError
from jose import jwt, JWTError
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from pydantic import BaseModel
from sqlalchemy.orm import Session

# Import SQLAlchemy components using absolute paths from the project root
from . import models, database

from langchain_openai import ChatOpenAI
from langchain.memory import ConversationBufferMemory
from langchain.chains import ConversationChain
from langchain.prompts import (
    ChatPromptTemplate,
    MessagesPlaceholder,
    SystemMessagePromptTemplate,
    HumanMessagePromptTemplate,
)

# Create database tables (if they don't exist)
models.Base.metadata.create_all(bind=database.engine)

# --- App & Middleware Configuration ---
app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=os.getenv("APP_SECRET_KEY"))
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:4200"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Settings & Pydantic Models ---
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
APP_SECRET_KEY = os.getenv("APP_SECRET_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
# The ADMIN_USERS list is no longer needed.


class ChatRequest(BaseModel):
    message: str


class ChatResponse(BaseModel):
    reply: str


# --- Database Dependency ---
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()


# --- LangChain Setup ---
llm = ChatOpenAI(model_name="gpt-4", openai_api_key=OPENAI_API_KEY)
prompt = ChatPromptTemplate.from_messages(
    [
        SystemMessagePromptTemplate.from_template(
            "The following is a friendly conversation between a human and an AI."
        ),
        MessagesPlaceholder(variable_name="history"),
        HumanMessagePromptTemplate.from_template("{input}"),
    ]
)

# --- Authlib Setup & JWT ---
oauth = OAuth()
oauth.register(
    name="google",
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    client_kwargs={"scope": "openid email profile"},
)


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, APP_SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(request: Request, db: Session = Depends(get_db)) -> models.User:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
        )

    token = auth_header.split("Bearer ")[1]
    try:
        payload = jwt.decode(token, APP_SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload"
            )

        user = db.query(models.User).filter(models.User.email == email).first()
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found"
            )
        return user
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )


# --- Authentication Endpoints ---
@app.get("/api/auth/login")
async def login(request: Request):
    redirect_uri = request.url_for("auth_callback")
    return await oauth.google.authorize_redirect(request, redirect_uri)


@app.get("/api/auth/callback", name="auth_callback")
async def auth(request: Request, db: Session = Depends(get_db)):
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

    # --- Check for user in DB or create new one ---
    user = db.query(models.User).filter(models.User.email == user_info["email"]).first()
    if not user:
        user = models.User(
            email=user_info["email"],
            name=user_info["name"],
            picture=user_info["picture"],
            role="user",  # Default role
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    # Use the role from the database to create the token
    internal_access_token = create_access_token(
        data={
            "sub": user.email,
            "role": user.role,
            "name": user.name,
            "picture": user.picture,
        }
    )
    redirect_url = (
        f"http://localhost:4200/auth/callback#access_token={internal_access_token}"
    )
    return RedirectResponse(url=redirect_url)


# -- Chat Endpoint with SQLAlchemy & User ID --
@app.post("/api/chat", response_model=ChatResponse)
async def chat_with_ai(
    chat_request: ChatRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    # 1. Load conversation history from DB using the user's ID
    history_record = (
        db.query(models.ConversationHistory)
        .filter(models.ConversationHistory.user_id == current_user.id)
        .first()
    )

    memory = ConversationBufferMemory(return_messages=True)
    if history_record and history_record.history:
        past_messages = json.loads(history_record.history)
        for msg in past_messages:
            # --- FIX: Access 'content' directly, not 'data.content' ---
            if msg["type"] == "human":
                memory.chat_memory.add_user_message(msg["content"])
            elif msg["type"] == "ai":
                memory.chat_memory.add_ai_message(msg["content"])

    # 2. Create conversation chain
    conversation = ConversationChain(memory=memory, prompt=prompt, llm=llm)

    # 3. Get AI response
    try:
        response = await conversation.ainvoke(chat_request.message)
        ai_reply = response["response"]
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error communicating with AI service: {str(e)}"
        )

    # 4. Save updated history to DB
    # The memory.chat_memory.messages now contains the full history.
    # We need to convert the message objects to dictionaries before saving.
    history_to_save = [message.dict() for message in memory.chat_memory.messages]
    updated_history_json = json.dumps(history_to_save)

    if history_record:
        history_record.history = updated_history_json
    else:
        new_history_record = models.ConversationHistory(
            user_id=current_user.id, history=updated_history_json
        )
        db.add(new_history_record)

    db.commit()

    return ChatResponse(reply=ai_reply)
