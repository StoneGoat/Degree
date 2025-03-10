from fastapi import FastAPI
from pydantic import BaseModel
from chat_manager import ChatManager

app = FastAPI()
manager = ChatManager()  # Global instance managing all chat sessions.

class ChatRequest(BaseModel):
    chat_id: str = None  # Optional: if not provided, a new session is created.
    prompt: str
    model_id: str = "default"  # Specify which model to use.
    token_limit: int = 256
    temperature: float = 0.7
    top_p: float = 0.75
    role: str = "user"  # E.g., "system", "user", "assistant"

class ChatResponse(BaseModel):
    chat_id: str
    response: str

@app.post("/chat", response_model=ChatResponse)
def chat_endpoint(request: ChatRequest):
    chat_id, response = manager.request_response(
        prompt=request.prompt,
        chat_id=request.chat_id,
        model_id=request.model_id,
        token_limit=request.token_limit,
        temperature=request.temperature,
        top_p=request.top_p,
        role=request.role,
    )
    return ChatResponse(chat_id=chat_id, response=response)
