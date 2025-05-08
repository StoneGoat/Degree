import threading
import time
from datetime import datetime
import uuid
import torch
import json
import os
from fastapi import FastAPI
from pydantic import BaseModel
from transformers import AutoModelForCausalLM, AutoTokenizer

torch.backends.cuda.matmul.allow_tf32 = True
torch.backends.cudnn.allow_tf32   = True

# --- ChatSession Class ---
class ChatSession:
    def __init__(self, model, tokenizer, chat_id=None, on_shutdown=None, model_id=None, initial_history=None):
        self.chat_id = chat_id if chat_id else str(uuid.uuid4())
        self.model = model
        self.tokenizer = tokenizer
        self.model_id = model_id  # Store the model's identifier.
        self.last_activity = time.time()
        self.timer = None
        self.on_shutdown = on_shutdown  # Callback to notify ChatManager on shutdown.
        self.chat_history = initial_history if initial_history is not None else []
        self.start_inactivity_timer()

    def start_inactivity_timer(self):
        if self.timer:
            self.timer.cancel()
        self.timer = threading.Timer(600, self.shutdown)
        self.timer.start()

    def update_activity(self):
        self.last_activity = time.time()
        self.start_inactivity_timer()

    def shutdown(self):
        print(f"Chat session {self.chat_id} with model '{self.model_id}' is shutting down due to inactivity.")
        if self.on_shutdown:
            self.on_shutdown(self.chat_id)

    def check_json(self, prompt, level=0):
        filename = "history.json"

        # 1. If the file doesn't exist, create it with an empty "prompts" dict
        if not os.path.exists(filename):
            with open(filename, "w") as f:
                json.dump({0: {}, 1: {}, 2: {}}, f, indent=4)

        # 2. Now open for read+write; handle the case where it's empty or invalid JSON
        with open(filename, "r+") as f:
            try:
                file_data = json.load(f)
            except json.JSONDecodeError:
                # file was empty or invalid → reinitialize
                file_data = {"prompts": {}}
                f.seek(0)
                json.dump(file_data, f, indent=4)
                f.truncate()

            # 3. Perform your lookup
            if prompt in file_data[str(level)]:
                return file_data[str(level)][prompt]

        return ""
    
    def update_json(self, prompt, response, level=0, filename="history.json"):
        # 1. If the file doesn't exist, create it with an empty "prompts" dict
        if not os.path.exists(filename):
            with open(filename, "w") as f:
                json.dump({0: {}, 1: {}, 2: {}}, f, indent=4)

        # 2. Open for read+write
        with open(filename, "r+") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                # Empty or invalid JSON → reinitialize
                data = {"prompts": {}}

            # 3. Update the mapping
            data[str(level)][prompt] = response

            # 4. Write back, then truncate any leftover
            f.seek(0)
            json.dump(data, f, indent=4)
            f.truncate()
        
    def generate_response(self, prompt, token_limit=256, temperature=0.7, top_p=0.75, role="user", level=0):
        print("Time at start of generate_response: " + str(datetime.now()))
        # Append the new message to the chat history.
        self.chat_history.append({"role": role, "content": prompt})

        response = self.check_json(prompt, level)

        if response == "":
            # Format the conversation.
            if hasattr(self.tokenizer, "apply_chat_template"):
                formatted_chat = self.tokenizer.apply_chat_template(
                    self.chat_history,
                    tokenize=False,
                    add_generation_prompt=True
                )
            else:
                formatted_chat = "\n".join([f"{msg['role']}: {msg['content']}" for msg in self.chat_history])
            
            # Tokenize the input.
            inputs = self.tokenizer(
                formatted_chat,
                return_tensors="pt",
                add_special_tokens=True
            ).to(self.model.device)
            
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=token_limit,
                temperature=temperature,
                top_p=top_p,
                pad_token_id=self.tokenizer.eos_token_id,
                do_sample=False
            )
            # Only decode the newly generated tokens.
            generated = outputs[0][inputs['input_ids'].size(1):]
            response = self.tokenizer.decode(generated, skip_special_tokens=True).strip()
        else:
            print("\n\n\nUSING EXISTING RESPONSE\n\n\n")
        
        # Append the assistant's response to the conversation.
        self.chat_history.append({"role": "assistant", "content": response})

        if role != "system":
          self.update_json(prompt, response, level)

        print("Time at end of generate_response: " + str(datetime.now()))

        return response

# ChatManager Class
class ChatManager:
    def __init__(self):
        self.sessions = {}  # Active chat sessions.
        self.loaded_models = {}
        self.model_lock = threading.Lock()

    def _load_model(self, model_id):
        print(f"Loading model {model_id}")
        model = AutoModelForCausalLM.from_pretrained(
            model_id,
            device_map="auto",
            torch_dtype=torch.bfloat16
        )
        tokenizer = AutoTokenizer.from_pretrained(model_id)
        return model, tokenizer

    def _start_model_inactivity_timer(self, model_id):
        if "timer" in self.loaded_models[model_id] and self.loaded_models[model_id]["timer"]:
            self.loaded_models[model_id]["timer"].cancel()
        # Start a timer to unload the model after 60 seconds of inactivity.
        timer = threading.Timer(600, lambda: self._unload_model_if_inactive(model_id))
        self.loaded_models[model_id]["timer"] = timer
        timer.start()

    def _unload_model_if_inactive(self, model_id):
        with self.model_lock:
            # Check if any active session is using this model.
            active = any(session.model_id == model_id for session in self.sessions.values())
            if not active:
                print(f"Unloading model {model_id} due to inactivity.")
                del self.loaded_models[model_id]
                torch.cuda.empty_cache()  # Clear GPU cache if applicable.
            else:
                self._start_model_inactivity_timer(model_id)

    def _get_or_load_model(self, model_id):
        with self.model_lock:
            if model_id not in self.loaded_models:
                model, tokenizer = self._load_model(model_id)
                self.loaded_models[model_id] = {"model": model, "tokenizer": tokenizer, "timer": None}
            self._start_model_inactivity_timer(model_id)
            return self.loaded_models[model_id]["model"], self.loaded_models[model_id]["tokenizer"]

    def remove_session(self, chat_id):
        if chat_id in self.sessions:
            session = self.sessions[chat_id]
            print(f"Removing chat session {chat_id} using model {session.model_id}.")
            del self.sessions[chat_id]

    def request_response(self, prompt, chat_id=None, model_id="default", token_limit=256, temperature=0.7, top_p=0.75, role="user", level=0):
        # If a chat_id is provided and exists, check if its model matches the requested one.
        if chat_id and chat_id in self.sessions:
            session = self.sessions[chat_id]
            if session.model_id != model_id:
                print(f"Chat ID {chat_id} is for model '{session.model_id}', starting new session for model '{model_id}'.")
                chat_id = None

        # If no valid chat_id is provided, create a new session.
        if chat_id is None or chat_id not in self.sessions:
            model, tokenizer = self._get_or_load_model(model_id)
            session = ChatSession(model, tokenizer, chat_id, on_shutdown=self.remove_session, model_id=model_id)
            self.sessions[session.chat_id] = session
            chat_id = session.chat_id  # update to the new chat_id

        session.update_activity()
        response = session.generate_response(prompt, token_limit=token_limit, temperature=temperature, top_p=top_p, role=role, level=level)
        return session.chat_id, response

# FastAPI Setup
app = FastAPI()
manager = ChatManager()  # Global instance managing all chat sessions.

class ChatRequest(BaseModel):
    chat_id: str = None
    prompt: str
    model_id: str = "default"  # Specify which model to use.
    token_limit: int = 256
    temperature: float = 0
    top_p: float = 1
    role: str = "user"  # E.g., "system", "user", "assistant"
    level: int = 0 # 0-1-2

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
        level=request.level
    )
    return ChatResponse(chat_id=chat_id, response=response)
