import threading
import time
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from chat_session import ChatSession

class ChatManager:
    def __init__(self):
        self.sessions = {}  # Active chat sessions.
        # Mapping from model_id to a dict with keys: "model", "tokenizer", "timer".
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
        timer = threading.Timer(60, lambda: self._unload_model_if_inactive(model_id))
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
            print(f"Removing chat session {chat_id} using model {session.model_id} from ChatManager.")
            del self.sessions[chat_id]

    def request_response(self, prompt, chat_id=None, model_id="default", token_limit=256, temperature=0.7, top_p=0.75, role="user"):
        # If a chat_id is provided and exists, check if its model matches the requested one.
        if chat_id and chat_id in self.sessions:
            session = self.sessions[chat_id]
            if session.model_id != model_id:
                # The provided chat_id maps to a different model. Create a new session.
                print(f"Chat ID {chat_id} is for model '{session.model_id}', starting new session for model '{model_id}'.")
                chat_id = None

        # If no valid chat_id is provided, create a new session.
        if chat_id is None or chat_id not in self.sessions:
            model, tokenizer = self._get_or_load_model(model_id)
            session = ChatSession(model, tokenizer, chat_id, on_shutdown=self.remove_session, model_id=model_id)
            self.sessions[session.chat_id] = session
            chat_id = session.chat_id  # update to the new chat_id

        session.update_activity()
        response = session.generate_response(prompt, token_limit=token_limit, temperature=temperature, top_p=top_p, role=role)
        return session.chat_id, response

