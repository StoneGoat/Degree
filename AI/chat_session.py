import threading
import time
import uuid

class ChatSession:
    def __init__(self, model, tokenizer, chat_id=None, on_shutdown=None, model_id=None, initial_history=None):
        self.chat_id = chat_id if chat_id else str(uuid.uuid4())
        self.model = model
        self.tokenizer = tokenizer
        self.model_id = model_id  # Store the model's identifier.
        self.last_activity = time.time()
        self.timer = None
        self.on_shutdown = on_shutdown  # Callback to notify ChatManager on shutdown.
        # Conversation history as a list of messages (each is a dict with "role" and "content").
        self.chat_history = initial_history if initial_history is not None else []
        self.start_inactivity_timer()

    def start_inactivity_timer(self):
        if self.timer:
            self.timer.cancel()
        # Set timer for 60 seconds of inactivity.
        self.timer = threading.Timer(60, self.shutdown)
        self.timer.start()

    def update_activity(self):
        self.last_activity = time.time()
        self.start_inactivity_timer()

    def shutdown(self):
        print(f"Chat session {self.chat_id} with model '{self.model_id}' is shutting down due to inactivity.")
        if self.on_shutdown:
            self.on_shutdown(self.chat_id)

    def generate_response(self, prompt, token_limit=256, temperature=0.7, top_p=0.75, role="user"):
        # Append the new message to the chat history.
        self.chat_history.append({"role": role, "content": prompt})
        
        # Format the conversation.
        if hasattr(self.tokenizer, "apply_chat_template"):
            # If available, use the tokenizer's chat template functionality.
            formatted_chat = self.tokenizer.apply_chat_template(
                self.chat_history,
                tokenize=False,
                add_generation_prompt=True
            )
        else:
            # Fallback: simply join messages with role labels.
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
            pad_token_id=self.tokenizer.eos_token_id
        )
        # Only decode the newly generated tokens.
        generated = outputs[0][inputs['input_ids'].size(1):]
        response = self.tokenizer.decode(generated, skip_special_tokens=True).strip()
        
        # Append the assistant's response to the conversation.
        self.chat_history.append({"role": "assistant", "content": response})
        return response
