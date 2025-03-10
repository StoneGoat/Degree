import requests

model_list = {"segolilylabs/Lily-Cybersecurity-7B-v0.2", "WhiteRabbitNeo/Llama-3-WhiteRabbitNeo-8B-v2.0", "chuanli11/Llama-3.2-3B-Instruct-uncensored"}

API_URL = "http://127.0.0.1:8000/chat"

def send_chat_request(prompt, chat_id=None, model_id="chuanli11/Llama-3.2-3B-Instruct-uncensored",
                      token_limit=256, temperature=0.7, top_p=0.75, role="user"):
    payload = {
        "prompt": prompt,
        "model_id": model_id,
        "token_limit": token_limit,
        "temperature": temperature,
        "top_p": top_p,
        "role": role
    }
    
    if chat_id is not None:
        payload["chat_id"] = chat_id
        
    response = requests.post(API_URL, json=payload)
    
    if response.status_code == 200:
        data = response.json()
        return data["chat_id"], data["response"]
    else:
        print("Error:", response.text)
        return None, None

def main():
    # Start Chat Session 1 (System message).
    chat_id1, _ = send_chat_request("You are a friendly assistant for Chat 1.", role="system")
    print(f"Chat 1 - System message set. Chat ID: {chat_id1}\n")
    
    # Continue Chat Session 1.
    chat_id1, response1 = send_chat_request("Hello, how are you?", chat_id=chat_id1)
    print(f"Chat 1 - User: Hello, how are you?\nAssistant: {response1}\n")
    
    # Start Chat Session 2 (System message).
    chat_id2, _ = send_chat_request("You are a curious assistant for Chat 2.", role="system")
    print(f"Chat 2 - System message set. Chat ID: {chat_id2}\n")
    
    # Continue Chat Session 2.
    chat_id2, response2 = send_chat_request("Hi, what's new?", chat_id=chat_id2)
    print(f"Chat 2 - User: Hi, what's new?\nAssistant: {response2}\n")

if __name__ == "__main__":
    main()
