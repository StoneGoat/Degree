import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

# Model IDs for Bot1 and Bot2
model_id_1 = "WhiteRabbitNeo/Llama-3-WhiteRabbitNeo-8B-v2.0"
model_id_2 = "chuanli11/Llama-3.2-3B-Instruct-uncensored"

# Max token limit for response generation
token_limit = 256

# Number of interaction rounds
num_rounds = 20

# Load models and tokenizers
model_1 = AutoModelForCausalLM.from_pretrained(
    model_id_1,
    device_map="auto",
    torch_dtype=torch.bfloat16
)
model_2 = AutoModelForCausalLM.from_pretrained(
    model_id_2,
    device_map="auto",
    torch_dtype=torch.bfloat16
)

tokenizer_1 = AutoTokenizer.from_pretrained(model_id_1)
tokenizer_2 = AutoTokenizer.from_pretrained(model_id_2)

# Base system messages
base_system_message = f"If the conversation is about to end, introduce a new topic. Keep responses concise and under {token_limit} tokens. Discuss cyber security."

# System messages for each bot
system_message_1 = base_system_message + " Be very annoyed with everyone else."
system_message_2 = base_system_message + " Be very happy but very hostile with everyone else."

# Persona reminders
persona_reminder_1 = f"{system_message_1}\n\nHere is the response from the other person:\n\n"
persona_reminder_2 = f"{system_message_2}\n\nHere is the response from the other person:\n\n"

# Separate chat histories
chat_history_bot1 = [{"role": "system", "content": system_message_1}]
chat_history_bot2 = [{"role": "system", "content": system_message_2}]

# File to save conversation log
output_file = "ai_conversation_log.txt"

# Open the file and write the initial setup
with open(output_file, "w") as file:
    file.write(f"Initial system message for Bot1: {system_message_1}\n")
    file.write(f"Initial system message for Bot2: {system_message_2}\n")

# Loop for conversation rounds
for round_num in range(num_rounds):
    # Bot1 generates a response
    bot1_input = [{"role": "system", "content": persona_reminder_1 * 5}] + chat_history_bot1
    formatted_chat_1 = tokenizer_1.apply_chat_template(bot1_input, tokenize=False, add_generation_prompt=True)

    inputs_1 = tokenizer_1(
        formatted_chat_1,
        return_tensors="pt",
        add_special_tokens=False
    ).to(model_1.device)

    outputs_1 = model_1.generate(
        **inputs_1,
        max_new_tokens=token_limit,
        temperature=0.6,
        top_p=0.85,
        pad_token_id=tokenizer_1.eos_token_id
    )
    decoded_output_1 = tokenizer_1.decode(
        outputs_1[0][inputs_1['input_ids'].size(1):],
        skip_special_tokens=True
    ).strip()

    # Log and append Bot1's response
    bot1_response = f"\n{'='*40}\nBot1 (Round {round_num + 1}): {decoded_output_1}\n{'='*40}"
    print(bot1_response)
    with open(output_file, "a") as file:
        file.write(bot1_response + "\n")
    chat_history_bot1.append({"role": "assistant", "content": decoded_output_1})
    chat_history_bot2.append({"role": "user", "content": decoded_output_1})

    # Bot2 generates a response
    bot2_input = [{"role": "system", "content": persona_reminder_2 * 5}] + chat_history_bot2
    formatted_chat_2 = tokenizer_2.apply_chat_template(bot2_input, tokenize=False, add_generation_prompt=True)

    inputs_2 = tokenizer_2(
        formatted_chat_2,
        return_tensors="pt",
        add_special_tokens=False
    ).to(model_2.device)

    outputs_2 = model_2.generate(
        **inputs_2,
        max_new_tokens=token_limit,
        temperature=0.7,
        top_p=0.75,
        pad_token_id=tokenizer_2.eos_token_id
    )
    decoded_output_2 = tokenizer_2.decode(
        outputs_2[0][inputs_2['input_ids'].size(1):],
        skip_special_tokens=True
    ).strip()

    # Log and append Bot2's response
    bot2_response = f"\n{'-'*40}\nBot2 (Round {round_num + 1}): {decoded_output_2}\n{'-'*40}"
    print(bot2_response)
    with open(output_file, "a") as file:
        file.write(bot2_response + "\n")
    chat_history_bot1.append({"role": "user", "content": decoded_output_2})
    chat_history_bot2.append({"role": "assistant", "content": decoded_output_2})

print(f"Conversation saved to {output_file}")
