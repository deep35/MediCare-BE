import base64
import json
from pathlib import Path
from groq import Groq
import os
from dotenv import load_dotenv

load_dotenv()

GROQ_API = os.getenv("GROQ_API_KEY")

def encode_image(image_input):
    # Case 1 — bytes provided directly (UploadFile.read())
    if isinstance(image_input, (bytes, bytearray)):
        return base64.b64encode(image_input).decode("utf-8")

    # Case 2 — string or Path provided → treat as file path
    if isinstance(image_input, (str, Path)):
        with open(image_input, "rb") as image_file:
            return base64.b64encode(image_file.read()).decode("utf-8")

    raise TypeError("encode_image expects bytes or a file path.")


def get_meds(base64_img):
    prompt = """
    You are an OCR specialist for handwritten and printed medical prescriptions.

    Extract ONLY medicines and supplements from the image and return them in a single valid JSON array. Each item must contain exactly:
    - "medicine": the corrected, full medicine name as plain text
    - "quantity": an integer

    Rules:
    - Output JSON only. No explanation or text outside the JSON.
    - Correct any misspelled medicine names.
    - Do not include dosage, strength, volume, or units (mg, g, ml, IU).
    - Quantity must come ONLY from explicit quantity indicators (Qty:, QTY:, xN, N strips/tabs/pcs/pack/box/bottle/vial).
    - Ignore numbers connected to units of strength or volume.
    - If no valid quantity is present, set quantity to 1.
    - Merge multiline medicine names into one item.
    - Return only the medicine name and its correct quantity, nothing else.
    """

    base64_image = base64_img

    client = Groq(api_key=GROQ_API)

    chat_completion = client.chat.completions.create(
        messages=[
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:image/jpeg;base64,{base64_image}",
                        },
                    },
                ],
            }
        ],
        model="meta-llama/llama-4-scout-17b-16e-instruct",
    )

    result = chat_completion.choices[0].message.content

    return json.loads(result)
