import base64
import json
from pathlib import Path
import google.generativeai as genai
import os
from dotenv import load_dotenv

load_dotenv()

GEMINI_API = os.getenv("GEMINI_API_KEY")

genai.configure(api_key=GEMINI_API)


def encode_image(image_input):
    if isinstance(image_input, (bytes, bytearray)):
        return base64.b64encode(image_input).decode("utf-8")

    if isinstance(image_input, (str, Path)):
        with open(image_input, "rb") as f:
            return base64.b64encode(f.read()).decode("utf-8")

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
    - Return only the medicine name and its correct quantity.
    """

    model = genai.GenerativeModel("gemini-2.5-flash")

    # Gemini Vision → expects: [{"mime_type": "image/jpeg", "data": base64_bytes}]
    image_part = {
        "mime_type": "image/jpeg",
        "data": base64.b64decode(base64_img),
    }

    response = model.generate_content(
        [
            prompt,
            image_part
        ],
        generation_config={"temperature": 0}
    )

    raw = response.text.strip()

    # Gemini sometimes wraps JSON in ```json blocks → clean it
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        raw = raw.replace("json", "").strip()

    return json.loads(raw)
