import os

from openai import OpenAI


api_key = os.getenv("OPENAI_API_KEY")

if not api_key:
    raise RuntimeError(
        "OPENAI_API_KEY is not configured."
    )


model = os.getenv("OPENAI_MODEL")

if not model:
    raise RuntimeError(
        "OPENAI_MODEL is not configured."
    )


client = OpenAI(api_key=api_key)


response = client.responses.create(
    model=model,
    input=(
        "You are a defensive cyber threat "
        "intelligence analyst. Reply with exactly: "
        "ThreatIntel AI connection successful"
    ),
)


print(response.output_text)