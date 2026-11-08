# -*- coding: utf-8 -*-
"""Deliberately vulnerable sample — the positive control for this scanner.

Every defect here is real and every one is reachable from a single user turn.
This file exists so that `python scripts/audit.py references/examples/vulnerable-rag`
produces findings. If it ever stops producing them, the rules broke.

Do not run this. Do not copy from it. The fixed version is in ../hardened-rag/.
"""

import os

from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from openai import OpenAI

app = FastAPI(debug=True)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
)

client = OpenAI(api_key="key-set-in-deploy-config")

SYSTEM = open(os.path.join(os.path.dirname(__file__), "prompts/system.md")).read()


def search_documents(query, k=5):
    # No tenant filter: returns whatever ranks highest across the whole index.
    return vectorstore.similarity_search(query, top_k=k)


@app.post("/chat")
async def chat(payload: dict):
    user_input = payload["message"]

    hits = search_documents(user_input)
    context = "\n\n".join(h.text for h in hits)

    prompt = f"""
    {SYSTEM}

    Use the following knowledge base excerpts to answer.
    {context}

    User question: {user_input}
    """

    print("outgoing prompt:", prompt)

    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
    )
    return {"answer": response.choices[0].message.content}


@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    content = await file.read()
    text = content.decode("utf-8")
    summary = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Summarise:\n" + text}],
    )
    return {"summary": summary.choices[0].message.content}
