# Attack Flow Analyzer — How It Works (Internal Guide)

This document explains the product in plain terms so teams can understand what happens from upload to finished graph, without needing to read code.

---

## What it is

The **Attack Flow Analyzer** is a small web application. You give it a threat-related document (or paste text). It produces an **interactive diagram** that shows techniques, tools, and relationships in a way that’s easier to review than scrolling through a long report. You can also generate **detection rules** from what was found.

It is meant to **assist** analysts, not replace judgment. The diagram reflects how an AI interpreted the text—not a guaranteed ground truth.

---

## Who uses it

- Threat intel or SOC teams reviewing advisories, write-ups, or bundles  
- Anyone who wants a quick visual “story” of tactics and connections described in a document  

---

## End-to-end workflow (the journey)

### Step 1: Open the app

You use the app in a browser. Two pieces need to be running on the machine (or server) that hosts it:

1. **The website (frontend)** — what you click and see  
2. **The service behind it (backend)** — what reads files, talks to the AI, and sends data back  

If the page won’t load or says “connection refused,” usually one of these isn’t running.

### Step 2: Provide content

You can either:

- **Upload a file** — for example PDF, plain text, or a STIX JSON bundle, or  
- **Paste text** — same analysis, no file needed  

The system turns everything into **text** it can send to the analysis step (PDFs are read for text; STIX is turned into a text summary the pipeline can use).

### Step 3: Start analysis

When you click to analyze, your text is sent to the **backend**. Nothing magic happens on the browser alone—the heavy work is on the server.

### Step 4: AI-assisted extraction

The backend uses **configured AI models** (via an API key you supply) to:

- Read the document  
- Identify security-relevant ideas (for example techniques, tools, impacts)  
- Suggest how they might link in a sequence or relationship  

So the flow is **not** built by simple keyword search. It is **generated from the text using AI**, which means:

- Results can vary if you run the same text again  
- Quality depends on how clear and detailed the source is  
- A short or vague input may yield a thin or empty diagram  

There are backup steps so that if the main extraction returns almost nothing, the system can still try to build a smaller graph from other signals or a second, simpler AI pass.

### Step 5: View the flow

The app draws **nodes** (boxes) and **lines** between them—things like techniques, tools, assets, vulnerabilities—depending on what was extracted. You can zoom, pan, and open details on a node.

### Step 6 (optional): Rules

From selected techniques, the app can ask the AI to draft **detection-style rules** (for example Sigma, YARA, Suricata). Those are **starting points** for your team to review and tune—not drop-in production rules without review.

---

## What you need in practice

- An **API key** for the AI provider (configured on the server; typically OpenAI-compatible)  
- A valid path to the **ttp_chainer** extraction toolkit on the server (used by the main analysis pipeline)  
- Both **frontend** and **backend** processes running for local or internal demos  

Exact technical setup lives in the project `README` and `.env.example`; this guide is only the workflow story.

---

## Privacy and data handling (short)

The **full text** you analyze is sent to the **AI provider** you configured (the same as using that provider’s API elsewhere). Treat uploads like any sensitive intel: use approved keys, networks, and data-handling policies. Do not use classified or restricted data unless your security team approves that path.

---

## Common issues (non-technical)

| What you see | Likely cause |
|--------------|----------------|
| Browser says site can’t connect on port **5173** | The **website** process isn’t running. |
| Upload works but analyze fails or spins forever | The **backend** isn’t running, or the API key / service path is wrong. |
| “No attack flow” or almost no nodes | The model didn’t extract much—try richer text, or check key and logs. Same file can behave differently on another run. |
| Graph looks generic or odd | The AI may have filled gaps with a generic chain; use the source text as the authority and refine in your process. |

---

## Summary in one sentence

**You supply threat-related text; the backend sends it to AI models that extract and connect ideas; the app turns that into an interactive flow you can explore and optionally turn into draft detection content.**

---

*Internal use — align with your org’s AI and data policies. For deployment and environment details, see `README.md` in this folder.*
