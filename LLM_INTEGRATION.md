# LLM Integration Guide

## Architecture
The tool uses a local Ollama model (`llama3.1`) to enhance the detection of NIST CSF controls. It operates completely independently of external APIs to ensure data privacy and to avoid API costs during development and analysis.

## Keyword-First Strategy
The primary detection mechanism relies on keyword matching. This approach is:
1. Fast (ms latency vs 5-10s latency for LLM)
2. Predictable
3. High-confidence

## LLM Fallback Workflow
When keyword matching fails to detect a signal for a control, the tool falls back to the LLM.
1. The relevant text (e.g., Trust Center raw text) is passed to Ollama along with the control's specific `llm_extraction_prompt`.
2. The LLM processes the prompt and returns a strictly formatted answer (YES/NO + exact quote).
3. The LLM extraction is added to the evidence with an 85% confidence score (compared to 100% for keywords).

## Cross-Validation
LLM-extracted claims should be cross-validated. If an LLM finds evidence that contradicts keyword findings or isn't corroborated by structured data, it is marked with `requires_verification`.

## Expected Latency
- Keyword-only scan: 2-5 seconds
- LLM Fallback (depending on number of missed controls): +15-40 seconds per scan.

## Changing Models
To use an external API (e.g., OpenAI, Anthropic), you can modify the `OllamaService` class to implement an interface that communicates with the desired API. The system prompts and logic would remain identical.
