# Security Analysis Automation

An automated Governance, Risk, and Compliance (GRC) assessment agent that performs passive reconnaissance and maps findings to security frameworks. This tool automatically aggregates intelligence from public data sources to generate client-ready, professional security assessment reports.

A hiring manager or a security team looking at this project will see a practical demonstration of software engineering fundamentals, structured risk thinking, and real-world framework mapping.

---

## Technical Architecture

The tool uses a multi-layered automation pipeline to move from a simple company name to a comprehensive compliance deliverable:

1. **User Input:** Accepts a company name, domain, and optional ticker or internal documentation.


2. **Orchestration Layer:** Powered by local LLMs via Ollama to perform token-efficient reasoning.


3. **Intelligence Tool Belt:** Parallelized workers gathering live passive telemetry and public records.


4. **Two Pass Analysis:** Pass 1 extracts technical findings while Pass 2 handles deterministic framework alignment and risk scoring.


5. **Structured Report Generation:** Outputs high-fidelity terminal views, portable JSON data, or stylized HTML reports designed to easily print to PDF.



---

## Project Roadmap and Development Phases

This project was built iteratively across five distinct development phases:

### Phase 1: Proof of Concept

* Focused on establishing the core orchestration loop.


* Built a foundational Python script capable of accepting user targets.


* Directed the LLM engine to analyze raw text inputs and generate structured textual risk analysis.



### Phase 2: Passive Data Source Integration

* Expanded the intelligence tool belt by implementing parallel API connections and scrapers.


* Integrated the Qualys SSL Labs API to assess transport layer security configurations.


* Embedded automated checks for HTTP security headers.


* Added news intelligence aggregation and OSINT querying via Tavily to flag historical security incidents.


* Connected corporate public disclosures by checking ASX company announcements and OAIC data breach records.



### Phase 3: Framework Mapping and Risk Register

* Implemented a formal risk register utilizing a standard likelihood and impact matrix.


* Developed deterministic prompt guardrails to map technical observations straight to major compliance baselines: the Australian Cyber Security Centre (ACSC) Essential Eight, ISO 27001, NIST CSF 2.0, and the Australian Privacy Principles (APPs).


* Designed specific guardrails preventing AI hallucination, ensuring any control unobservable by passive scanning defaults strictly to a clean, non-assumed status unless supported by concrete documentary evidence.



### Phase 4: Professional Report Generation

* Transformed raw terminal outputs into enterprise-grade consulting deliverables.


* Configured a custom HTML layout engine featuring clean typography, clear visual risk hierarchies, corporate branding, and strict page-break control.


* Embedded clear, necessary disclaimers defining the boundaries of the tool: clarifying that it handles passive reconnaissance only, generates indicative findings, requires professional human oversight, and is never a substitute for authorized penetration testing.


* Implemented a fallback document generation pipeline ensuring look-and-feel consistency across different execution platforms.



### Phase 5: Web Frontend and Deployment

* Developed an intuitive user interface to wrap the underlying CLI tool.
* Created a single-input interface where a user can enter a company domain, view progress indicators, and directly fetch their compliance files.
* Structured the web application layout for seamless hosting on lightweight deployment platforms like Vercel or Railway.



---

## Setup and Dependencies

The backend engine depends heavily on Python along with a small, specialized selection of packages for scraping, parsing, and rendering:

* `requests` for robust endpoint interaction.


* `beautifulsoup4` and `lxml` for structured web scraping.


* `rich` for formatting complex data layouts inside the command line interface.


* `python-dotenv` for local environment configuration and key safety.



---

## Critical Operating Methodology

This tool operates under strict professional boundaries. Because it relies exclusively on public information, evaluating internal technical controls directly is not possible without context.

To bridge the gap between passive telemetry and internal posture, users should supply internal documentation (such as a public privacy statement, an annual report, or an information security policy) utilizing the script's document flag. When provided, the engine extracts documented operational claims and parses them directly against the framework models, turning unverified items into evidence-backed compliance analysis.