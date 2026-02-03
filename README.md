# LLM-Security

## Most important things to consider (security basics)

* **Model source trust**

  * Only pull models from reputable or verified sources
  * Avoid random or re-uploaded models you can’t trace

* **Prompt & input handling**

  * Treat all user input as untrusted
  * Never allow prompts to directly control system commands or file access

* **Tool / plugin restrictions**

  * Disable tools, shell access, or file system access unless absolutely required
  * Use allow-lists instead of broad permissions

* **Network exposure**

  * Do **not** expose Ollama to the internet by default
  * Bind to `localhost` unless you fully understand the risks

* **Data handling**

  * Don’t feed secrets, API keys, credentials, or sensitive data into prompts
  * Assume prompts and outputs may be logged or cached

* **Model output trust**

  * Never blindly trust model output for decisions, code execution, or security logic
  * Always validate and sanitize outputs before use

* **System isolation**

  * Run Ollama as a non-root user
  * Prefer containers, VMs, or sandboxing for extra isolation

* **Updates**

  * Keep Ollama and models up to date to reduce known vulnerabilities

---

## Key risks (simple, high-level)

* **Prompt injection**

  * Model is tricked into ignoring rules or revealing data

* **Malicious models**

  * Model contains backdoors or harmful behavior

* **Data leakage**

  * Sensitive data accidentally exposed through prompts or logs

* **Unauthorized access**

  * Open ports allow others to use or abuse your model

* **Command execution**

  * Model output used to run unsafe commands or code

* **Hallucinated authority**

  * Model gives confident but wrong or dangerous advice

* **Supply chain risk**

  * Compromised model files or dependencies

---

### One-sentence rule of thumb

> Treat a local LLM like an **untrusted intern with a very fast typing speed** — helpful, but never in charge of secrets, systems, or decisions.



The link you shared — **[https://atlas.mitre.org/](https://atlas.mitre.org/)** — is the home of **MITRE ATLAS™** (Adversarial Threat Landscape for Artificial-Intelligence Systems), an interactive, publicly accessible **security knowledge base and framework** focused on adversarial threats against AI and machine learning systems. ([vectra.ai][1])

### 📌 What *MITRE ATLAS* Is

**MITRE ATLAS** is:

* A **living, globally accessible knowledge base** of adversary tactics, techniques, and case studies specifically targeting AI/ML systems. ([vectra.ai][1])
* Designed to help **security professionals, AI developers, and researchers** understand how attackers exploit AI systems. 
* Modeled after the well-known **MITRE ATT&CK®** framework, but focused on **AI-specific threats** like data poisoning, model stealing, prompt injection, evasion, and other attacks that don’t fit traditional IT threat models. ([vectra.ai][1])

### 🧠 What the Website Offers

On **atlas.mitre.org** you’ll typically find:

* An **interactive matrix** of **tactics and techniques** showing how adversaries compromise AI systems. ([vectra.ai][1])
* **Descriptions and examples** of adversarial behaviors and methods. ([We learn Security!][2])
* **Real-world case studies** drawn from security research and red team exercises. ([vectra.ai][1])
* **Mitigations and defenses** organizations can use to improve AI security. ([MITRE ATLAS][3])
* Tools like the **ATLAS Navigator** to visualize threat coverage and integrate the framework into threat-modeling workflows. ([vectra.ai][1])

### 📊 Why It Matters

As AI systems become more widely deployed, security risks unique to these systems—such as adversarial example attacks or training data poisoning—are growing. ATLAS provides a **structured way** to understand, communicate, and defend against these risks, often in conjunction with traditional frameworks like MITRE ATT&CK. ([vectra.ai][1])

If you’re interested, I can help you **navigate specific parts of the ATLAS site** (like how to use the matrix, how to find techniques relevant to your AI system, or how to export community data). Just let me know!

[1]: https://www.vectra.ai/topics/mitre-atlas?utm_source=chatgpt.com "MITRE ATLAS: 15 tactics and 66 techniques for AI security"
[2]: https://welearnsecurity.com/2023/07/05/mitre-atlas/?utm_source=chatgpt.com "MITRE ATLAS – We learn Security!"
[3]: https://atlas.mitre.org/pdf-files/MITRE_ATLAS_Fact_Sheet.pdf?utm_source=chatgpt.com "A COLLABORATION ACROSS INDUSTRY, ACADEMIA, AND GOVERNMENT |"
