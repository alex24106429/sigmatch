# **Project Plan: AI-Assisted Windows EDR**

**Group:** Team Triple Threat  
**Course:** AI for Good Minor \- Term 2 Group Project (Weeks 11–20)  
**Members & Roles:** Arbër Deda, Alex Wrobel, Haki Abdulovski

---

## **1\. Problem Statement**

**What problem:** Modern cyberattacks increasingly rely on stealthy, "fileless" techniques-such as process hollowing, DLL/APC injection, and abuse of legitimate Windows tools ("Living off the Land" binaries/scripts like PowerShell, cmd, or mshta, known as LOLBAS)-to steal data or deploy ransomware without dropping traditional malware files onto disk. 

Standard consumer antivirus tools (including default signature-based defenses) frequently miss or detect these behaviors too late, while enterprise Endpoint Detection and Response (EDR) tools are too expensive, complex, and noisy for non-specialists. When low-level alerts do appear, raw telemetry (e.g., process IDs, registry paths, Sysmon event codes, Sigma rule matches) is incomprehensible to non-technical users, leaving them unable to judge whether an alert is real or what safe action to take.

**For whom:**

1. **Primary users:** Individual Windows users (e.g., freelancers, students, remote workers, journalists, or community organizers) who handle sensitive personal or client data and need protection against stealthy threats without needing deep forensic expertise.  
2. **Secondary stakeholders:** Small IT/security teams or volunteer IT coordinators at resource-constrained organizations (e.g., SMBs, schools, non-profits) who need understandable endpoint triage.

**Why it matters:** A single undetected fileless intrusion or ransomware payload can permanently lock individuals or small organizations out of critical files, expose personal data, and cause severe financial or emotional harm. Conversely, aggressive automated deletion of unknown processes risks breaking legitimate software or operating system stability. Users need real-time containment that pauses suspicious execution safely and reversibly while translating technical forensics into clear, actionable choices.

**Evidence:**

- Technical threat landscape evidence: Publicly documented attack frameworks and benchmarks (LOLBAS project, Sigma detection rules, APTSimulator, Sharp-Suite) demonstrate how easily standard Windows utilities are abused for memory injection and persistence.  
- Current validation gap (to be addressed in Weeks 11–14): While the technical threat is well-documented, we have not yet conducted interviews with everyday Windows users or IT coordinators. A core assumption we must validate early is whether everyday users want and will adopt a lightweight companion EDR alongside Windows Defender, and whether freezing processes with AI explanations genuinely improves comprehension and trust.

---

## **2\. Relation to the Sustainable Development Goals (SDGs)**

* **Primary SDG \- SDG 9 (Industry, Innovation and Infrastructure):** *Build resilient infrastructure, promote inclusive and sustainable industrialization and foster innovation.* Reliable, accessible cybersecurity is foundational to resilient digital infrastructure. Commercial EDR platforms price out individuals and small organizations; this project lowers that barrier by combining open detection standards (Sysmon, Sigma) with AI-assisted explanation.  
* **Secondary SDG \- SDG 16 (Peace, Justice and Strong Institutions):** *Promote peaceful and inclusive societies and build effective, accountable institutions.* Reducing successful ransomware, credential theft, and covert endpoint compromise helps protect citizens, students, and small civic/non-profit groups from digital crime and exploitation.

**Who benefits:** Individual Windows users and small, under-resourced organizations gain enterprise-grade behavioral containment and plain-language security guidance-reducing the digital safety gap between large corporations with Security Operations Centers (SOCs) and everyday computer users.

---

## **3\. Feasibility**

### **Data & Privacy**

* **What data & where from:**  
  1. *Runtime endpoint telemetry:* Real-time Windows Sysmon events (process creation, image loads, network connections, remote threads, registry/persistence changes) generated locally on the user's machine.  
  2. *Detection rules & validation datasets:* Open-source Sigma rules, simulated attack telemetry generated in isolated Virtual Machines (VMs) using APTSimulator and Sharp-Suite, and vetted samples from MalwareBazaar for detection benchmarking.  
* **Privacy:** Endpoint telemetry contains sensitive metadata (usernames, file paths, command-line arguments, IP addresses). To protect user privacy:  
  - Raw Sysmon ingestion, Sigma matching, and containment run 100% locally.  
  - Only minimized, sanitized context needed for triage is passed to the LLM agent via strictly typed forensic RPCs (stripping unnecessary PII/secrets where possible).  
  - If a cloud LLM API is used, users must be explicitly informed what fields leave the device, with opt-in controls and API keys secured via Windows DPAPI.

### **Team Skills & Learning Needs**

* **Existing strengths:**  
  - Arbër Deda:  
    1. **Programming:** Experience with C, C++ and Python.  
    2. **Networking:** Knowledge of TCP/IP, Wi-Fi communication and network protocols.  
    3. **System Integration:** Experience connecting hardware and software, including Raspberry Pi, STM32 and microcontrollers.  
    4. **Troubleshooting:** Able to identify and solve technical problems in software and hardware.  
    5. **Teamwork:** Experience working in Agile teams, using Scrum and dividing tasks across team members.  
  - Alex Wrobel:  
    1. **Programming:** Experience with Python, JavaScript, Java, C and C++.  
    2. **Teamwork:** Experience working with Scrum.  
  - Haki Abdulovski:  
    1. **Programming:** Experience with C, C++ and Python.  
    2. **Networking:** Knowledge of TCP/IP, Wi-Fi communication and network protocols.  
    3. **System Integration:** Experience connecting hardware and software, including Raspberry Pi, STM32 and microcontrollers.  
    4. **Troubleshooting:** Able to identify and solve technical problems in software and hardware.  
    5. **Teamwork:** Experience working in Agile teams, using Scrum and dividing tasks across team members.  
* **What we still need to learn:**  
  - Safe and reliable Windows API usage (SDDL-restricted Named Pipes, WinVerifyTrust UI verification) without deadlocking critical system processes.  
  - Writing/tuning Sigma rules to balance detection coverage against false positives.  
  - Designing and evaluating deterministic vs. LLM-based triage (latency, hallucination control, confidence/uncertainty display).  
  - Conducting structured Design Thinking user interviews and comprehension/usability tests.

### **Scope (8-Week MVP: Weeks 11–18)**

Per our Concept Review, full enterprise architecture is too large for 8 weeks. We commit to a tightly scoped, testable MVP:

| In Scope (8-Week MVP) | Explicitly Out of Scope (Post-MVP / Future Work) |
| :---- | :---- |
| SYSTEM-level EDR Core Service ingesting real-time Sysmon events | Mutual-heartbeat Watchdog Service & WFP network isolation |
| Sigma-based behavioral detection engine (focused rule subset) | Stateful cross-host/kernel injection graph engine |
| Reversible containment via `NtSuspendProcess` before payload execution | Enterprise mTLS web dashboard & Ed25519-signed remote policies |
| Sandboxed LLM forensic triage agent using strictly typed forensic RPCs (process tree, connections, persistence) | Automated cloud remediation / autonomous deletion without human approval |
| Local UI (Named Pipe \+ Anti-Tamper PIN) showing AI explanation, confidence/limits, and Approve/Terminate/Resume controls | Non-Windows platforms (macOS / Linux) |
| Benchmarking in isolated VMs \+ user comprehension testing with real users | Production kernel-mode driver development |

### **Key Risks & Mitigations**

1. **False-positive process freezes:** Suspending a critical Windows process or daily-use app could freeze the user's system. *Mitigation:* Maintain a strict allowlist of signed core OS processes, require high-confidence Sigma thresholds before auto-freezing, and make "Resume Process" one click away.  
2. **Scope creep:** Attempting Watchdog/WFP or the enterprise dashboard would jeopardize a working Week 18 demo. *Mitigation:* Enforce the MVP scope table above; defer enterprise features to documentation/roadmap.  
3. **Malware testing safety:** Running live samples on host machines risks infection. *Mitigation:* Perform all testing on snapshotted, network-isolated VMs using APTSimulator/Sharp-Suite first, restricting any MalwareBazaar binaries to air-gapped VMs.  
4. **LLM latency, cost, or hallucination:** Slow or inaccurate AI explanations delay user decisions or mislead users. *Mitigation:* Keep containment instant and deterministic (Sigma \+ `NtSuspendProcess` runs before the LLM); constrain the LLM to typed RPC facts and display uncertainty/raw evidence alongside the summary.

---

## **4\. Users and Stakeholders**

### **Who They Are & What They Need**

* **Primary Users \- Everyday / Semi-Technical Windows Users:** Need silent protection against stealthy threats, clear non-jargon explanations of *why* something was paused, reassurance that nothing was permanently broken, and simple safe choices (*Resume*, *Terminate*, *Keep Paused*).  
* **Secondary Stakeholders \- SMB / Non-Profit IT Admins & Security Advisors:** Need verifiable technical evidence (Sigma rule ID, process tree, persistence check), low false-positive rates, and confidence that the AI agent itself cannot be hijacked via prompt injection.  
* **Indirect Stakeholders \- Software Developers / Legitimate App Vendors:** Affected if false positives wrongly flag benign developer scripts or updaters.

### **Research & Validation Methods (Design Thinking: Empathize & Test)**

1. **Stakeholder Map:** Map direct users, IT advisors, OS/defender ecosystem (Windows Defender), and potential attackers to clarify boundaries and responsibilities.  
2. **Semi-Structured User Interviews (Weeks 11–13):** Interview **5–8 target Windows users** (plus **1–2 IT/security practitioners**) about past security scares, how they react to Windows Defender/antivirus pop-ups, whether they would install a companion EDR, and what makes them trust or ignore an alert.  
3. **Personas & Empathy Maps (Week 12–13):** Synthesize interview findings into 1–2 grounded user personas (e.g., *Non-Technical Freelancer*, *Volunteer IT Coordinator*) to guide UI wording and containment UX.  
4. **Comparative Comprehension & Usability Testing (Weeks 15–17):** Test interactive mockups and the working prototype by showing users (a) a raw Sigma/Sysmon alert vs. (b) our AI-explained alert, measuring comprehension, decision accuracy, and trust.

---

## **5\. Why AI?**

A purely deterministic (non-AI) rule engine like Sigma can detect and freeze a suspicious process-and importantly, detection and freezing do not depend on AI, ensuring zero-latency containment. However, non-AI solutions fall short on triage, correlation, and user-facing explanation:

1. **Automated Multi-Step Forensic Correlation:** Investigating *why* a Sigma rule fired requires checking parent-child process trees, command-line flags, active network sockets, and persistence keys. A sandboxed AI agent orchestrates strictly typed forensic RPC calls dynamically based on what triggered the alert, rather than forcing a non-expert user to run manual forensic commands.  
2. **Translating Telemetry into Plain-Language Context:** Static Sigma template messages (e.g., *"Suspicious PowerShell EncodedCommand"*) tell a user *what* rule matched, not *what it means in context* (e.g., *"A macro in an invoice Word document launched hidden PowerShell and tried to contact an unknown IP-this strongly resembles fileless malware"*).  
3. **Explainability & Limits (Benchmark Requirement):** During Week 14–17, we will explicitly benchmark our AI triage agent against deterministic Sigma/Chainsaw baselines on speed, accuracy, false positives, and user comprehension. In the UI itself, the AI will show:  
   - What evidence it inspected (linked directly to the RPC outputs),  
   - Its confidence level and rationale, and  
   - Explicit limitations (e.g., *"AI analysis is advisory; check raw process details if unsure"*), plus documented failure cases where the LLM misinterprets benign admin scripts.

*Note on Knock-out Criterion K3:* Without the AI triage & explanation agent, non-expert users cannot reliably distinguish benign false positives from real attacks on frozen processes-leading to either unsafe blind "Resume" clicks or destructive termination of legitimate apps.

---

## **6\. Ethical Considerations**

* **Safety & False-Positive Harm:** Automatic deletion or system-wide lockouts could destroy user work or brick essential apps. *Mitigation:* Use reversible freezing; protect core OS processes via strict allowlists; keep final termination/resumption strictly human-approved.  
* **Privacy & Data Minimization:** System logs can expose sensitive user activity (filenames, URLs, credentials passed on CLI). *Mitigation:* Process logs locally; sanitize/redact sensitive fields before LLM inference; secure API keys with Windows DPAPI; explore local LLM inference or strict zero-retention API settings.  
* **Prompt Injection & Privilege Escalation:** Malicious process names or command lines crafted by an attacker could attempt to trick the LLM into declaring malware "safe." *Mitigation:* Run the AI agent in a low-privilege sandbox with **read-only, strictly typed forensic RPCs**\-the LLM has zero direct OS execution or containment authority, and raw Sigma severity remains visible to the user.  
* **Misinformation & Over-Reliance (Automation Bias):** Users might blindly trust a confident-sounding AI hallucination. *Mitigation:* Ground every AI claim in verifiable RPC evidence shown alongside the summary, display uncertainty/limits, and test user skepticism during usability trials.  
* **Exclusion & Accessibility:** Technical jargon or inaccessible alert interfaces exclude non-technical, older, or visually impaired users. *Mitigation:* Write explanations at an accessible reading level, design clear high-contrast UI states, and validate comprehension with non-technical participants.

---

## **7\. Collaboration**

* **Team Structure & Roles (3 Members):**  
  - **Alex Wrobel:** Core Service & Containment Lead: Log ingestion, NtSuspendProcess/NtResumeProcess, Named Pipe/SDDL security, VM test lab.  
  - **Arber Deda:** Detection & Benchmarking Lead: Sigma rule curation, APTSimulator/Sharp-Suite evaluation, Chainsaw/baseline comparison.  
  - **Haki Abdulovski:** AI Triage & Explainability Lead: Low-privilege AI sandbox, typed forensic RPCs, prompt-injection safeguards, confidence/limit reporting.  
* **Weekly Rhythm:**  
  - **Monday:** Sprint planning (assign GitHub issues for the week, review blockers).  
  - **Wednesday:** Mid-week technical & research sync (30 min).  
  - **Thursday:** Prep progress update, questions, and next steps for supervisor.  
  - **Friday (1 hour):** Mandatory supervisor meeting with all members present.  
* **Communication & Decision Agreements:**  
  - Primary chat: **Discord**  
  - Code & Design Thinking documentation: **GitHub**.  
  - **Git workflow:** Feature branches \+ pull requests requiring at least 1 peer review before merging to `main`.  
  - **Decision-making:** Evidence-based consensus (backed by VM tests or user feedback); if deadlocked after 24 hours, majority vote or escalate to Friday supervisor meeting. If a member falls behind or misses meetings, notify the group 24 hours in advance so tasks can be rebalanced early.

---

## **8\. Plan (Weeks 11–18)**

### **What Our First Version (V1 / Mid-Term) Looks Like (Week 13–14)**

An end-to-end **VM-hosted early prototype** demonstrating:

1. Real-time Sysmon log ingestion \+ a focused set of 5–10 Sigma rules detecting simulated LOLBAS/injection behavior (triggered via APTSimulator).  
2. Automatic process freeze on match.  
3. A basic sandboxed LLM triage script consuming typed process-tree/network JSON to produce a plain-language explanation \+ confidence indicator.  
4. Initial findings from 5+ user/IT interviews (personas, empathy map, and comprehension baseline).

### **What We Deliver by Week 15**

By the start of Week 15, we will deliver a **functional integrated MVP** inside our GitHub repository:

- Working EDR Core Service \+ Sigma detection \+ containment in an isolated Windows VM.  
- Sandboxed AI triage agent connected via typed RPCs.  
- Local desktop UI connected over an SDDL-restricted Named Pipe allowing a user to read the AI explanation (with uncertainty/limits) and click **Terminate** or **Resume**.  
- Completed Design Thinking phases 1–3 (*Empathize, Define, Ideate*) documented on GitHub, plus a test plan for Weeks 15–17 user & detection evaluations.

### **Step-by-Step Schedule for the Next Three Weeks**

* **Week 11 (Empathize & Architecture Setup):**  
  - Finalize team roles, set up GitHub repository structure (code \+ Design Thinking docs), and provision isolated Windows test VMs (Sysmon \+ APTSimulator).  
  - Submit Draft Project Plan (Thursday) and review open scope/ethics questions with supervisor (Friday).  
  - Draft interview guide and recruit 5–8 Windows users \+ 1–2 IT advisors.  
* **Week 12 (Define, Ideate & Final Plan):**  
  - Conduct user/IT interviews; synthesize findings into problem definition, personas, and empathy map.  
  - Explore and document at least 3 UX/AI triage alternatives (e.g., deterministic templates vs. local LLM vs. cloud sandboxed LLM) before locking V1 architecture.  
  - Submit Final Project Plan \+ deliver 5-minute pitch (Thursday).  
* **Week 13 (Early Prototype & Mid-Term Review):**  
  - Build V1 pipeline: Sysmon \-\> Sigma match \-\> `NtSuspendProcess` \-\> typed forensic RPC \-\> AI explanation output.  
  - Run initial APTSimulator & Sharp-Suite tests to verify freeze reliability and false-positive behavior.  
  - Prepare early prototype demo, initial user research insights, and feedback questions for the Mid-Term Progress Meeting (Week 13 or 14).

---

## **Appendix: Open Questions for Supervisor (Week 11/12 Review)**

1. Are there any institutional restrictions on testing benign attack-simulation tools (APTSimulator / Sharp-Suite) on personal laptops inside isolated local VMs?  
2. For our Week 15–18 user impact tests, is evaluating user comprehension and decision accuracy via realistic simulated alerts in a controlled VM sufficient (given we cannot expose real users to live malware)?  
3. Do you recommend prioritizing a local quantized LLM (stronger privacy, higher hardware requirement) or a cloud LLM with stripped/anonymized RPC telemetry (lower latency/better reasoning) for the 8-week MVP?