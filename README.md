# detection-as-code

# Detection-as-Code (DaC) & Sigma Testing Lab

<img width="1024" height="572" alt="image" src="https://github.com/user-attachments/assets/aad45c58-617d-43e8-886e-44dd9d86e6f7" />

![Detection CI](https://img.shields.io/badge/Detection_CI-Passing-brightgreen?style=for-the-badge&logo=githubactions)
![Standard](https://img.shields.io/badge/Standard-Sigma_HQ-blue?style=for-the-badge)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-T1053.003-orange?style=for-the-badge)

A continuous testing framework for modern blue teams. Converts vendor-agnostic Sigma rules into SIEM production queries (Splunk SPL, Elastic DSL) and validates detection effectiveness against synthetic attack telemetry.

---

## 1. Architecture Flow

```mermaid
flowchart LR
    A[Sigma Rule .yml] --> B[Schema & Metadata Validator]
    B -->|Verified| C[Sigma CLI Transpiler Engine]
    C --> D[Splunk SPL]
    C --> E[Elasticsearch Query DSL]
    A --> F[Pytest CI Runner]
    G[Synthetic Attack Logs] --> F
    H[Benign Automation Logs] --> F
    F -->|Assert Attack = MATCH| I[Pass CI Gate]
    F -->|Assert Benign = SUPPRESS| I
