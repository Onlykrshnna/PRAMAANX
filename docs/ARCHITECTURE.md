# PRAMAANX Architecture & Phase 1 Specifications

## 1. System Overview
PRAMAANX is a modular digital forensics platform engineered to examine untrusted documents and images. It determines authenticity, extracts structural metadata, identifies evasion tactics, and computes a standardized Tamper Risk Score without relying on any external cloud or LLM APIs.

## 2. Core Architecture Pipeline

```mermaid
flowchart TD
    Upload[Untrusted File Input] --> SizeCheck[Size & Ingestion Guardrails]
    SizeCheck --> Hash[SHA-256 Digest]
    SizeCheck --> Entropy[Shannon Entropy H(X)]
    SizeCheck --> Magic[Magic-Byte Signature Inspection]
    
    Magic --> ExtCheck{Extension vs Magic Mismatch?}
    ExtCheck -- Yes --> SpoofFinding[Finding: Extension Spoofing High Severity]
    ExtCheck -- No --> ArchiveCheck{Is ZIP Archive?}
    
    ArchiveCheck -- Yes --> ZipGuard[ZIP Pre-Extraction Safety Screener]
    ZipGuard --> ZipFindings[Zip Slip / Bomb Findings]
    
    SpoofFinding --> Scoring[Noisy-OR Risk Aggregator]
    ZipFindings --> Scoring
    Entropy --> Scoring
    
    Scoring --> Output[AnalysisResult + Risk Band Low/Medium/High]
```

## 3. Mathematical Models

### 3.1 Shannon Entropy
Given byte values $x \in [0, 255]$ with empirical probabilities $p(x) = \frac{\text{count}(x)}{N}$:

$$H(X) = -\sum_{x=0}^{255} p(x) \log_2 p(x)$$

### 3.2 Noisy-OR Tamper Risk Scoring
Given independent findings $F = \{f_1, f_2, \dots, f_n\}$ with calibrated weights $w_i \in [0.0, 1.0]$:

$$\text{Risk Score} = \text{round}\left( \left(1 - \prod_{i=1}^{n} (1 - w_i)\right) \times 100 \right)$$

### 3.3 Risk Bands
- **Low**: 0 to 30
- **Medium**: 31 to 60
- **High**: 61 to 100

