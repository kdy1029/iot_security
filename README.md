# Assessing IoT Android App Security: Static Components, Privacy Threats and Vulnerabilities

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This repository presents a comprehensive analysis pipeline for assessing the security and privacy risks of IoT Android applications. The project focuses on identifying vulnerable components, analyzing privacy leaks, and uncovering potential attack surfaces through static analysis techniques.

The goal is to systematically evaluate IoT companion apps—commonly used to control smart devices—and reveal security weaknesses that could lead to data exposure, unauthorized access, or misuse of sensitive information.

---

## academically published

A portion of this research has been accepted for publication:

**Assessing IoT Android App Security: Static Components, Privacy Threats and Vulnerabilities.**  
*Firdous Samreen, Sawsan Imleh, Daeyoung Kim*  
In the 12th EAI International Conference on Mobility, IoT and Smart Cities, December 2025.

---

## Key Features

- **Static Security Analysis Pipeline**  
  Automated extraction and analysis of Android app components (Activities, Services, Broadcast Receivers, Content Providers)

- **Privacy Risk Detection**  
  Identification of sensitive data usage such as:
  - Location
  - Device identifiers
  - Network communication endpoints
  - Permissions misuse

- **Component Exposure Analysis**  
  Detects exported components and misconfigured access controls that may lead to:
  - Intent spoofing
  - Unauthorized inter-app communication

- **Permission & Manifest Inspection**  
  Deep analysis of `AndroidManifest.xml` to identify:
  - Over-privileged apps
  - Dangerous permission combinations

- **Scalable App Evaluation**  
  Designed to analyze multiple IoT APKs in batch mode for large-scale studies

- **Security Reporting**  
  Generates structured outputs summarizing:
  - Vulnerabilities
  - Privacy risks
  - Component-level findings

---

## Project Structure

```
.
├── data/
├── analysis/
├── results/
├── utils/
├── main.py
├── analyze_manifest.py
├── extract_components.py
├── privacy_analysis.py
├── requirements.txt
└── README.md
```

---

## Methodology Overview

1. APK Collection  
2. Static Analysis  
3. Component Extraction  
4. Permission Analysis  
5. Privacy Threat Modeling  
6. Vulnerability Identification  

---

## Getting Started

### Installation

```sh
git clone <your-repository-url>
cd <repository-name>
pip install -r requirements.txt
```

---

### Run

```sh
python main.py
```

---

## Citation

```bibtex
@inproceedings{samreen2025assessing,
  title={Assessing IoT Android App Security: Static Components, Privacy Threats and Vulnerabilities},
  author={Samreen, Firdous and Imleh, Sawsan and Kim, Daeyoung},
  booktitle={12th EAI International Conference on Mobility, IoT and Smart Cities},
  year={2025},
  month={December},
  organization={EAI}
}
```
