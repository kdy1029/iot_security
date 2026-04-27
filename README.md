```markdown
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
├── data/                     # APK files or extracted datasets
├── analysis/                 # Core analysis scripts (static analysis, parsing)
├── results/                  # Output reports and findings
├── utils/                    # Helper functions (APK parsing, feature extraction)
├── main.py                   # Entry point for full analysis pipeline
├── analyze_manifest.py       # AndroidManifest.xml analysis
├── extract_components.py     # Extract app components
├── privacy_analysis.py       # Sensitive data & privacy risk detection
├── requirements.txt          # Python dependencies
└── README.md                 # This file

````

---

## Methodology Overview

The pipeline follows a structured workflow:

1. **APK Collection**
   - IoT companion apps are collected from public sources (e.g., app stores)

2. **Static Analysis**
   - APKs are decompiled
   - Manifest and bytecode are analyzed

3. **Component Extraction**
   - Identify exposed components and entry points

4. **Permission Analysis**
   - Evaluate declared permissions vs actual usage

5. **Privacy Threat Modeling**
   - Detect sensitive data flows and potential leaks

6. **Vulnerability Identification**
   - Map findings to known security issues (e.g., improper export, weak protection)

---

## Getting Started

### Prerequisites

- Python 3.8+
- Java (for APK analysis tools, if required)
- Android analysis tools (e.g., apktool, JADX)

---

### Installation

```sh
git clone <your-repository-url>
cd <repository-name>
pip install -r requirements.txt
````

---

### How to Run

1. **Prepare APK Files**

Place IoT Android APK files inside the `data/` directory.

---

2. **Run Full Analysis Pipeline**

```sh
python main.py
```

---

3. **Run Individual Modules (Optional)**

* Manifest Analysis:

```sh
python analyze_manifest.py
```

* Component Extraction:

```sh
python extract_components.py
```

* Privacy Analysis:

```sh
python privacy_analysis.py
```

---

## Results

This project demonstrates that many IoT Android applications expose significant security and privacy risks:

* **Exposed Components**
  Multiple apps contain exported components without proper protection

* **Over-Privileged Permissions**
  Apps often request more permissions than required for functionality

* **Sensitive Data Exposure**
  Potential leakage of user data through insecure communication or improper handling

* **Attack Surface Expansion**
  Misconfigured components increase the risk of:

  * Intent injection
  * Privilege escalation
  * Data exfiltration

Detailed findings are stored in the `results/` directory.

---

## Use Cases

* Academic research on IoT security
* Security auditing of Android IoT apps
* Dataset generation for ML-based vulnerability detection
* Benchmarking static analysis tools

---

## Future Work

* Integration with dynamic analysis (runtime behavior tracking)
* Automated vulnerability classification using ML models
* Expansion to cross-platform IoT ecosystems (iOS, firmware)

---

## Citation

If you find this work useful in your research, please consider citing our paper:

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

---

## License

This project is licensed under the MIT License.

```
```
