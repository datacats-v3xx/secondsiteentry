# Magecart Attack Investigation & Proof of Concept

## Project Overview

This repository contains a comprehensive security case study documenting the discovery, analysis, and demonstration of a Magecart attack in the wild. The report illustrates how sophisticated threat actors exploit common web vulnerabilities and documents the challenges of communicating security risks effectively.

## Repository Contents

- **Full_Case_Study.md**: The complete three-phase investigation with detailed technical analysis
- **Technical_Appendices/**: Supporting technical evidence including code samples and YARA rules
- **Presentations/**: Simplified slides for different audiences (technical and non-technical)
- **Artifacts/**: Sample evidence files with PII and identifiers removed

## Investigation Phases

### Phase 1: Magecart Attack Discovery & Analysis
Detailed technical documentation of a Magecart Group 12 attack discovered on a restaurant website. Includes JavaScript deobfuscation, infrastructure analysis, and attribution techniques.

### Phase 2: Vulnerability Assessment
Comprehensive security assessment revealing multiple critical vulnerabilities including remote JavaScript injection and arbitrary file upload in Gravity Forms.

### Phase 3: Proof-of-Concept Demonstration
Documentation of an ethically conducted proof-of-concept that demonstrated the same vulnerabilities on the web developer's site using the same techniques employed by Magecart Group 12.

## Key Technical Findings

1. Sophisticated JavaScript obfuscation using lookup tables and dynamic code execution
2. Time-based evasion techniques with dynamic URL generation
3. Referrer-based activation to avoid detection
4. Base64 encoding to hide command and control infrastructure
5. Vulnerable file upload functionality in Gravity Forms WordPress plugin

## Audience & Purpose

This case study is designed for multiple audiences:

- **Security Professionals**: Detailed technical information on Magecart attack techniques
- **Web Developers**: Practical examples of how common vulnerabilities can be exploited
- **Business Stakeholders**: Plain language explanations of security risks and their business impact
- **Students & Researchers**: Real-world example of security research methodology

Each section contains both detailed technical information and "Plain English/TL;DR" summaries to make the content accessible to both technical and non-technical readers.

## Research Ethics

This research followed responsible disclosure practices:

1. All vulnerabilities were reported to the affected parties
2. Proof-of-concept tests were conducted with minimal impact (simple text file upload)
3. No actual exploitation or data exfiltration was performed
4. All PII and identifying information has been redacted from public documentation
5. Both sites were successfully remediated following our demonstration 

## Authors

This research was conducted by the DataCats as part of ongoing security research into e-commerce attacks in the wild.

## License

This work is licensed under Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0). You may use and adapt this material for non-commercial purposes with appropriate attribution.
