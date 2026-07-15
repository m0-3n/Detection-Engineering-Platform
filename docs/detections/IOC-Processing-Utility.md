# IOC Processing Utility

## Overview

The IOC Processing Utility is a modular component of the **Detection Engineering Platform** responsible for processing raw Indicators of Compromise (IOCs) into a standardized, validated, and structured format.

The utility accepts a text file containing one IOC per line and performs the following operations:

1. Reads raw IOC data.
2. Classifies the IOC type.
3. Validates the IOC format.
4. Normalizes IOC values.
5. Removes duplicate entries.
6. Exports the processed data to multiple output formats.

The resulting dataset can be consumed by future modules within the Detection Engineering Platform, including detection engineering, threat hunting, SIEM rule development, and automation workflows.

---

# Purpose

Threat intelligence is collected from a wide range of sources, including:

* Threat intelligence reports
* Malware analysis
* Incident response investigations
* Open-source intelligence (OSINT)
* Security vendors
* Community IOC feeds

These sources often contain duplicate indicators, inconsistent formatting, and mixed IOC types. Before the data can be used by security tools, it must be standardized and validated.

The IOC Processing Utility automates this process by transforming unstructured IOC data into a clean and reusable dataset.

---

# Objectives

The utility has the following objectives:

* Validate Indicators of Compromise
* Classify IOC types automatically
* Normalize IOC formatting
* Remove duplicate indicators
* Produce consistent output formats
* Provide reusable structured data for future modules

---

# Supported IOC Types

| IOC Type     | Example                                                            |
| ------------ | ------------------------------------------------------------------ |
| IPv4 Address | `8.8.8.8`                                                          |
| Domain       | `example.com`                                                      |
| URL          | `https://example.com/login`                                        |
| MD5 Hash     | `44d88612fea8a8f36de82e1278abb02f`                                 |
| SHA1 Hash    | `3395856ce81f2b7382dee72602f798b642f14140`                         |
| SHA256 Hash  | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

---

# Project Architecture

```text
                Raw IOC File
                      │
                      ▼
                Read Input File
                      │
                      ▼
              Parse Individual Lines
                      │
                      ▼
             Classify IOC Type
                      │
                      ▼
              Validate IOC Format
                      │
                      ▼
              Normalize IOC Values
                      │
                      ▼
             Remove Duplicate IOCs
                      │
                      ▼
             Create IOC Objects
                      │
                      ▼
          Export JSON / CSV / TXT
```

---

# Processing Workflow

## Step 1 – Input

The utility reads a text file containing one IOC per line.

Example:

```text
8.8.8.8
google.com
https://example.com/login
44d88612fea8a8f36de82e1278abb02f
```

Blank lines are ignored automatically.

---

## Step 2 – Classification

Each value is classified according to a fixed order.

Classification order:

1. IPv4
2. URL
3. Domain
4. MD5
5. SHA1
6. SHA256
7. Unknown

Using a fixed order ensures deterministic behaviour and prevents ambiguous classifications.

---

## Step 3 – Validation

Each IOC type is validated using dedicated validation functions.

Examples include:

* `ipaddress` for IPv4 addresses
* Regular expressions for hashes
* `urllib.parse` for URLs
* Domain validation using regular expressions

Each validator has a single responsibility and can be tested independently.

---

## Step 4 – Normalization

Before duplicate detection, IOC values are normalized.

Normalization rules:

| IOC Type | Normalization                 |
| -------- | ----------------------------- |
| Domain   | Convert to lowercase          |
| URL      | Lowercase scheme and hostname |
| MD5      | Lowercase                     |
| SHA1     | Lowercase                     |
| SHA256   | Lowercase                     |
| IPv4     | No modification               |
| Unknown  | No modification               |

Normalization improves consistency and ensures equivalent values are treated as duplicates where appropriate.

---

## Step 5 – Deduplication

Duplicate IOC entries are removed while preserving their original order.

Deduplication compares:

* IOC value
* IOC type

This approach avoids incorrect matches between different IOC categories while maintaining predictable output.

---

## Step 6 – Export

The processed IOC dataset can currently be exported as:

* JSON
* CSV
* TXT

Each exporter is implemented independently while sharing the same processed IOC objects.

---

# Module Responsibilities

| Module            | Responsibility                                  |
| ----------------- | ----------------------------------------------- |
| `main.py`         | Command-line interface                          |
| `parser.py`       | Reads input and classifies IOC types            |
| `validator.py`    | Validates IOC formats                           |
| `normalizer.py`   | Normalizes IOC values                           |
| `deduplicator.py` | Removes duplicate IOCs                          |
| `exporter.py`     | Exports processed IOC data                      |
| `models.py`       | Defines IOC data models                         |
| `constants.py`    | Stores shared constants and regular expressions |

---

# Data Model

Each IOC is represented using a frozen dataclass.

```python
IOC(
    value="8.8.8.8",
    ioc_type=IOCType.IPV4,
    is_valid=True
)
```

This provides:

* Immutable data objects
* Improved readability
* Strong typing
* Easier testing
* Easier serialization

---

# Design Decisions

## Why a Modular Architecture?

Each module has a single responsibility.

Advantages include:

* Easier maintenance
* Simpler testing
* Better readability
* Improved scalability
* Reduced coupling

Future modules can be added without modifying existing functionality.

---

## Why Dataclasses?

Dataclasses reduce boilerplate code while providing a clear representation of IOC objects.

Using `frozen=True` prevents accidental modification after object creation.

---

## Why an Enum for IOC Types?

Using an enumeration avoids inconsistencies caused by raw strings.

Instead of:

```text
ipv4
IPv4
IPV4
ip_v4
```

the application uses:

```python
IOCType.IPV4
```

This improves consistency throughout the project.

---

## Why Normalize Before Deduplication?

Without normalization:

```text
Google.com
google.com
GOOGLE.COM
```

would be treated as three separate entries.

Normalization ensures logically identical values are compared consistently.

---

## Why Separate Exporters?

Each output format has different requirements.

Keeping exporters separate:

* Simplifies maintenance
* Makes testing easier
* Allows new formats to be added without changing existing code

---

# Example Input

```text
8.8.8.8
google.com
GOOGLE.COM
https://example.com/login
44D88612FEA8A8F36DE82E1278ABB02F
invalid-ip
```

---

# Example JSON Output

```json
[
    {
        "value": "8.8.8.8",
        "ioc_type": "ipv4",
        "is_valid": true
    },
    {
        "value": "google.com",
        "ioc_type": "domain",
        "is_valid": true
    }
]
```

---

# Example CSV Output

```text
value,ioc_type,is_valid
8.8.8.8,ipv4,True
google.com,domain,True
```

---

# Example TXT Output

```text
8.8.8.8
google.com
https://example.com/login
```

---

# Testing Strategy

The IOC Processing Utility uses unit testing to verify individual components independently.

Current tests include:

* IOC validation
* IOC parsing
* IOC deduplication
* IOC exporting

Testing is performed using **pytest**.

Before every commit:

```bash
python -m pytest
```

This ensures existing functionality remains stable as the project evolves.

---

# Current Limitations

The current implementation does not yet support:

* IPv6 addresses
* CIDR ranges
* Email addresses
* Registry keys
* File paths
* Cryptocurrency wallet addresses
* Threat intelligence enrichment
* STIX 2.1 export
* MISP export
* YARA rule generation
* Sigma rule generation
* Wazuh rule generation

These features are planned for future development.

---

# Future Enhancements

Planned improvements include:

* IPv6 validation
* CIDR support
* Additional IOC types
* Threat intelligence enrichment
* VirusTotal integration
* URLhaus integration
* AbuseIPDB integration
* STIX 2.1 export
* MISP integration
* YARA generation
* Sigma rule generation
* Wazuh rule generation
* Splunk lookup generation
* IOC statistics dashboard
* Logging support
* Configuration file support

---

# References

* MITRE ATT&CK Framework
* Sigma Rule Specification
* Python Standard Library Documentation
* RFC 3986 – Uniform Resource Identifier (URI): Generic Syntax
* RFC 1035 – Domain Names: Implementation and Specification
* RFC 791 – Internet Protocol
