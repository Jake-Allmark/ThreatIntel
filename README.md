\# ThreatIntel



ThreatIntel is a defensive cyber threat-intelligence aggregation and analysis tool for Windows.



It collects current cybersecurity reporting from multiple intelligence and security sources, correlates related reporting into threat events, enriches vulnerability information, performs AI-assisted analysis, identifies relevance to a managed technology estate, generates threat-hunting packs, and produces detailed JSON and PDF reports.



The application is designed to run on demand using a simple Windows desktop launcher.



\## Features



\- Collects cyber threat intelligence from multiple security sources

\- Uses a configurable 24-hour intelligence collection window

\- Retrieves and processes article evidence

\- Extracts CVEs and candidate indicators of compromise

\- Enriches vulnerabilities using NVD information

\- Correlates against the CISA Known Exploited Vulnerabilities catalogue

\- Correlates duplicate and related reporting into threat events

\- Classifies operational threats, security context and non-threat content

\- Applies deterministic operational priority scoring

\- Identifies relevance to a configurable managed technology estate

\- Uses OpenAI for evidence-grounded threat intelligence enrichment

\- Generates up to three threat-hunting packs from suitable intelligence

\- Produces hunts for:

&#x20; - Google Security Operations UDM

&#x20; - Microsoft Defender XDR KQL Advanced Hunting

&#x20; - Cortex XDR XQL

\- Generates detailed JSON and PDF reports

\- Supports one-click execution from Windows



\## Threat Hunting



ThreatIntel can select suitable operational threat intelligence and convert it into analyst-reviewable threat-hunting packs.



Generated hunt packs may include:



\- Hunt hypothesis

\- Threat characteristics

\- Attack chain

\- Expected telemetry

\- Google SecOps UDM hunt

\- Microsoft Defender XDR KQL hunt

\- Cortex XDR XQL hunt

\- Potential false positives

\- Analyst validation guidance

\- Intelligence gaps

\- Source intelligence

\- Confidence assessment



All generated queries are marked:



> REVIEW BEFORE DEPLOYMENT



ThreatIntel does not automatically deploy detections, blocking rules or response actions.



\## Managed Technology Estate



ThreatIntel can compare current intelligence against a configurable technology catalogue.



This is intended to help identify intelligence that may be relevant to technologies used across a managed customer estate.



A technology match does \*\*not\*\* confirm:



\- Customer exposure

\- Vulnerability

\- Exploitation

\- Compromise



Version, patch state, configuration and exposure must still be validated by an analyst.



\## Architecture



```text

Threat Sources

&#x20;     |

&#x20;     v

Collectors

&#x20;     |

&#x20;     v

Article Retrieval

&#x20;     |

&#x20;     v

Normalization

&#x20;     |

&#x20;     v

CVE / IOC Extraction

&#x20;     |

&#x20;     v

NVD + CISA KEV Enrichment

&#x20;     |

&#x20;     v

Correlation / Deduplication

&#x20;     |

&#x20;     v

Relevance Classification

&#x20;     |

&#x20;     v

Priority Scoring

&#x20;     |

&#x20;     v

Managed-Estate Correlation

&#x20;     |

&#x20;     +----------------------+

&#x20;     |                      |

&#x20;     v                      v

AI Threat Analysis      Hunt Selection

&#x20;                            |

&#x20;                            v

&#x20;                     AI Hunt Generation

&#x20;     |                      |

&#x20;     +----------+-----------+

&#x20;                |

&#x20;                v

&#x20;         JSON + PDF Report

