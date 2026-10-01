# SecureCloudAI



Cloud Security Posture Management and Misconfiguration Detection Platform



SecureCloudAI is a Python-based cloud security assessment platform that analyzes cloud asset configurations, detects security misconfigurations, generates remediation guidance, and provides AI-assisted security analysis.



The project uses deterministic security rules as the authoritative detection layer while using AI to summarize findings and provide additional recommendations.



## Features



- Cloud asset configuration analysis

- Security misconfiguration detection

- AWS-style S3, IAM, and security group checks

- Severity classification

- Stable security rule IDs

- Remediation guidance

- AI-assisted security analysis

- Mock AI provider for deterministic testing

- OpenAI provider for AI-assisted analysis

- JSON security reports

- Markdown security reports

- Automated testing with pytest

- End-to-end integration testing

- Input validation and error handling

- Generated report protection through `.gitignore`



## Security Checks



SecureCloudAI currently detects:



| Rule ID | Severity | Finding |

|---|---|---|

| `CLOUD-S3-001` | Critical | Publicly accessible storage bucket |

| `CLOUD-S3-002` | High | Storage encryption disabled |

| `CLOUD-S3-003` | Medium | Storage logging disabled |

| `CLOUD-IAM-001` | Critical | Privileged account without MFA |

| `CLOUD-NET-001` | High | SSH exposed to the internet |



## Architecture



```text

Cloud Asset Data

&#x20;      |

&#x20;      v

+------------------+

|   Cloud Loader   |

+------------------+

&#x20;      |

&#x20;      v

+------------------+

| Security Detector|

+------------------+

&#x20;      |

&#x20;      +--------------------+

&#x20;      |                    |

&#x20;      v                    v

Deterministic          AI Analysis

&#x20;Findings                Layer

&#x20;      |                    |

&#x20;      +---------+----------+

&#x20;                |

&#x20;                v

&#x20;       +------------------+

&#x20;       | Report Generator|

&#x20;       +------------------+

&#x20;          |          |

&#x20;          v          v

&#x20;       JSON       Markdown

