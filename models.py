"""
This module defines data structures used across the vulnerability analysis project.
It includes representations for CPEs (Common Platform Enumeration), CVEs (Common Vulnerabilities and Exposures),
and GitHub-based exploits.

Classes:
    - CPE: Represents a software or hardware product in standardized CPE format.
    - GitHubExploit: Represents a reference to a publicly available exploit hosted on GitHub.
    - CVE: Represents a known vulnerability entry, enriched with metadata and potential GitHub exploits.
"""

from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class CPE:
    """
    Represents a Common Platform Enumeration (CPE) entry returned by the CPE API.
    """
    title: str       # Human-readable product name
    cpe_uri: str     # Official CPE URI used in API queries (e.g., cpe:/a:apache:log4j:2.14.1)

@dataclass
class GitHubExploit:
    """
    Represents a GitHub exploit reference linked to a CVE.
    """
    url: str
    stars: Optional[int] = 0
    forks: Optional[int] = 0


@dataclass
class CVE:
    """
    Represents a Common Vulnerabilities and Exposures (CVE) entry.
    """
    cve_id: str                       # CVE identifier (e.g., CVE-2021-44228)
    score: Optional[float]           # CVSS v3.x base score (severity)
    description: str                 # Short text description of the vulnerability
    github_exploits: List[GitHubExploit] = field(default_factory=list)

