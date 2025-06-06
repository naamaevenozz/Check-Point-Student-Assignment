from abc import ABC, abstractmethod
from models import CPE
import requests
from utils import handle_http_error
from models import CVE
from github_exploit_searcher import GitHubSearchEngine
from utils import clean_text
from typing import List, Optional

NVD_CPE_API_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDBaseEngine(ABC):
    """
        Abstract base class for engines that interact with the NVD (National Vulnerability Database) API.

        This class defines a common interface for components that perform search operations
        using the NVD APIs, such as CPE or CVE search engines.

        Attributes:
            headers (dict): Optional HTTP headers (e.g., for authentication) to include in requests.

        Methods:
            search(*args, **kwargs):
                Abstract method that must be implemented by subclasses.
                Should perform a specific type of search against the NVD API,
                such as fetching CVEs for a CPE or searching for CPEs by keyword.
        """
    def __init__(self, headers: Optional[dict] = None, results_per_page: int = 100):
        self.headers = headers or {}
        self.results_per_page = results_per_page


    @abstractmethod
    def run(self, *args, **kwargs):
        """Abstract method to be implemented by subclasses."""
        pass


class CPESearchEngine(NVDBaseEngine):
    """
        A search engine that queries the NVD API for CPE (Common Platform Enumeration) entries
        matching a given keyword (e.g., "log4j", "Windows 10").
    """

    def run(self, keyword: str) -> List[CPE]:
        """
        Search for CPEs that match a keyword (e.g., "log4j", "Windows 10").
        Returns a list of CPE objects with title and URI.
        """
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": self.results_per_page,
        }
        cpe_options = {}
        try:
            response = requests.get(NVD_CPE_API_URL, params=params, headers=self.headers)
            response.raise_for_status()
            cpe_options = response.json()
        except requests.exceptions.HTTPError as err:
            handle_http_error(err, source="NVD", context="CPE Search", info=str(params))
        except requests.exceptions.RequestException as e:
            print(f"Request error while fetching CPE data")
            print("There may be an invalid query or a temporary issue. Contact the development team if this persists.")
            raise RuntimeError()

        results = []
        for cpe in cpe_options.get("products", []):
            cpe_info = cpe.get("cpe", {})
            title = (
                cpe_info.get("titles", [{}])[0].get("title", "Unknown title")
                if cpe_info.get("titles") else "Unknown title"
            )
            title = clean_text(title)
            cpe_uri = cpe_info.get("cpeName", "Unknown URI")

            if cpe_uri != "Unknown URI":
                results.append(CPE(title=title, cpe_uri=cpe_uri))

        return results

class CVEFetchEngine(NVDBaseEngine):
    """
        A fetch engine that retrieves CVEs (Common Vulnerabilities and Exposures)
        for a given CPE URI using the NVD API. Can optionally filter by minimum CVSS score
        and collect related GitHub exploits.
    """

    def run(self, cpe_uri: str, github_engine: GitHubSearchEngine, min_cvss_score: Optional[float] = None) -> List[CVE]:
        """
        Fetches CVEs for a given CPE URI.
        Optionally filters by a minimum CVSS v3.x score.
        """
        cve_list = []
        start_index = 0

        # Go through all the pages that need to be fetched from the API
        while True:
            params = {
                "cpeName": cpe_uri,
                "resultsPerPage": self.results_per_page,
                "startIndex": start_index,
            }
            try:
                response = requests.get(NVD_CVE_API_URL, params=params, headers=self.headers)
                response.raise_for_status()
                data = response.json()
            except requests.exceptions.HTTPError as err:
                handle_http_error(err, source="NVD", context="CVE Fetch", info=str(params))
                break
            except requests.exceptions.RequestException as err:
                print(f"[Error] Failed to connect to NVD API: {err}")
                break

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break

            # Go over all CVEs on the current page
            for vuln in vulnerabilities:
                cve_item = vuln.get("cve", {})
                description_data = cve_item.get("descriptions", [])
                description = next((d["value"] for d in description_data if d.get("lang") == "en"), "No description")

                cvss_score = None
                severity_data = cve_item.get("metrics", {})

                cvss_v31 = severity_data.get("cvssMetricV31")
                cvss_v30 = severity_data.get("cvssMetricV30")

                if cvss_v31:
                    cvss_score = cvss_v31[0].get("cvssData", {}).get("baseScore")
                elif cvss_v30:
                    cvss_score = cvss_v30[0].get("cvssData", {}).get("baseScore")

                if min_cvss_score is not None and (cvss_score is None or cvss_score < min_cvss_score):
                    continue

                exploits = []
                seen_urls = set()
                for ref in cve_item.get('references', []):
                    url = ref.get('url')
                    tags = ref.get('tags', [])

                    if 'github.com' in url and 'Exploit' in tags and url not in seen_urls:
                        seen_urls.add(url)
                        exploits.append(github_engine.fetch_github_data(url))

                cve_id = cve_item.get("id","")
                cve_list.append(CVE(
                    cve_id=cve_id,
                    score=cvss_score,
                    description=clean_text(description),
                    github_exploits=exploits
                ))

            start_index += len(vulnerabilities)

        return cve_list
