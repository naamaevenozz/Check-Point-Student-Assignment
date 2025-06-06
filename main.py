"""
Main CLI program connecting the components.
Allows user input for CPE keyword, shows matching CPEs,
lets user select a CPE, fetches CVEs, and displays Exploit info from GitHub.
"""

from dotenv import dotenv_values
from nvd_base import CPESearchEngine,CVEFetchEngine
from typing import Optional, List
from github_exploit_searcher import GitHubSearchEngine
from models import CPE
from utils import print_header, print_divider, github_stars_to_rating

config = dotenv_values(".env")
NVD_API_KEY = config.get("NVD_API_KEY")
GITHUB_TOKEN = config.get("GITHUB_API_AUTH_TOKEN")

GITHUB_AUTH_HEADER = {"Authorization": f"Bearer {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}
NVD_AUTH_HEADER = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}

MAX_REPO_SHOWN = 5

def prompt_float(prompt_text: str, allow_blank: bool = True) -> Optional[float]:
    while True:
        value = input(prompt_text).strip()
        if allow_blank and not value:
            return None
        try:
            return float(value)
        except ValueError:
            print("Invalid number. Please enter a numeric value.")

def get_cpe_results(keyword: str) -> List[CPE]:
    cpe_searcher = CPESearchEngine(NVD_AUTH_HEADER,150)
    return cpe_searcher.run(keyword)

def select_cpe_from_results(cpe_results: List[CPE]) -> Optional[CPE]:
    print("\nFound CPEs:")
    for i, cpe in enumerate(cpe_results, start=1):
        print(f"{i}. {cpe.title} ({cpe.cpe_uri})")

    try:
        choice = int(input("\nSelect a CPE by number: "))
        if not (1 <= choice <= len(cpe_results)):
            raise ValueError
        return cpe_results[choice - 1]
    except ValueError:
        print("Invalid selection.")
        return None

def get_min_cvss_score() -> Optional[float]:
    return prompt_float("Enter minimum CVSS score to filter (press Enter to skip): ")

def display_cve_table(cve_list):
    print_divider()
    print(f"| {'CVE ID':<24} | {'Severity':<9} | {'Description':<58} |")
    print_divider()

    for cve in cve_list:
        score = "N/A" if cve.score is None else f"{cve.score}"
        full_desc = cve.description or ""
        lines = [full_desc[i:i + 58] for i in range(0, len(full_desc), 58)]

        if lines:
            print(f"| {cve.cve_id:<24} | {score:<9} | {lines[0]:<58} |")
            for line in lines[1:]:
                print(f"| {' ' * 24} | {' ' * 9} | {line:<58} |")

        if cve.github_exploits:
            unique_exploits = {}
            for exploit in cve.github_exploits:
                base_url = exploit.url.split("/tree/")[0]
                if base_url not in unique_exploits or exploit.stars > unique_exploits[base_url].stars:
                    unique_exploits[base_url] = exploit

            sorted_exploits = sorted(unique_exploits.values(), key=lambda e: e.stars, reverse=True)[:MAX_REPO_SHOWN]

            if sorted_exploits:
                print(f"| {' ' * 24} | {' ' * 9} | {'GitHub Resources:':<58} |")

            for exploit in sorted_exploits:
                stars = exploit.stars
                stars_label = github_stars_to_rating(stars)
                repo_name = exploit.url.split("github.com/")[-1].split("/tree/")[0]
                display_text = f"- {repo_name} ({stars_label} - {stars} stars)"
                wrapped_lines = [display_text[i:i + 58] for i in range(0, len(display_text), 58)]
                for i, line in enumerate(wrapped_lines):
                    print(f"| {' ' * 24} | {' ' * 9} | {line:<58} |")

        print_divider()

def main():
    """
        Main entry point for the 'CPE to CVE Vulnerability Lookup Tool'.

        This function provides an interactive CLI that allows users to:
          1. Input a software or hardware keyword.
          2. Search for matching CPEs (Common Platform Enumerations).
          3. Select a CPE from the results.
          4. Optionally define a minimum CVSS v3.x score threshold.
          5. Fetch related CVEs from the NVD API.
          6. Display the vulnerabilities in a structured table format.

        The function loops until the user chooses to exit.
        It handles user input validation and exception handling for external API calls.
    """
    print_header("CPE to CVE Vulnerability Lookup Tool")
    cpe_engine = CPESearchEngine(NVD_AUTH_HEADER,150)
    cve_engine = CVEFetchEngine(NVD_AUTH_HEADER)
    github_engine = GitHubSearchEngine(GITHUB_TOKEN)

    while True:
        keyword = input("Enter software/hardware keyword (e.g., 'log4j'): ").strip()
        if not keyword:
            print("Keyword cannot be empty.")
            continue

        try:
            # cpe_results = get_cpe_results(keyword)
            cpe_results = cpe_engine.run(keyword)
        except (RuntimeError, PermissionError, ValueError):
            continue

        if not cpe_results:
            print("No CPEs found for your keyword.")
            continue

        selected_cpe = select_cpe_from_results(cpe_results)
        if not selected_cpe:
            continue

        min_score = get_min_cvss_score()

        print(f"\nVulnerabilities found for {selected_cpe.title}:")
        try:
            cve_list = cve_engine.run(
                selected_cpe.cpe_uri,
                github_engine,
                min_cvss_score=min_score
            )
        except Exception:
            continue

        if not cve_list:
            print("No vulnerabilities found matching your criteria.")
        else:
            display_cve_table(cve_list)

        again = input("\nWould you like to perform another search? (y/n): ").strip().lower()
        if again != 'y':
            break

if __name__ == "__main__":
    main()
