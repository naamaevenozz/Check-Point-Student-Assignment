# CPE to CVE Vulnerability Lookup Tool

## Description
A command-line tool to search for Common Platform Enumerations (CPEs) by keyword.  
Once you select a CPE, it retrieves related Common Vulnerabilities and Exposures (CVEs) from the National Vulnerability Database (NVD) and finds relevant GitHub exploit repositories ranked by popularity.

## API Authentication Token Setup

To use this app effectively, you can (optionally) provide authentication tokens for the **GitHub API** and the **NVD API**.  
Providing tokens is not mandatory, but **strongly recommended** in order to increase rate limits and avoid temporary blocks due to excessive requests.

You can create the tokens as follows:

- **GitHub Token**:  
  Follow this guide to generate a personal access token:  
  https://docs.github.com/en/github/authenticating-to-github/creating-a-personal-access-token

- **NVD API Key**:  
  Register and request a key from the official NVD website:  
  https://nvd.nist.gov/developers/request-an-api-key

Once you have one or both tokens, create a file named `.env` in the root folder of the project (if it doesn’t exist already), and add the following lines:

```env
# Optional: GitHub token for improved rate limits
GITHUB_API_AUTH_TOKEN=<your_github_token_here>

# Optional: NVD API key for querying CVE data
NVD_API_KEY=<your_nvd_api_key_here>
```

**Important Notes:**

- The `.env` file is listed in `.gitignore`, so your secrets remain private and will **not** be committed to version control or uploaded to any public repository.
- These tokens help increase the reliability and performance of the tool by avoiding rate limits and authorization issues.

