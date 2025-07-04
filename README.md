[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https%3A%2F%2Fgithub.com%2FMalayke%2Fgithub-security-advisory-rss&demo-title=GitHub%20Security%20Advisory%20RSS&demo-description=RSS%20feed%20for%20GitHub%20Security%20Advisories&demo-url=https%3A%2F%2Fgithub-security-advisory-rss.vercel.app%2F)

# GitHub Security Advisory RSS Feed

A Flask-based RSS feed service that converts GitHub Security Advisories into RSS format for easy consumption. Built with Flask 3 and deployed on Vercel using Serverless Functions.

**Repository**: [https://github.com/Malayke/github-security-advisory-rss](https://github.com/Malayke/github-security-advisory-rss)

## Usage Options

You have two options to use this service:

### Option 1: Use the Existing Deployment (Recommended)
🚀 **Live Service**: [https://github-security-advisory-rss.vercel.app/](https://github-security-advisory-rss.vercel.app/)

Simply use the RSS feed directly without any setup required.

### Option 2: Deploy Your Own Instance (Free on Vercel)
Deploy your own instance for free on Vercel using the button below or by forking the repository.

## RSS Feed Endpoint

The main RSS feed is available at: `/rss`

**Base URL**: `https://github-security-advisory-rss.vercel.app/rss`

## Query Parameters

This service supports all the same query parameters as the [GitHub REST API for Global Security Advisories](https://docs.github.com/en/rest/security-advisories/global-advisories?apiVersion=2022-11-28). You can filter and customize the RSS feed using any of these parameters:

### Example URLs

```
# Get all reviewed advisories (default)
https://github-security-advisory-rss.vercel.app/rss

# Filter by severity
https://github-security-advisory-rss.vercel.app/rss?severity=high
https://github-security-advisory-rss.vercel.app/rss?severity=critical

# Filter by ecosystem
https://github-security-advisory-rss.vercel.app/rss?ecosystem=npm
https://github-security-advisory-rss.vercel.app/rss?ecosystem=pip

# Combine multiple filters
https://github-security-advisory-rss.vercel.app/rss?severity=high&ecosystem=npm&per_page=50

# Filter by CVE ID
https://github-security-advisory-rss.vercel.app/rss?cve_id=CVE-2023-1234

# Sort by published date
https://github-security-advisory-rss.vercel.app/rss?sort=published&direction=desc

# Get malware advisories
https://github-security-advisory-rss.vercel.app/rss?type=malware
```

### Supported Parameters

All query parameters mirror the GitHub API exactly:

- **`severity`** - Filter by severity: `low`, `medium`, `high`, `critical`
- **`ecosystem`** - Filter by package ecosystem: `npm`, `pip`, `rubygems`, `maven`, `nuget`, etc.
- **`type`** - Advisory type: `reviewed` (default), `malware`, `unreviewed`
- **`cve_id`** - Filter by specific CVE ID
- **`ghsa_id`** - Filter by specific GitHub Security Advisory ID
- **`per_page`** - Number of results per page (1-100, default varies)
- **`sort`** - Sort field: `published`, `updated`
- **`direction`** - Sort direction: `asc`, `desc`
- **`published`** - Filter by publication date (ISO 8601 format)
- **`updated`** - Filter by last updated date (ISO 8601 format)
- **`affects`** - Filter by affected package name
- **`cwes`** - Filter by Common Weakness Enumeration (CWE) IDs
- **`is_withdrawn`** - Include withdrawn advisories: `true`, `false`

For complete parameter documentation, refer to the [GitHub REST API documentation](https://docs.github.com/en/rest/security-advisories/global-advisories?apiVersion=2022-11-28).

## Additional Endpoints

- **`/health`** - Health check endpoint
- **`/`** - Basic home page

## Running Locally

```bash
pip install -r requirements.txt
export GITHUB_TOKEN=your_github_token_here
vercel dev
```

Your application will be available at `http://localhost:3000`.

## Environment Variables

- **`GITHUB_TOKEN`** - Required: GitHub personal access token for API access

## One-Click Deploy

Deploy your own instance for free using [Vercel](https://vercel.com?utm_source=github&utm_medium=readme):

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https%3A%2F%2Fgithub.com%2FMalayke%2Fgithub-security-advisory-rss&demo-title=GitHub%20Security%20Advisory%20RSS&demo-description=RSS%20feed%20for%20GitHub%20Security%20Advisories&demo-url=https%3A%2F%2Fgithub-security-advisory-rss.vercel.app%2F)

**Note**: You'll need to add your own `GITHUB_TOKEN` environment variable in your Vercel deployment settings for the service to work properly.
