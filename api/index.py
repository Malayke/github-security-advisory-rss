from flask import Flask, Response, jsonify, request
import os
import logging
import requests
import time
from feedgen.feed import FeedGenerator
from dateutil import parser
from datetime import datetime, timezone
from markupsafe import escape
import markdown

logger = logging.getLogger(__name__)

app = Flask(__name__)

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

def json_to_html(data_list):
    """Convert JSON data to HTML format for RSS content"""
    html_parts = []
    for item in data_list:
        if "packages" in item and item["packages"]:
            html_parts.append("<h3>Affected Packages:</h3><ul>")
            for pkg in item["packages"]:
                ecosystem = escape(pkg.get("package", {}).get("ecosystem", "Unknown"))
                name = escape(pkg.get("package", {}).get("name", "Unknown"))
                html_parts.append(f"<li><strong>{ecosystem}:</strong> {name}</li>")
            html_parts.append("</ul>")

        if "cvss" in item and item["cvss"]:
            cvss = item["cvss"]
            if cvss:
                score = cvss.get("score", "N/A")
                vector = cvss.get("vector_string", "N/A")
                html_parts.append(f"<h3>CVSS:</h3><p><strong>Score:</strong> {score}<br><strong>Vector:</strong> {vector}</p>")

    return "".join(html_parts)



def validate_github_token() -> bool:
    """Validate GitHub token by making a test request"""
    if not GITHUB_TOKEN or not GITHUB_TOKEN.startswith(('github_pat_')):
        return False
    
    # Optional: Test token with a simple API call
    try:
        headers = {"Authorization": f"Bearer {GITHUB_TOKEN}"}
        resp = requests.get("https://api.github.com/user", headers=headers, timeout=5)
        return resp.status_code == 200
    except:
        return False

def validate_query_params(params: dict) -> dict:
    """Validate and sanitize query parameters"""
    valid_params = {}
    
    # Validate severity
    if 'severity' in params:
        valid_severities = ['low', 'medium', 'high', 'critical']
        if params['severity'].lower() in valid_severities:
            valid_params['severity'] = params['severity'].lower()
    
    # Validate per_page
    if 'per_page' in params:
        try:
            per_page = int(params['per_page'])
            if 1 <= per_page <= 100:  # GitHub API limit
                valid_params['per_page'] = per_page
        except ValueError:
            pass
    
    return valid_params

def get_github_advisories(query_params: dict) -> list[dict[str, any]]:
    """Fetch GitHub security advisories from the API with query parameters"""
    if not validate_github_token():
        logger.error("Invalid or missing GitHub token")
        return []

    url = "https://api.github.com/advisories"

    # Build params from query_params, filtering out None values
    params = {}

    # Direct parameter mappings
    direct_params = [
        "ghsa_id",
        "type",
        "cve_id",
        "ecosystem",
        "severity",
        "cwes",
        "is_withdrawn",
        "affects",
        "published",
        "updated",
        "modified",
        "epss_percentage",
        "epss_percentile",
        "before",
        "after",
        "direction",
        "per_page",
        "sort",
    ]

    for param in direct_params:
        if param in query_params and query_params[param] is not None:
            params[param] = query_params[param]

    # Set default type if not specified
    if "type" not in params:
        params["type"] = "reviewed"

    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "User-Agent": "GHSA-RSS-Server/1.0",
    }

    # Retry logic with exponential backoff
    for attempt in range(3):
        try:
            logger.info(f"Fetching advisories from GitHub API (attempt {attempt + 1})")

            # The request is automatically cached by requests-cache
            resp = requests.get(
                url=url, headers=headers, params=params, timeout=(5,10)
            )
            resp.raise_for_status()

            # Check if response was from cache
            if hasattr(resp, "from_cache"):
                logger.info(f"Response from cache: {resp.from_cache}")

            # Check rate limit
            remaining = resp.headers.get("X-RateLimit-Remaining", "unknown")
            reset_time = resp.headers.get("X-RateLimit-Reset", "unknown")
            logger.info(
                f"GitHub API rate limit remaining: {remaining}, resets at: {reset_time}"
            )

            data = resp.json()

            advisories = [
                {
                    "cve": d.get("cve_id"),
                    "ghsa_id": d["ghsa_id"],
                    "summary": f'[{params.get("type", "reviewed")}] ' + d["summary"],
                    "content": d.get("description", ""),
                    "url": d["html_url"],
                    "severity": d.get("severity", "unknown"),
                    "packages": [p for p in d.get("vulnerabilities", [])],
                    "cvss": d.get("cvss"),
                    "pubdate": d.get("published_at"),
                }
                for d in data
            ]

            logger.info(f"Successfully fetched {len(advisories)} advisories")
            return advisories

        except requests.exceptions.Timeout:
            logger.warning(f"Request timeout (attempt {attempt + 1})")
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                logger.error("GitHub API rate limit exceeded")
                break
            elif e.response.status_code == 401:
                logger.error("GitHub API authentication failed")
                break
            else:
                logger.error(f"HTTP error: {e}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error: {e}")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")

        if attempt < 3 - 1:
            time.sleep(2**attempt)  # Exponential backoff

    logger.error("All retry attempts failed")
    return []


def generate_ghsa_rss(advisories: list[dict[str, str]], query_params: dict) -> str:
    """Generate RSS feed from advisories"""
    feed_type = query_params.get("type", "reviewed")

    # Generate dynamic URLs based on current request
    base_url = request.url_root.rstrip("/")
    feed_url = f"{base_url}/rss"

    # Add query parameters to the feed URL if they exist
    if query_params:
        query_string = "&".join(
            [f"{k}={v}" for k, v in query_params.items() if v is not None]
        )
        if query_string:
            feed_url += f"?{query_string}"

    fg = FeedGenerator()
    fg.id(feed_url)
    fg.title(f"GitHub Security Advisory - {feed_type.title()}")
    fg.link(href=feed_url, rel="alternate")
    fg.subtitle(
        "Security vulnerability database inclusive of CVEs and GitHub originated security advisories from the world of open source software."
    )
    fg.link(href=feed_url, rel="self")
    fg.language("en")
    fg.generator("GHSA-RSS-Server/1.0")
    fg.lastBuildDate(datetime.now(timezone.utc))

    for adv in advisories:
        severity = adv.get("severity", "").lower()
        # Include all severities, not just high/critical
        if severity and severity != "unknown":
            fe = fg.add_entry()
            fe.id(adv.get("url"))
            fe.guid(adv.get("url"))

            cve_part = f"{adv.get('cve')} " if adv.get("cve") else ""
            severity_part = (
                f"[{adv.get('severity', '').upper()}]" if adv.get("severity") else ""
            )
            title = f"{cve_part}{severity_part} {adv.get('summary', '').strip()}"
            fe.title(title)

            # Generate HTML content
            content_html = json_to_html(
                [{"packages": adv.get("packages", []), "cvss": adv.get("cvss")}]
            )

            if adv.get("content"):
                # Convert markdown to HTML
                md_content = markdown.markdown(adv.get("content"))
                content_html += f"<h3>Description:</h3>{md_content}"

            fe.content(content_html, type="CDATA")
            fe.link(href=adv.get("url"))

            # Add categories for severity, ecosystem, etc.
            # if adv.get("severity"):
            #     fe.category(term=adv["severity"].capitalize(), label="Severity")

            # if adv.get("packages"):
            #     for pkg in adv["packages"]:
            #         ecosystem = pkg.get("package", {}).get("ecosystem")
            #         if ecosystem:
            #             fe.category(term=ecosystem, label="Ecosystem")

            # Parse and set publication date
            if adv.get("pubdate"):
                try:
                    pub_date = parser.parse(adv.get("pubdate"))
                    # Ensure the datetime has timezone info
                    if pub_date.tzinfo is None:
                        pub_date = pub_date.replace(tzinfo=timezone.utc)
                    fe.pubDate(pub_date)
                except (ValueError, TypeError) as e:
                    logger.warning(f"Invalid date format for {adv.get('ghsa_id')}: {e}")

    return fg.rss_str(pretty=True)



@app.route('/')
def home():
    try:
        # Read the README.md file
        with open('../README.md', 'r', encoding='utf-8') as f:
            readme_content = f.read()
        
        # Convert markdown to HTML
        html_content = markdown.markdown(readme_content)
        
        # Wrap in basic HTML structure with SEO tags
        html_page = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            
            <!-- SEO Meta Tags -->
            <title>GitHub Security Advisory RSS Feed - Real-time Security Vulnerability Updates</title>
            <meta name="description" content="Get real-time RSS feeds of GitHub Security Advisories with customizable filters. Monitor CVEs, security vulnerabilities, and malware advisories across all ecosystems like npm, pip, maven, and more.">
            <meta name="keywords" content="github security advisory, CVE, security vulnerabilities, RSS feed, security monitoring, vulnerability alerts, npm security, pip security, maven security, cybersecurity, GHSA">
            <meta name="author" content="GitHub Security Advisory RSS Service">
            <meta name="robots" content="index, follow">
            <link rel="canonical" href="https://github-security-advisory-rss.vercel.app/">
            
            <!-- Open Graph Meta Tags -->
            <meta property="og:title" content="GitHub Security Advisory RSS Feed - Real-time Security Updates">
            <meta property="og:description" content="Get real-time RSS feeds of GitHub Security Advisories with customizable filters for CVEs and security vulnerabilities.">
            <meta property="og:url" content="https://github-security-advisory-rss.vercel.app/">
            <meta property="og:type" content="website">
            <meta property="og:site_name" content="GitHub Security Advisory RSS">
            <meta property="og:locale" content="en_US">
            
            <!-- Twitter Card Meta Tags -->
            <meta name="twitter:card" content="summary_large_image">
            <meta name="twitter:title" content="GitHub Security Advisory RSS Feed">
            <meta name="twitter:description" content="Real-time RSS feeds for GitHub Security Advisories with customizable filters for CVEs and vulnerabilities.">
            <meta name="twitter:creator" content="@github">
            
            <!-- Additional SEO Tags -->
            <meta name="theme-color" content="#3498db">
            <link rel="alternate" type="application/rss+xml" title="GitHub Security Advisory RSS Feed" href="https://github-security-advisory-rss.vercel.app/rss">
            
            <!-- Structured Data -->
            <script type="application/ld+json">
            {{
                "@context": "https://schema.org",
                "@type": "WebApplication",
                "name": "GitHub Security Advisory RSS Feed",
                "description": "Real-time RSS feed service for GitHub Security Advisories with customizable filtering options",
                "url": "https://github-security-advisory-rss.vercel.app/",
                "applicationCategory": "SecurityApplication",
                "operatingSystem": "Web",
                "offers": {{
                    "@type": "Offer",
                    "price": "0",
                    "priceCurrency": "USD"
                }},
                "creator": {{
                    "@type": "Person",
                    "name": "GitHub Security Advisory RSS Service"
                }},
                "featureList": [
                    "Real-time GitHub Security Advisory RSS feeds",
                    "Customizable filtering by severity, ecosystem, CVE ID",
                    "Support for all GitHub API parameters",
                    "Free deployment on Vercel",
                    "RESTful API integration"
                ]
            }}
            </script>
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 800px;
                    margin: 0 auto;
                    padding: 20px;
                    background-color: #f8f9fa;
                }}
                .container {{
                    background: white;
                    padding: 30px;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }}
                h1, h2, h3 {{
                    color: #2c3e50;
                }}
                h1 {{
                    border-bottom: 2px solid #3498db;
                    padding-bottom: 10px;
                }}
                code {{
                    background-color: #f4f4f4;
                    padding: 2px 4px;
                    border-radius: 3px;
                    font-family: 'Monaco', 'Consolas', monospace;
                }}
                pre {{
                    background-color: #f4f4f4;
                    padding: 15px;
                    border-radius: 5px;
                    overflow-x: auto;
                    border-left: 4px solid #3498db;
                }}
                a {{
                    color: #3498db;
                    text-decoration: none;
                }}
                a:hover {{
                    text-decoration: underline;
                }}
                .badge {{
                    display: inline-block;
                    margin-bottom: 20px;
                }}
                ul {{
                    padding-left: 20px;
                }}
                li {{
                    margin-bottom: 5px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                {html_content}
            </div>
        </body>
        </html>
        """
        
        return html_page
        
    except Exception as e:
        logger.error(f"Error reading README: {e}")
        return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>GitHub Security Advisory RSS Feed - Real-time Security Vulnerability Updates</title>
            <meta name="description" content="Get real-time RSS feeds of GitHub Security Advisories with customizable filters for CVEs and security vulnerabilities.">
            <meta name="robots" content="index, follow">
            <link rel="canonical" href="https://github-security-advisory-rss.vercel.app/">
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    max-width: 800px;
                    margin: 0 auto;
                    padding: 20px;
                    background-color: #f8f9fa;
                }}
                .container {{
                    background: white;
                    padding: 30px;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>GitHub Security Advisory RSS Feed</h1>
                <p>A Flask-based RSS feed service that converts GitHub Security Advisories into RSS format.</p>
                <p><strong>RSS Feed:</strong> <a href="/rss">/rss</a></p>
                <p><strong>Health Check:</strong> <a href="/health">/health</a></p>
            </div>
        </body>
        </html>
        """

@app.route('/about')
def about():
    return 'About'

@app.route('/rss')
def rss():
    query_params = request.args.to_dict()
    advisories = get_github_advisories(query_params)
    
    if not advisories:
        return Response("No advisories found", status=404)
    
    rss_feed = generate_ghsa_rss(advisories, query_params)
    response = Response(rss_feed, mimetype='application/rss+xml')
    response.headers['Cache-Control'] = 'public, s-maxage=600'
    return response

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {error}")
    return jsonify({"error": "Internal server error"}), 500

@app.route('/health')
def health():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "github_token_valid": validate_github_token()
    })