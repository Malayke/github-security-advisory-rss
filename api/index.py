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

def json_to_html(advisory_data):
    """Convert advisory data to HTML format for RSS content"""
    html_parts = []
    
    # Severity and CVE Information
    if advisory_data.get("severity"):
        severity = advisory_data["severity"].upper()
        html_parts.append(f"<h3>Severity: {severity}</h3>")
    
    if advisory_data.get("cve"):
        html_parts.append(f"<h3>CVE ID: {advisory_data['cve']}</h3>")
    
    if advisory_data.get("ghsa_id"):
        html_parts.append(f"<h3>GHSA ID: {advisory_data['ghsa_id']}</h3>")
    
    # Affected Packages and Version Information
    if advisory_data.get("vulnerabilities") and advisory_data["vulnerabilities"]:
        html_parts.append("<h3>Affected Packages:</h3>")
        for vuln in advisory_data["vulnerabilities"]:
            if "package" in vuln:
                pkg = vuln["package"]
                ecosystem = escape(pkg.get("ecosystem", "Unknown"))
                name = escape(pkg.get("name", "Unknown"))
                html_parts.append(f"<h4>{ecosystem}: {name}</h4>")
                
                if vuln.get("vulnerable_version_range"):
                    html_parts.append(f"<p><strong>Vulnerable Range:</strong> {escape(vuln['vulnerable_version_range'])}</p>")
                
                if vuln.get("first_patched_version"):
                    html_parts.append(f"<p><strong>First Patched Version:</strong> {escape(vuln['first_patched_version'])}</p>")
                
                html_parts.append("<br>")
    
    # CVSS Information
    if advisory_data.get("cvss_severities"):
        html_parts.append("<h3>CVSS Scores:</h3>")
        cvss_data = advisory_data["cvss_severities"]
        
        if cvss_data.get("cvss_v3"):
            cvss_v3 = cvss_data["cvss_v3"]
            score = cvss_v3.get("score", "N/A")
            vector = cvss_v3.get("vector_string", "N/A")
            html_parts.append(f"<p><strong>CVSS v3.1 Score:</strong> {score}<br><strong>Vector:</strong> {escape(vector)}</p>")
        
        if cvss_data.get("cvss_v4"):
            cvss_v4 = cvss_data["cvss_v4"]
            score = cvss_v4.get("score", "N/A")
            vector = cvss_v4.get("vector_string", "N/A")
            html_parts.append(f"<p><strong>CVSS v4.0 Score:</strong> {score}<br><strong>Vector:</strong> {escape(vector)}</p>")
    elif advisory_data.get("cvss"):
        # Fallback to old CVSS format
        cvss = advisory_data["cvss"]
        score = cvss.get("score", "N/A")
        vector = cvss.get("vector_string", "N/A")
        html_parts.append(f"<h3>CVSS:</h3><p><strong>Score:</strong> {score}<br><strong>Vector:</strong> {escape(vector)}</p>")
    
    # CWE Information
    if advisory_data.get("cwes") and advisory_data["cwes"]:
        html_parts.append("<h3>CWE (Common Weakness Enumeration):</h3><ul>")
        for cwe in advisory_data["cwes"]:
            cwe_id = cwe.get("cwe_id", "Unknown")
            cwe_name = escape(cwe.get("name", "Unknown"))
            html_parts.append(f"<li><strong>{cwe_id}:</strong> {cwe_name}</li>")
        html_parts.append("</ul>")
    
    # References
    if advisory_data.get("references") and advisory_data["references"]:
        html_parts.append("<h3>References:</h3><ul>")
        for ref in advisory_data["references"]:
            html_parts.append(f"<li><a href='{escape(ref)}' target='_blank'>{escape(ref)}</a></li>")
        html_parts.append("</ul>")
    
    # Identifiers
    if advisory_data.get("identifiers") and advisory_data["identifiers"]:
        html_parts.append("<h3>Identifiers:</h3><ul>")
        for identifier in advisory_data["identifiers"]:
            id_type = identifier.get("type", "Unknown")
            id_value = identifier.get("value", "Unknown")
            html_parts.append(f"<li><strong>{id_type}:</strong> {escape(id_value)}</li>")
        html_parts.append("</ul>")
    
    # Timestamps
    html_parts.append("<h3>Timeline:</h3>")
    if advisory_data.get("published_at"):
        try:
            pub_date = parser.parse(advisory_data["published_at"])
            html_parts.append(f"<p><strong>Published:</strong> {pub_date.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>")
        except (ValueError, TypeError):
            html_parts.append(f"<p><strong>Published:</strong> {escape(advisory_data['published_at'])}</p>")
    
    if advisory_data.get("updated_at"):
        try:
            update_date = parser.parse(advisory_data["updated_at"])
            html_parts.append(f"<p><strong>Updated:</strong> {update_date.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>")
        except (ValueError, TypeError):
            html_parts.append(f"<p><strong>Updated:</strong> {escape(advisory_data['updated_at'])}</p>")
    
    if advisory_data.get("github_reviewed_at"):
        try:
            review_date = parser.parse(advisory_data["github_reviewed_at"])
            html_parts.append(f"<p><strong>GitHub Reviewed:</strong> {review_date.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>")
        except (ValueError, TypeError):
            html_parts.append(f"<p><strong>GitHub Reviewed:</strong> {escape(advisory_data['github_reviewed_at'])}</p>")
    
    if advisory_data.get("nvd_published_at"):
        try:
            nvd_date = parser.parse(advisory_data["nvd_published_at"])
            html_parts.append(f"<p><strong>NVD Published:</strong> {nvd_date.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>")
        except (ValueError, TypeError):
            html_parts.append(f"<p><strong>NVD Published:</strong> {escape(advisory_data['nvd_published_at'])}</p>")
    
    # Source Code Location
    if advisory_data.get("source_code_location"):
        html_parts.append(f"<h3>Source Code:</h3><p><a href='{escape(advisory_data['source_code_location'])}' target='_blank'>{escape(advisory_data['source_code_location'])}</a></p>")

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
                    # Additional fields for enhanced RSS content
                    "vulnerabilities": d.get("vulnerabilities", []),
                    "cvss_severities": d.get("cvss_severities", {}),
                    "cwes": d.get("cwes", []),
                    "references": d.get("references", []),
                    "identifiers": d.get("identifiers", []),
                    "published_at": d.get("published_at"),
                    "updated_at": d.get("updated_at"),
                    "github_reviewed_at": d.get("github_reviewed_at"),
                    "nvd_published_at": d.get("nvd_published_at"),
                    "source_code_location": d.get("source_code_location"),
                    "withdrawn_at": d.get("withdrawn_at"),
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
    fg.title(f"GitHub Security Advisory RSS Feed - {feed_type.title()}")
    fg.link(href=feed_url, rel="alternate")
    fg.subtitle(
        "Security vulnerability database inclusive of CVEs and GitHub originated security advisories from the world of open source software. " +
        "feedId:163880769874497536+userId:46228940824907776"
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
                adv
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
        # Try multiple paths to find README.md
        readme_paths = [
            '../README.md',  # Original path
            'README.md',     # Current directory
            '/var/task/README.md',  # Vercel serverless path
            os.path.join(os.path.dirname(os.path.dirname(__file__)), 'README.md')  # Relative to this file
        ]
        
        readme_content = None
        for path in readme_paths:
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    readme_content = f.read()
                    break
            except FileNotFoundError:
                continue
        
        if readme_content is None:
            raise FileNotFoundError("README.md not found in any expected location")
        
        # Convert markdown to HTML with extensions for proper code block handling
        html_content = markdown.markdown(
            readme_content,
            extensions=['fenced_code', 'codehilite', 'tables', 'nl2br']
        )
        
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
            <link rel="icon" type="image/svg+xml" href="/favicon.ico">
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
                    background-color: #f8f8f8;
                    padding: 15px;
                    border-radius: 5px;
                    overflow-x: auto;
                    border-left: 4px solid #3498db;
                    margin: 15px 0;
                }}
                pre code {{
                    background-color: transparent;
                    padding: 0;
                    border-radius: 0;
                    font-size: 0.9em;
                    color: #333;
                }}
                .codehilite {{
                    background-color: #f8f8f8;
                    border-radius: 5px;
                    margin: 15px 0;
                }}
                .codehilite pre {{
                    margin: 0;
                    border-left: none;
                    background-color: transparent;
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
        
        response = Response(html_page, mimetype='text/html')
        response.headers['Cache-Control'] = 'public, s-maxage=600'
        return response
        
    except Exception as e:
        logger.error(f"Error reading README: {e}")
        error_page = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>GitHub Security Advisory RSS Feed - Real-time Security Vulnerability Updates</title>
            <meta name="description" content="Get real-time RSS feeds of GitHub Security Advisories with customizable filters for CVEs and security vulnerabilities.">
            <meta name="robots" content="index, follow">
            <link rel="canonical" href="https://github-security-advisory-rss.vercel.app/">
            <link rel="icon" type="image/svg+xml" href="/favicon.ico">
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
        
        response = Response(error_page, mimetype='text/html')
        response.headers['Cache-Control'] = 'public, s-maxage=600'
        return response

@app.route('/about')
def about():
    return 'About'

@app.route('/favicon.ico')
def favicon():
    # Simple security shield icon as SVG favicon
    svg_icon = '''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#3498db">
        <path d="M12 2L3 7v4c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z"/>
        <path d="M10 17l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z" fill="white"/>
    </svg>'''
    
    # Convert SVG to data URI
    import base64
    svg_bytes = svg_icon.encode('utf-8')
    svg_b64 = base64.b64encode(svg_bytes).decode('utf-8')
    
    response = Response(svg_bytes, mimetype='image/svg+xml')
    response.headers['Cache-Control'] = 'public, max-age=86400'  # Cache for 1 day
    return response

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