#!/usr/bin/env python3
"""
navarro.py – OSINT username checker (25+ reliable platforms)
by Noobosaurus R3x
Usage: 
    python3 navarro.py <username>
    python3 navarro.py --list usernames.txt
    python3 navarro.py <username> --export results.json

Requires: requests, rich
"""
import sys
import re
import json
import requests
import time
import random
import argparse
import os
import atexit
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Callable, Tuple, List, Optional
from enum import Enum
from collections import defaultdict
from functools import wraps

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    RICH = True
except ImportError:
    RICH = False

# User agent that works with Facebook
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/125.0.0.0"}

# User agents for rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
]

TIMEOUT = 8
RATE_LIMIT_FILE = Path.home() / ".navarro_rate_limits.json"

class CheckResult(Enum):
    """Result types for platform checks"""
    FOUND = "found"
    NOT_FOUND = "not_found"
    NETWORK_ERROR = "network_error"
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    UNKNOWN_ERROR = "unknown_error"

class RateLimiter:
    """Rate limiter with persistence"""
    def __init__(self):
        # Fixed: Create datetime objects directly, not strings
        self.limits = defaultdict(lambda: {"count": 0, "reset_time": datetime.now()})
        self.delays = defaultdict(lambda: 0.5)  # Base delay per platform
        self.last_request = defaultdict(lambda: datetime.now())
        self.load_limits()
    
    def load_limits(self):
        """Load saved rate limits from disk"""
        if RATE_LIMIT_FILE.exists():
            try:
                with open(RATE_LIMIT_FILE, 'r') as f:
                    saved_data = json.load(f)
                    # Convert ISO format strings back to datetime objects with error handling
                    for platform, limit_data in saved_data.get('limits', {}).items():
                        try:
                            reset_time = datetime.fromisoformat(limit_data.get("reset_time", datetime.now().isoformat()))
                        except (ValueError, TypeError):
                            reset_time = datetime.now()
                        
                        self.limits[platform] = {
                            "count": limit_data.get("count", 0),
                            "reset_time": reset_time
                        }
                    self.delays.update(saved_data.get('delays', {}))
            except Exception:
                pass
    
    def save_limits(self):
        """Save rate limits to disk"""
        try:
            # Convert datetime objects to ISO format for JSON serialization
            limits_to_save = {}
            for platform, limit_data in self.limits.items():
                limits_to_save[platform] = {
                    "count": limit_data["count"],
                    "reset_time": limit_data["reset_time"].isoformat() if isinstance(limit_data["reset_time"], datetime) else limit_data["reset_time"]
                }
            
            with open(RATE_LIMIT_FILE, 'w') as f:
                json.dump({
                    'limits': limits_to_save,
                    'delays': dict(self.delays)
                }, f, indent=2)
        except Exception:
            pass
    
    def should_wait(self, platform: str) -> float:
        """Calculate wait time for platform"""
        now = datetime.now()
        
        # Check if we're rate limited - handle both datetime objects and strings
        reset_time = self.limits[platform]["reset_time"]
        if isinstance(reset_time, str):
            try:
                reset_time = datetime.fromisoformat(reset_time)
            except (ValueError, TypeError):
                reset_time = now  # If parsing fails, assume no wait needed
        
        if reset_time > now:
            return (reset_time - now).total_seconds()
        
        # Calculate adaptive delay
        time_since_last = (now - self.last_request[platform]).total_seconds()
        if time_since_last < self.delays[platform]:
            return self.delays[platform] - time_since_last
        
        return 0
    
    def record_request(self, platform: str, was_rate_limited: bool = False):
        """Record a request and update delays"""
        now = datetime.now()
        self.last_request[platform] = now
        
        if was_rate_limited:
            # Increase delay and set reset time
            self.delays[platform] = min(self.delays[platform] * 2, 30)  # Max 30s delay
            self.limits[platform]["reset_time"] = now + timedelta(seconds=60)
        else:
            # Gradually decrease delay if successful
            self.delays[platform] = max(self.delays[platform] * 0.9, 0.5)  # Min 0.5s delay
        
        self.save_limits()

class SessionManager:
    """Manage persistent sessions"""
    def __init__(self):
        self.sessions = {}
        self._user_agent_index = 0
    
    def get_session(self, platform: str) -> requests.Session:
        """Get or create a session for a platform"""
        if platform not in self.sessions:
            session = requests.Session()
            # Connection pooling
            adapter = requests.adapters.HTTPAdapter(
                pool_connections=10,
                pool_maxsize=10,
                max_retries=3
            )
            session.mount('http://', adapter)
            session.mount('https://', adapter)
            
            # Set random user agent
            session.headers.update(self._get_next_user_agent())
            self.sessions[platform] = session
        
        return self.sessions[platform]
    
    def _get_next_user_agent(self) -> Dict[str, str]:
        """Rotate through user agents"""
        ua = USER_AGENTS[self._user_agent_index % len(USER_AGENTS)]
        self._user_agent_index += 1
        return {"User-Agent": ua}
    
    def close_all(self):
        """Close all sessions"""
        for session in self.sessions.values():
            session.close()
        self.sessions.clear()

# Global instances
rate_limiter = RateLimiter()
session_manager = SessionManager()

# Register cleanup on exit
atexit.register(session_manager.close_all)

def handle_request_errors(func):
    """Decorator to handle common request errors and return appropriate CheckResult"""
    @wraps(func)
    def wrapper(username):
        try:
            return func(username)
        except requests.exceptions.Timeout:
            return CheckResult.TIMEOUT
        except requests.exceptions.ConnectionError:
            return CheckResult.NETWORK_ERROR
        except requests.exceptions.RequestException:
            return CheckResult.NETWORK_ERROR
        except Exception:
            return CheckResult.UNKNOWN_ERROR
    return wrapper

def check_rate_limit(response):
    """Check if response indicates rate limiting"""
    if response.status_code == 429:
        return True
    
    if 'retry-after' in response.headers:
        return True
    
    remaining_headers = ['x-ratelimit-remaining', 'x-rate-limit-remaining']
    for header in remaining_headers:
        if header in response.headers:
            try:
                remaining = int(response.headers.get(header, '1'))
                if remaining == 0:
                    return True
            except ValueError:
                pass
    
    rate_limit_patterns = [
        "rate limit exceeded",
        "too many requests",
        "429 too many requests",
    ]
    
    response_text = response.text.lower()
    return any(pattern in response_text for pattern in rate_limit_patterns)

# Platform check functions
@handle_request_errors
def github(username):
    session = session_manager.get_session("github")
    url = f"https://github.com/{username}"
    r = session.get(url, timeout=TIMEOUT)
    
    if check_rate_limit(r):
        rate_limiter.record_request("github", was_rate_limited=True)
        return CheckResult.RATE_LIMITED
    
    rate_limiter.record_request("github")
    
    if r.status_code == 200 and "Not Found" not in r.text:
        return CheckResult.FOUND
    return CheckResult.NOT_FOUND

@handle_request_errors
def gitlab(username):
    session = session_manager.get_session("gitlab")
    url = f"https://gitlab.com/{username}"
    r = session.get(url, timeout=TIMEOUT)
    
    if check_rate_limit(r):
        rate_limiter.record_request("gitlab", was_rate_limited=True)
        return CheckResult.RATE_LIMITED
    
    rate_limiter.record_request("gitlab")
    
    if r.status_code == 200 and re.search(r'<h1>[\w\-]+', r.text):
        return CheckResult.FOUND
    return CheckResult.NOT_FOUND

@handle_request_errors
def reddit(username):
    session = session_manager.get_session("reddit")
    url = f"https://www.reddit.com/user/{username}"
    r = session.get(url, timeout=TIMEOUT)
    
    if check_rate_limit(r):
        rate_limiter.record_request("reddit", was_rate_limited=True)
        return CheckResult.RATE_LIMITED
    
    rate_limiter.record_request("reddit")
    
    if r.status_code == 200 and not re.search(r"nobody on Reddit goes by that name", r.text):
        return CheckResult.FOUND
    return CheckResult.NOT_FOUND

@handle_request_errors
def linktree(username):
    session = session_manager.get_session("linktree")
    url = f"https://linktr.ee/{username}"
    r = session.get(url, timeout=TIMEOUT)
    
    if check_rate_limit(r):
        rate_limiter.record_request("linktree", was_rate_limited=True)
        return CheckResult.RATE_LIMITED
    
    rate_limiter.record_request("linktree")
    
    if r.status_code == 200:
        if "Sorry, this page isn't available" in r.text or "404" in r.text:
            return CheckResult.NOT_FOUND
        if username.lower() in r.text.lower() or "linktr.ee" in r.text.lower():
            return CheckResult.FOUND
    return CheckResult.NOT_FOUND

@handle_request_errors
def instagram(username):
    session = session_manager.get_session("instagram")
    url = f"https://www.instagram.com/{username}/"
    r = session.get(url, timeout=TIMEOUT)
    
    if check_rate_limit(r):
        rate_limiter.record_request("instagram", was_rate_limited=True)
        return CheckResult.RATE_LIMITED
    
    rate_limiter.record_request("instagram")
    
    if r.status_code != 200:
        return CheckResult.NOT_FOUND
    
    text = r.text
    
    if '"user":null' in text or re.search(r'"user":\s*{\s*}', text):
        return CheckResult.NOT_FOUND
    
    not_found_indicators = [
        "isn't available",
        "not available",
        "page isn't available", 
        "profile isn't available",
        "The link may be broken",
        "profile may have been removed",
        '"challengeType":"UNKNOWN"',
        '"viewer":null',
    ]
    
    text_lower = text.lower()
    for indicator in not_found_indicators:
        if indicator.lower() in text_lower:
            return CheckResult.NOT_FOUND
    
    if "/accounts/login/" in r.url:
        return CheckResult.NOT_FOUND
    
    user_data_patterns = [
        f'"username":"{username}"',
        f'"alternateName":"@{username}"',
        '"edge_followed_by":{"count":',
        '"profile_pic_url":"http',
        '"is_private":',
        '"media_count":',
    ]
    
    if any(pattern in text for pattern in user_data_patterns):
        return CheckResult.FOUND
    
    return CheckResult.NOT_FOUND

@handle_request_errors
def facebook(username: str) -> CheckResult:
    """
    Return CheckResult.FOUND if a Facebook profile/page exists, otherwise CheckResult.NOT_FOUND.
    Facebook checks are really a pain in the ass.
    Strategy:
    • Try Graph API first (fastest when it works)
    • For usernames with periods/hyphens, use direct URL check since Graph API often fails
    • Use negative detection (look for "not found" indicators) rather than positive detection
    """
    session = session_manager.get_session("facebook")
    session.headers.update(UA)

    def _graph_ok(slug: str) -> bool:
        url = f"https://graph.facebook.com/{slug}/picture?type=normal&redirect=false"
        try:
            r = session.get(url, timeout=TIMEOUT)
            if r.status_code == 200:
                json_data = r.json()
                data = json_data.get("data")
                # Must have actual picture data
                return (
                    isinstance(data, dict) and 
                    data.get("url") and 
                    data.get("width") and 
                    "facebook.com" in data.get("url", "")
                )
            return False
        except (ValueError, requests.RequestException):
            return False

    def _direct_check(slug: str) -> bool:
        url = f"https://www.facebook.com/{slug}"
        try:
            r = session.get(url, timeout=TIMEOUT)
            if r.status_code != 200:
                return False
            
            text = r.text
            
            # Facebook shows specific error messages for non-existent profiles
            # Use negative detection - if we DON'T see these errors, profile likely exists
            definite_not_found_indicators = [
                "This content isn't available right now",
                "This page isn't available",
                "Page Not Found",
                "Content Not Found", 
                "The page you requested cannot be displayed",
                "Sorry, this page isn't available",
                '"error":{"message":"Unsupported get request',
                '"error":{"message":"(#803)',  # Facebook error code
                '"error":{"message":"Invalid username',
                "profile unavailable",
                "Page not found",
            ]
            
            # If we see definite "not found" indicators, return False
            text_lower = text.lower()
            for indicator in definite_not_found_indicators:
                if indicator.lower() in text_lower:
                    return False
            
            # If we reach here and got 200, check for some basic Facebook page structure
            # These are very basic indicators that appear on real Facebook pages
            basic_facebook_indicators = [
                'id="facebook"',           # Facebook's main div ID
                'property="og:site_name" content="Facebook"',  # Open Graph site name
                'name="twitter:site" content="@facebook"',     # Twitter card
                '<title>',                 # Has a title tag (basic)
                'www.facebook.com',        # Contains Facebook domain
            ]
            
            # Must have some basic Facebook page structure
            has_basic_structure = any(indicator in text for indicator in basic_facebook_indicators)
            
            if not has_basic_structure:
                return False
            
            # Additional check: if the URL in the response contains the username, it's likely real
            # Facebook often includes the actual profile URL in meta tags
            url_indicators = [
                f'facebook.com/{slug}',
                f'content="https://www.facebook.com/{slug}"',
                f'content="https://facebook.com/{slug}"',
            ]
            
            has_url_match = any(indicator in text for indicator in url_indicators)
            
            # For usernames with special characters, be more lenient
            if any(char in slug for char in '.-_'):
                # If no explicit "not found" message and has basic FB structure, probably exists
                return has_basic_structure
            else:
                # For normal usernames, require URL match or explicit profile indicators
                return has_url_match or '"userID":"' in text or '"pageID":"' in text
            
        except requests.RequestException:
            return False

    rate_limiter.record_request("facebook")

    # 1. Try Graph API with original username (works for most usernames without periods)
    if _graph_ok(username):
        return CheckResult.FOUND

    # 2. Try Graph API with cleaned username (Facebook sometimes normalizes)
    cleaned = re.sub(r"[.\-]", "", username)
    if cleaned != username and _graph_ok(cleaned):
        return CheckResult.FOUND

    # 3. For usernames with periods/hyphens or when Graph API fails, use direct check
    if any(char in username for char in '.-') or True:  # Always fallback to direct check
        if _direct_check(username):
            return CheckResult.FOUND
        # Also try cleaned version
        if cleaned != username and _direct_check(cleaned):
            return CheckResult.FOUND

    return CheckResult.NOT_FOUND

@handle_request_errors
def tiktok(username):
    session = session_manager.get_session("tiktok")
    url = f"https://www.tiktok.com/@{username}"
    r = session.get(url, timeout=TIMEOUT)
    
    if check_rate_limit(r):
        rate_limiter.record_request("tiktok", was_rate_limited=True)
        return CheckResult.RATE_LIMITED
    
    rate_limiter.record_request("tiktok")
    
    if r.status_code != 200:
        return CheckResult.NOT_FOUND
    
    user_data_patterns = [
        f'"uniqueId":"{username}"',
        f'"@{username}"',
        '"__typename":"User"',
        '"followerCount":',
        '"videoCount":',
    ]
    
    not_found_markers = [
        "Couldn't find this account",
        "Impossible de trouver ce compte",
        '<h1>404</h1>',
        '"statusCode":10202',
    ]
    
    text = r.text
    
    for marker in not_found_markers:
        if marker in text:
            return CheckResult.NOT_FOUND
    
    if any(pattern in text for pattern in user_data_patterns):
        return CheckResult.FOUND
    
    return CheckResult.NOT_FOUND

@handle_request_errors
def linkedin(username):
    session = session_manager.get_session("linkedin")
    url = f"https://www.linkedin.com/in/{username}"
    r = session.get(url, timeout=TIMEOUT)
    
    if check_rate_limit(r):
        rate_limiter.record_request("linkedin", was_rate_limited=True)
        return CheckResult.RATE_LIMITED
    
    rate_limiter.record_request("linkedin")
    
    if r.status_code != 200:
        return CheckResult.NOT_FOUND
    
    profile_markers = [
        '"profile":',
        '"publicIdentifier":"',
        '"firstName":"',
        '"lastName":"',
        '"headline":"',
    ]
    
    if any(marker in r.text for marker in profile_markers):
        return CheckResult.FOUND
    
    return CheckResult.NOT_FOUND

@handle_request_errors
def pinterest(username):
    session = session_manager.get_session("pinterest")
    url = f"https://www.pinterest.com/{username}/"
    r = session.get(url, timeout=TIMEOUT)
    
    if check_rate_limit(r):
        rate_limiter.record_request("pinterest", was_rate_limited=True)
        return CheckResult.RATE_LIMITED
    
    rate_limiter.record_request("pinterest")
    
    if r.status_code != 200:
        return CheckResult.NOT_FOUND
    
    profile_markers = [
        '"@type":"Person"',
        '"profileOwner":',
        f'"username":"{username}"',
        '"pinterestapp:followers"',
    ]
    
    not_found_markers = [
        "User not found",
        "Sorry! We couldn't find",
        "Oops! We couldn't find",
    ]
    
    text = r.text
    
    for marker in not_found_markers:
        if marker in text:
            return CheckResult.NOT_FOUND
    
    if any(marker in text for marker in profile_markers):
        return CheckResult.FOUND
    
    return CheckResult.NOT_FOUND

@handle_request_errors
def pastebin(username):
    session = session_manager.get_session("pastebin")
    url = f"https://pastebin.com/u/{username}"
    r = session.get(url, timeout=TIMEOUT)
    
    if check_rate_limit(r):
        rate_limiter.record_request("pastebin", was_rate_limited=True)
        return CheckResult.RATE_LIMITED
    
    rate_limiter.record_request("pastebin")
    
    if r.status_code == 200 and "pastebin.com" in r.text.lower():
        return CheckResult.FOUND
    return CheckResult.NOT_FOUND

@handle_request_errors
def telegram(username):
    """Alternative Telegram check using their preview API"""
    session = session_manager.get_session("telegram")
    
    # First try the regular t.me URL
    url = f"https://t.me/{username}"
    r = session.get(url, timeout=TIMEOUT, allow_redirects=True)
    
    if check_rate_limit(r):
        rate_limiter.record_request("telegram", was_rate_limited=True)
        return CheckResult.RATE_LIMITED
    
    rate_limiter.record_request("telegram")
    
    # Check final URL after redirects
    # Invalid usernames often redirect to telegram.org
    if r.url.startswith('https://telegram.org'):
        return CheckResult.NOT_FOUND
    
    if r.status_code == 404:
        return CheckResult.NOT_FOUND
    
    if r.status_code == 200:
        text = r.text
        
        # Look for structured data
        if '"@type":"Person"' in text or '"@type":"Organization"' in text:
            return CheckResult.FOUND
        
        # Check for preview image which indicates valid profile
        if 'og:image' in text and 'cdn' in text:
            # Make sure it's not the default Telegram logo
            if 'telegram_logo' not in text and 'default' not in text:
                return CheckResult.FOUND
        
        # Valid profiles have certain meta tags
        has_title = 'property="og:title"' in text or 'name="twitter:title"' in text
        has_description = 'property="og:description"' in text or 'name="twitter:description"' in text
        
        if has_title and has_description and username.lower() in text.lower():
            return CheckResult.FOUND
    
    return CheckResult.NOT_FOUND

@handle_request_errors
def snapchat(username):
    session = session_manager.get_session("snapchat")
    url = f"https://www.snapchat.com/add/{username}"
    r = session.get(url, timeout=TIMEOUT)
    
    if check_rate_limit(r):
        rate_limiter.record_request("snapchat", was_rate_limited=True)
        return CheckResult.RATE_LIMITED
    
    rate_limiter.record_request("snapchat")
    
    if r.status_code == 200 and 'Snapcode' in r.text:
        return CheckResult.FOUND
    return CheckResult.NOT_FOUND

@handle_request_errors
def strava(username):
    session = session_manager.get_session("strava")
    url = f"https://www.strava.com/athletes/{username}"
    r = session.get(url, timeout=TIMEOUT)
    
    if check_rate_limit(r):
        rate_limiter.record_request("strava", was_rate_limited=True)
        return CheckResult.RATE_LIMITED
    
    rate_limiter.record_request("strava")
    
    if r.status_code == 200 and (username in r.text or "Athlete" in r.text):
        return CheckResult.FOUND
    return CheckResult.NOT_FOUND

@handle_request_errors
def threads(username):
    session = session_manager.get_session("threads")
    url = f"https://www.threads.net/@{username}"
    r = session.get(url, timeout=TIMEOUT)
    
    if check_rate_limit(r):
        rate_limiter.record_request("threads", was_rate_limited=True)
        return CheckResult.RATE_LIMITED
    
    rate_limiter.record_request("threads")
    
    if r.status_code != 200:
        return CheckResult.NOT_FOUND
    
    profile_markers = [
        '"user":{"pk"',
        '"profile_pic_url"',
        f'"username":"{username}"',
        '"thread_items"',
    ]
    
    not_found_markers = [
        "Sorry, this page isn't available",
        "User not found",
    ]
    
    text = r.text
    
    for marker in not_found_markers:
        if marker in text:
            return CheckResult.NOT_FOUND
    
    if any(marker in text for marker in profile_markers):
        return CheckResult.FOUND
    
    return CheckResult.NOT_FOUND

@handle_request_errors
def mastodon(username):
    session = session_manager.get_session("mastodon")
    
    for instance in ["mastodon.social", "hachyderm.io", "infosec.exchange"]:
        url = f"https://{instance}/@{username}"
        try:
            r = session.get(url, timeout=TIMEOUT)
            
            if check_rate_limit(r):
                rate_limiter.record_request("mastodon", was_rate_limited=True)
                return CheckResult.RATE_LIMITED
            
            if r.status_code == 200 and (f"@{username.lower()}" in r.text.lower() or username.lower() in r.text.lower()):
                rate_limiter.record_request("mastodon")
                return CheckResult.FOUND
                
        except requests.exceptions.Timeout:
            continue
        except:
            continue
    
    rate_limiter.record_request("mastodon")
    return CheckResult.NOT_FOUND

@handle_request_errors
def bluesky(username):
    session = session_manager.get_session("bluesky")
    candidates = [f"{username}.bsky.social", username]
    
    for user in candidates:
        url = f"https://bsky.app/profile/{user}"
        try:
            r = session.get(url, timeout=TIMEOUT)
            
            if check_rate_limit(r):
                rate_limiter.record_request("bluesky", was_rate_limited=True)
                return CheckResult.RATE_LIMITED
            
            if r.status_code == 200 and (username in r.text or "Posts" in r.text):
                rate_limiter.record_request("bluesky")
                return CheckResult.FOUND
        except:
            continue
    
    rate_limiter.record_request("bluesky")
    return CheckResult.NOT_FOUND

@handle_request_errors
def spotify(username):
    session = session_manager.get_session("spotify")
    url = f"https://open.spotify.com/user/{username}"
    r = session.get(url, timeout=TIMEOUT)
    
    if check_rate_limit(r):
        rate_limiter.record_request("spotify", was_rate_limited=True)
        return CheckResult.RATE_LIMITED
    
    rate_limiter.record_request("spotify")
    
    if r.status_code == 200 and username.lower() in r.text.lower():
        return CheckResult.FOUND
    return CheckResult.NOT_FOUND

@handle_request_errors
def soundcloud(username):
    session = session_manager.get_session("soundcloud")
    url = f"https://soundcloud.com/{username}"
    r = session.get(url, timeout=TIMEOUT)
    
    if check_rate_limit(r):
        rate_limiter.record_request("soundcloud", was_rate_limited=True)
        return CheckResult.RATE_LIMITED
    
    rate_limiter.record_request("soundcloud")
    
    if r.status_code == 200 and ('soundcloud' in r.text.lower() or username.lower() in r.text.lower()):
        return CheckResult.FOUND
    return CheckResult.NOT_FOUND

@handle_request_errors
def youtube(username):
    session = session_manager.get_session("youtube")
    urls = [
        f"https://www.youtube.com/@{username}",
        f"https://www.youtube.com/c/{username}",
        f"https://www.youtube.com/user/{username}",
    ]
    
    for url in urls:
        try:
            r = session.get(url, timeout=TIMEOUT)
            
            if check_rate_limit(r):
                rate_limiter.record_request("youtube", was_rate_limited=True)
                return CheckResult.RATE_LIMITED
            
            if r.status_code == 200:
                channel_markers = [
                    '"channelId":"',
                    '"ownerText":',
                    '"subscriberCountText":',
                    '"@type":"Channel"',
                ]
                
                not_found_markers = [
                    '{"error":{"code":404',
                    'This page isn\'t available',
                    '<title>404 Not Found</title>',
                ]
                
                text = r.text
                
                is_not_found = any(marker in text for marker in not_found_markers)
                if is_not_found:
                    continue
                
                if any(marker in text for marker in channel_markers):
                    rate_limiter.record_request("youtube")
                    return CheckResult.FOUND
        except:
            continue
    
    rate_limiter.record_request("youtube")
    return CheckResult.NOT_FOUND

@handle_request_errors
def medium(username):
    session = session_manager.get_session("medium")
    url = f"https://medium.com/@{username}"
    r = session.get(url, timeout=TIMEOUT)
    
    if check_rate_limit(r):
        rate_limiter.record_request("medium", was_rate_limited=True)
        return CheckResult.RATE_LIMITED
    
    rate_limiter.record_request("medium")
    
    if r.status_code == 404:
        return CheckResult.NOT_FOUND
    
    if r.status_code == 200:
        profile_markers = [
            '"@type":"Person"',
            '"creator":{"@type":"Person"',
            f'"identifier":"@{username}"',
            '"UserFollowButton"',
        ]
        
        not_found_markers = [
            "We couldn't find this page",
            "PAGE NOT FOUND",
            "404",
        ]
        
        text = r.text
        
        for marker in not_found_markers:
            if marker in text:
                return CheckResult.NOT_FOUND
        
        if any(marker in text for marker in profile_markers):
            return CheckResult.FOUND
    
    return CheckResult.NOT_FOUND

@handle_request_errors
def chessdotcom(username):
    session = session_manager.get_session("chessdotcom")
    url = f"https://www.chess.com/member/{username}"
    r = session.get(url, timeout=TIMEOUT)
    
    if check_rate_limit(r):
        rate_limiter.record_request("chessdotcom", was_rate_limited=True)
        return CheckResult.RATE_LIMITED
    
    rate_limiter.record_request("chessdotcom")
    
    if r.status_code == 200 and username.lower() in r.text.lower() and "chess.com" in r.text.lower():
        return CheckResult.FOUND
    return CheckResult.NOT_FOUND

@handle_request_errors
def vk(username):
    session = session_manager.get_session("vk")
    url = f"https://vk.com/{username}"
    r = session.get(url, timeout=TIMEOUT)
    
    if check_rate_limit(r):
        rate_limiter.record_request("vk", was_rate_limited=True)
        return CheckResult.RATE_LIMITED
    
    rate_limiter.record_request("vk")
    
    if r.status_code != 200:
        return CheckResult.NOT_FOUND
    
    not_found_markers = [
        "Profile not found",
        "страница удалена",
        "страница не найдена",
        "is unavailable",
        "has been deleted",
    ]
    
    for marker in not_found_markers:
        if marker.lower() in r.text.lower():
            return CheckResult.NOT_FOUND
    
    if '<div class="page_name"' in r.text or "wall_tab_all" in r.text:
        return CheckResult.FOUND
    
    if username.lower() in r.text.lower():
        return CheckResult.FOUND
    
    return CheckResult.NOT_FOUND

@handle_request_errors
def steam(username):
    session = session_manager.get_session("steam")
    url = f"https://steamcommunity.com/id/{username}"
    r = session.get(url, timeout=TIMEOUT)
    
    if check_rate_limit(r):
        rate_limiter.record_request("steam", was_rate_limited=True)
        return CheckResult.RATE_LIMITED
    
    rate_limiter.record_request("steam")
    
    if r.status_code == 404:
        return CheckResult.NOT_FOUND
    
    if "The specified profile could not be found" in r.text:
        return CheckResult.NOT_FOUND
    
    if 'class="profile_header_bg"' in r.text or 'steamcommunity.com/id/' in r.text:
        return CheckResult.FOUND
    
    if username.lower() in r.text.lower():
        return CheckResult.FOUND
    
    return CheckResult.NOT_FOUND

@handle_request_errors
def deviantart(username):
    session = session_manager.get_session("deviantart")
    url = f"https://www.deviantart.com/{username}"
    r = session.get(url, timeout=TIMEOUT)
    
    if check_rate_limit(r):
        rate_limiter.record_request("deviantart", was_rate_limited=True)
        return CheckResult.RATE_LIMITED
    
    rate_limiter.record_request("deviantart")
    
    if r.status_code == 404:
        return CheckResult.NOT_FOUND
    
    if "doesn't exist" in r.text or "The page you're looking for" in r.text:
        return CheckResult.NOT_FOUND
    
    if username.lower() in r.text.lower() or 'deviantart.com' in r.text:
        return CheckResult.FOUND
    
    return CheckResult.NOT_FOUND

@handle_request_errors
def vimeo(username):
    session = session_manager.get_session("vimeo")
    url = f"https://vimeo.com/{username}"
    r = session.get(url, timeout=TIMEOUT)
    
    if check_rate_limit(r):
        rate_limiter.record_request("vimeo", was_rate_limited=True)
        return CheckResult.RATE_LIMITED
    
    rate_limiter.record_request("vimeo")
    
    if r.status_code == 404:
        return CheckResult.NOT_FOUND
    
    if "Sorry, we couldn't find that page" in r.text or "Page not found" in r.text:
        return CheckResult.NOT_FOUND
    
    if username.lower() in r.text.lower():
        return CheckResult.FOUND
    
    return CheckResult.NOT_FOUND

@handle_request_errors
def keybase(username):
    session = session_manager.get_session("keybase")
    url = f"https://keybase.io/{username}"
    r = session.get(url, timeout=TIMEOUT)
    
    if check_rate_limit(r):
        rate_limiter.record_request("keybase", was_rate_limited=True)
        return CheckResult.RATE_LIMITED
    
    rate_limiter.record_request("keybase")
    
    if r.status_code != 200:
        return CheckResult.NOT_FOUND
    
    profile_markers = [
        f'"username":"{username}"',
        '"proofs_summary"',
        '"stellar"',
        '"bitcoin"',
    ]
    
    not_found_markers = [
        "User not found",
        "404",
        "No such user",
    ]
    
    text = r.text
    
    for marker in not_found_markers:
        if marker in text:
            return CheckResult.NOT_FOUND
    
    if any(marker in text for marker in profile_markers):
        return CheckResult.FOUND
    
    return CheckResult.NOT_FOUND

CHECKS: Dict[str, Callable[[str], CheckResult]] = {
    "GitHub": github,
    "GitLab": gitlab,
    "Reddit": reddit,
    "Instagram": instagram,
    "Facebook": facebook,
    "TikTok": tiktok,
    "LinkedIn": linkedin,
    "Pinterest": pinterest,
    "Pastebin": pastebin,
    "Telegram": telegram,
    "Snapchat": snapchat,
    "Strava": strava,
    "Threads": threads,
    "Mastodon": mastodon,
    "Bluesky": bluesky,
    "Spotify": spotify,
    "SoundCloud": soundcloud,
    "YouTube": youtube,
    "Medium": medium,
    "Chess.com": chessdotcom,
    "Keybase": keybase,
    "Linktree": linktree,
    "VK": vk,
    "Steam": steam,
    "DeviantArt": deviantart,
    "Vimeo": vimeo,
}

profile_urls = {
    "GitHub": lambda u: f"https://github.com/{u}",
    "GitLab": lambda u: f"https://gitlab.com/{u}",
    "Reddit": lambda u: f"https://reddit.com/user/{u}",
    "Instagram": lambda u: f"https://instagram.com/{u}",
    "Facebook": lambda u: f"https://facebook.com/{u}",
    "TikTok": lambda u: f"https://www.tiktok.com/@{u}",
    "LinkedIn": lambda u: f"https://www.linkedin.com/in/{u}",
    "Pinterest": lambda u: f"https://www.pinterest.com/{u}/",
    "Pastebin": lambda u: f"https://pastebin.com/u/{u}",
    "Telegram": lambda u: f"https://t.me/{u}",
    "Snapchat": lambda u: f"https://www.snapchat.com/add/{u}",
    "Strava": lambda u: f"https://www.strava.com/athletes/{u}",
    "Threads": lambda u: f"https://www.threads.net/@{u}",
    "Mastodon": lambda u: f"https://mastodon.social/@{u}",
    "Bluesky": lambda u: f"https://bsky.app/profile/{u}.bsky.social",
    "Spotify": lambda u: f"https://open.spotify.com/user/{u}",
    "SoundCloud": lambda u: f"https://soundcloud.com/{u}",
    "YouTube": lambda u: f"https://www.youtube.com/@{u}",
    "Medium": lambda u: f"https://medium.com/@{u}",
    "Chess.com": lambda u: f"https://www.chess.com/member/{u}",
    "Keybase": lambda u: f"https://keybase.io/{u}",
    "Linktree": lambda u: f"https://linktr.ee/{u}",
    "VK": lambda u: f"https://vk.com/{u}",
    "Steam": lambda u: f"https://steamcommunity.com/id/{u}",
    "DeviantArt": lambda u: f"https://www.deviantart.com/{u}",
    "Vimeo": lambda u: f"https://vimeo.com/{u}",
}

def check_single_platform(platform: str, check_func: Callable, username: str) -> Tuple[str, CheckResult]:
    wait_time = rate_limiter.should_wait(platform.lower())
    if wait_time > 0:
        time.sleep(wait_time)
    
    result = check_func(username)
    return (platform, result)

def get_result_symbol(result: CheckResult) -> str:
    """Get the appropriate symbol for each result type"""
    symbols = {
        CheckResult.FOUND: "✅",
        CheckResult.NOT_FOUND: "❌",
        CheckResult.NETWORK_ERROR: "🔌",
        CheckResult.RATE_LIMITED: "⏳",
        CheckResult.TIMEOUT: "⏱️",
        CheckResult.UNKNOWN_ERROR: "❓"
    }
    return symbols.get(result, "❓")

def get_result_description(result: CheckResult) -> str:
    """Get human-readable description of the result"""
    descriptions = {
        CheckResult.FOUND: "Profile found",
        CheckResult.NOT_FOUND: "Profile not found",
        CheckResult.NETWORK_ERROR: "Network error",
        CheckResult.RATE_LIMITED: "Rate limited",
        CheckResult.TIMEOUT: "Timeout",
        CheckResult.UNKNOWN_ERROR: "Unknown error"
    }
    return descriptions.get(result, "Unknown")

def export_json(results: Dict[str, Dict[str, any]], filename: str):
    """Export results to JSON"""
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n💾 Results exported to {filename}")

def check_username(username: str) -> Dict:
    """Check a single username across all platforms"""
    results = {}
    total_platforms = len(CHECKS)
    current = 0
    
    # Track statistics
    stats = {
        CheckResult.FOUND: 0,
        CheckResult.NOT_FOUND: 0,
        CheckResult.NETWORK_ERROR: 0,
        CheckResult.RATE_LIMITED: 0,
        CheckResult.TIMEOUT: 0,
        CheckResult.UNKNOWN_ERROR: 0
    }
    
    if RICH:
        console = Console()
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task(f"[cyan]Checking {username}...", total=total_platforms)
            
            for plat, fn in CHECKS.items():
                platform_result, result = check_single_platform(plat, fn, username)
                results[plat] = result
                stats[result] += 1
                
                progress.update(task, advance=1, description=f"[cyan]Checking {username}... {plat} {get_result_symbol(result)}")
    else:
        for plat, fn in CHECKS.items():
            current += 1
            print(f"[{current}/{total_platforms}] Checking {plat}...", end=" ", flush=True)
            
            platform_result, result = check_single_platform(plat, fn, username)
            results[plat] = result
            stats[result] += 1
            
            print(get_result_symbol(result))
    
    return {
        "username": username,
        "results": results,
        "stats": stats,
        "timestamp": datetime.now()
    }

def display_results(username: str, results: Dict[str, CheckResult], stats: Dict):
    """Display results for a single username"""
    print(f"\n📊 Results Summary for '{username}':")
    print(f"✅ Found: {stats[CheckResult.FOUND]}")
    print(f"❌ Not Found: {stats[CheckResult.NOT_FOUND]}")
    if stats[CheckResult.NETWORK_ERROR] > 0:
        print(f"🔌 Network Errors: {stats[CheckResult.NETWORK_ERROR]}")
    if stats[CheckResult.RATE_LIMITED] > 0:
        print(f"⏳ Rate Limited: {stats[CheckResult.RATE_LIMITED]}")
    if stats[CheckResult.TIMEOUT] > 0:
        print(f"⏱️  Timeouts: {stats[CheckResult.TIMEOUT]}")
    if stats[CheckResult.UNKNOWN_ERROR] > 0:
        print(f"❓ Unknown Errors: {stats[CheckResult.UNKNOWN_ERROR]}")

    if RICH:
        console = Console()
        table = Table(title=f"Username: {username} | Found: {stats[CheckResult.FOUND]}/{len(CHECKS)}", show_lines=True)
        table.add_column("Platform", style="cyan", no_wrap=True)
        table.add_column("Status", style="green")
        table.add_column("Result", style="yellow")
        table.add_column("Profile URL", style="magenta")
        
        # Sort results
        def sort_key(item):
            plat, result = item
            if result == CheckResult.FOUND:
                return (0, plat)
            elif result == CheckResult.NOT_FOUND:
                return (2, plat)
            else:
                return (1, plat)
        
        sorted_results = sorted(results.items(), key=sort_key)
        
        for plat, result in sorted_results:
            url = profile_urls[plat](username) if plat in profile_urls else ""
            status = get_result_symbol(result)
            result_desc = get_result_description(result)
            table.add_row(plat, status, result_desc, url if result == CheckResult.FOUND else "")
        console.print(table)
    else:
        print("\n" + "="*60)
        print("DETAILED RESULTS:")
        print("="*60)
        
        found_profiles = [(plat, result) for plat, result in results.items() if result == CheckResult.FOUND]
        error_profiles = [(plat, result) for plat, result in results.items() if result not in [CheckResult.FOUND, CheckResult.NOT_FOUND]]
        not_found_profiles = [(plat, result) for plat, result in results.items() if result == CheckResult.NOT_FOUND]
        
        if found_profiles:
            print("\n✅ PROFILES FOUND:")
            for plat, _ in found_profiles:
                print(f"[+] {plat:12} : {profile_urls[plat](username)}")
        
        if error_profiles:
            print(f"\n⚠️  ERRORS ({len(error_profiles)}):")
            for plat, result in error_profiles:
                print(f"[!] {plat:12} : {get_result_description(result)}")
        
        if not_found_profiles:
            print(f"\n❌ NOT FOUND ({len(not_found_profiles)}):")
            for plat, _ in not_found_profiles:
                print(f"[-] {plat:12} : No profile detected")

def main():
    parser = argparse.ArgumentParser(description="OSINT username checker")
    parser.add_argument("username", nargs="?", help="Username to search")
    parser.add_argument("--list", "-l", help="File containing list of usernames (one per line)")
    parser.add_argument("--export", "-e", help="Export results to JSON file")
    
    args = parser.parse_args()
    
    if not args.username and not args.list:
        parser.print_help()
        sys.exit(1)
    
    print(f"\n🔍 Enhanced OSINT Username Checker")
    print("📝 Note: X/Twitter and Twitch not available - no reliable detection method")
        
    all_results = {}
    
    # Get list of usernames to check
    usernames = []
    if args.list:
        try:
            with open(args.list, 'r') as f:
                usernames = [line.strip().lstrip("@") for line in f if line.strip()]
            print(f"📋 Loaded {len(usernames)} usernames from {args.list}")
        except FileNotFoundError:
            print(f"❌ Error: File '{args.list}' not found")
            sys.exit(1)
    else:
        usernames = [args.username.strip().lstrip("@")]
    
    # Check each username
    for idx, username in enumerate(usernames):
        if len(usernames) > 1:
            print(f"\nChecking username: {username}")
            # Add delay between usernames to avoid IP-based rate limiting
            if idx > 0:
                delay = random.uniform(2, 5)  # Random delay between 2-5 seconds
                print(f"⏳ Waiting {delay:.1f} seconds before next username...")
                time.sleep(delay)
        
        result = check_username(username)
        all_results[username] = result
        
        display_results(
            username,
            result["results"],
            result["stats"]
        )
    
    # Export results if requested
    if args.export:
        export_data = {}
        for username, data in all_results.items():
            export_data[username] = {
                "timestamp": data["timestamp"].isoformat(),
                "stats": {k.value: v for k, v in data["stats"].items()},
                "results": {plat: result.value for plat, result in data["results"].items()},
                "found_profiles": {
                    plat: profile_urls[plat](username)
                    for plat, result in data["results"].items()
                    if result == CheckResult.FOUND and plat in profile_urls
                }
            }
        export_json(export_data, args.export)
    
    print(f"\n💡 Tips:")
    print("- Manually verify positive results for accuracy")
    print("- The things you own end up owning you")


if __name__ == "__main__":
    main()
    