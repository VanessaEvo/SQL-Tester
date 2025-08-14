import random
from typing import List, Dict

class UserAgentManager:
    """Advanced User-Agent management for detection avoidance"""
    
    def __init__(self):
        self.user_agents = {
            # 2024 Chrome Browsers (Most Common)
            "chrome_windows": [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
            ],
            
            "chrome_mac": [
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_7_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ],
            
            "chrome_linux": [
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
                "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ],
            
            # 2024 Firefox Browsers
            "firefox_windows": [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:118.0) Gecko/20100101 Firefox/118.0",
                "Mozilla/5.0 (Windows NT 11.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
                "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:121.0) Gecko/20100101 Firefox/121.0"
            ],
            
            "firefox_mac": [
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:119.0) Gecko/20100101 Firefox/119.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 13.6; rv:121.0) Gecko/20100101 Firefox/121.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.1; rv:121.0) Gecko/20100101 Firefox/121.0"
            ],
            
            "firefox_linux": [
                "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
                "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
                "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
                "Mozilla/5.0 (X11; Linux i686; rv:121.0) Gecko/20100101 Firefox/121.0"
            ],
            
            # Safari Browsers
            "safari_mac": [
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15"
            ],
            
            # Edge Browsers
            "edge_windows": [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Edg/118.0.0.0",
                "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
            ],
            
            "edge_mac": [
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0"
            ],
            
            # Mobile Browsers (Important for modern testing)
            "mobile_chrome_android": [
                "Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
                "Mozilla/5.0 (Linux; Android 13; SM-A515F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
                "Mozilla/5.0 (Linux; Android 12; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
                "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
                "Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
            ],
            
            "mobile_safari_ios": [
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
                "Mozilla/5.0 (iPad; CPU OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
                "Mozilla/5.0 (iPad; CPU OS 16_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1"
            ],
            
            # Specialized/Security Testing User Agents
            "security_tools": [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 SecurityScanner/1.0",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 PenTest/2.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0 VulnScanner/3.0"
            ],
            
            # Bot/Crawler User Agents (Sometimes useful)
            "bots": [
                "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
                "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
                "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
                "Mozilla/5.0 (compatible; DuckDuckBot-Https/1.1; https://duckduckgo.com/duckduckbot)"
            ],
            
            # Older but still common browsers
            "legacy_browsers": [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
            ],
            
            # Enterprise/Corporate Browsers
            "enterprise": [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Corporate/1.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Enterprise/2.0",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Corporate/Linux"
            ],
            
            # Gaming/Console Browsers
            "gaming": [
                "Mozilla/5.0 (PlayStation 5 6.00) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
                "Mozilla/5.0 (Xbox Series X) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edge/44.18363.8131",
                "Mozilla/5.0 (Nintendo Switch; WebApplet) AppleWebKit/606.4 (KHTML, like Gecko) NF/6.0.1.15.4 NintendoBrowser/5.1.0.20393"
            ],
            
            # Smart TV/IoT Browsers
            "smart_devices": [
                "Mozilla/5.0 (SMART-TV; LINUX; Tizen 6.0) AppleWebKit/537.36 (KHTML, like Gecko) Version/6.0 TV Safari/537.36",
                "Mozilla/5.0 (Web0S; Linux/SmartTV) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36 WebAppManager",
                "Mozilla/5.0 (X11; Linux armv7l) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 RaspberryPi"
            ]
        }
        
        # Weight distribution for realistic selection
        self.category_weights = {
            "chrome_windows": 35,
            "chrome_mac": 15,
            "chrome_linux": 8,
            "firefox_windows": 12,
            "firefox_mac": 5,
            "firefox_linux": 3,
            "safari_mac": 8,
            "edge_windows": 6,
            "edge_mac": 2,
            "mobile_chrome_android": 3,
            "mobile_safari_ios": 2,
            "legacy_browsers": 1,
            "enterprise": 0.5,
            "security_tools": 0.3,
            "bots": 0.1,
            "gaming": 0.05,
            "smart_devices": 0.05
        }

    def get_random_user_agent(self, category: str = None) -> str:
        """Get a random user agent, optionally from a specific category"""
        if category and category in self.user_agents:
            return random.choice(self.user_agents[category])
        
        # Weighted random selection from all categories
        categories = list(self.category_weights.keys())
        weights = list(self.category_weights.values())
        
        selected_category = random.choices(categories, weights=weights)[0]
        return random.choice(self.user_agents[selected_category])

    def get_user_agents_by_category(self, category: str) -> List[str]:
        """Get all user agents from a specific category"""
        return self.user_agents.get(category, [])

    def get_all_categories(self) -> List[str]:
        """Get list of all available categories"""
        return list(self.user_agents.keys())

    def get_desktop_user_agent(self) -> str:
        """Get a random desktop user agent"""
        desktop_categories = [
            "chrome_windows", "chrome_mac", "chrome_linux",
            "firefox_windows", "firefox_mac", "firefox_linux",
            "safari_mac", "edge_windows", "edge_mac"
        ]
        category = random.choice(desktop_categories)
        return random.choice(self.user_agents[category])

    def get_mobile_user_agent(self) -> str:
        """Get a random mobile user agent"""
        mobile_categories = ["mobile_chrome_android", "mobile_safari_ios"]
        category = random.choice(mobile_categories)
        return random.choice(self.user_agents[category])

    def get_stealth_user_agent(self) -> str:
        """Get a user agent optimized for stealth (most common browsers)"""
        stealth_categories = ["chrome_windows", "chrome_mac", "firefox_windows"]
        category = random.choice(stealth_categories)
        return random.choice(self.user_agents[category])

    def get_enterprise_user_agent(self) -> str:
        """Get an enterprise/corporate user agent"""
        return random.choice(self.user_agents["enterprise"])

    def get_security_tool_user_agent(self) -> str:
        """Get a security tool user agent"""
        return random.choice(self.user_agents["security_tools"])

    def get_bot_user_agent(self) -> str:
        """Get a bot/crawler user agent"""
        return random.choice(self.user_agents["bots"])

    def get_user_agent_info(self, user_agent: str) -> Dict[str, str]:
        """Extract information from a user agent string"""
        info = {
            "browser": "Unknown",
            "version": "Unknown",
            "os": "Unknown",
            "device": "Desktop"
        }
        
        # Browser detection
        if "Chrome" in user_agent:
            info["browser"] = "Chrome"
            if "Edg/" in user_agent:
                info["browser"] = "Edge"
        elif "Firefox" in user_agent:
            info["browser"] = "Firefox"
        elif "Safari" in user_agent and "Chrome" not in user_agent:
            info["browser"] = "Safari"
        elif "bot" in user_agent.lower():
            info["browser"] = "Bot"
        
        # OS detection
        if "Windows NT 10.0" in user_agent:
            info["os"] = "Windows 10"
        elif "Windows NT 11.0" in user_agent:
            info["os"] = "Windows 11"
        elif "Mac OS X" in user_agent:
            info["os"] = "macOS"
        elif "Linux" in user_agent:
            info["os"] = "Linux"
        elif "Android" in user_agent:
            info["os"] = "Android"
            info["device"] = "Mobile"
        elif "iPhone" in user_agent or "iPad" in user_agent:
            info["os"] = "iOS"
            info["device"] = "Mobile"
        
        return info

    def rotate_user_agents(self, count: int = 10) -> List[str]:
        """Get a list of diverse user agents for rotation"""
        agents = []
        categories = list(self.user_agents.keys())
        
        for _ in range(count):
            category = random.choice(categories)
            agent = random.choice(self.user_agents[category])
            if agent not in agents:
                agents.append(agent)
        
        return agents

    def get_realistic_headers(self, user_agent: str = None) -> Dict[str, str]:
        """Get realistic HTTP headers to accompany the user agent"""
        if not user_agent:
            user_agent = self.get_random_user_agent()
        
        headers = {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": random.choice([
                "en-US,en;q=0.9",
                "en-GB,en;q=0.9",
                "en-US,en;q=0.9,es;q=0.8",
                "en-US,en;q=0.9,fr;q=0.8",
                "en-US,en;q=0.9,de;q=0.8"
            ]),
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": random.choice(["1", "0"]),
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        
        # Add browser-specific headers
        if "Chrome" in user_agent:
            headers["sec-ch-ua"] = '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"'
            headers["sec-ch-ua-mobile"] = "?0" if "Mobile" not in user_agent else "?1"
            headers["sec-ch-ua-platform"] = self._get_platform_from_ua(user_agent)
            headers["Sec-Fetch-Dest"] = "document"
            headers["Sec-Fetch-Mode"] = "navigate"
            headers["Sec-Fetch-Site"] = "none"
            headers["Sec-Fetch-User"] = "?1"
        
        return headers

    def _get_platform_from_ua(self, user_agent: str) -> str:
        """Extract platform information for sec-ch-ua-platform header"""
        if "Windows" in user_agent:
            return '"Windows"'
        elif "Mac OS X" in user_agent:
            return '"macOS"'
        elif "Linux" in user_agent:
            return '"Linux"'
        elif "Android" in user_agent:
            return '"Android"'
        else:
            return '"Unknown"'

    def get_user_agent_statistics(self) -> Dict[str, int]:
        """Get statistics about the user agent collection"""
        stats = {}
        total = 0
        
        for category, agents in self.user_agents.items():
            count = len(agents)
            stats[category] = count
            total += count
        
        stats["total"] = total
        return stats

    def validate_user_agent(self, user_agent: str) -> bool:
        """Validate if a user agent string looks legitimate"""
        # Basic validation checks
        if not user_agent or len(user_agent) < 20:
            return False
        
        # Should contain Mozilla
        if "Mozilla" not in user_agent:
            return False
        
        # Should contain at least one browser identifier
        browser_identifiers = ["Chrome", "Firefox", "Safari", "Edge", "Opera"]
        if not any(browser in user_agent for browser in browser_identifiers):
            return False
        
        return True

    def get_user_agent_for_target(self, target_url: str) -> str:
        """Get an appropriate user agent based on the target"""
        # Simple heuristic based on domain
        if any(domain in target_url.lower() for domain in ["mobile", "m.", "app"]):
            return self.get_mobile_user_agent()
        elif any(domain in target_url.lower() for domain in ["enterprise", "corp", "intranet"]):
            return self.get_enterprise_user_agent()
        else:
            return self.get_stealth_user_agent()