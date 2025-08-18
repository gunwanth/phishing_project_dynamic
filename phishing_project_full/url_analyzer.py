import re
import requests
import urllib.parse
from urllib.parse import urlparse
import dns.resolver
import socket
from datetime import datetime, timedelta

class URLAnalyzer:
    def __init__(self):
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top', '.click',
            '.download', '.stream', '.science', '.date', '.review'
        ]
        
        self.legitimate_domains = [
            'google.com', 'amazon.com', 'microsoft.com', 'apple.com',
            'facebook.com', 'linkedin.com', 'twitter.com', 'instagram.com',
            'youtube.com', 'github.com', 'stackoverflow.com', 'reddit.com'
        ]
        
        self.phishing_keywords = [
            'login', 'signin', 'verify', 'account', 'security', 'update',
            'confirm', 'validation', 'authentication', 'suspended'
        ]
    
    def extract_urls(self, text):
        """Extract all URLs from text content"""
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, text)
        return urls
    
    def analyze_url(self, url):
        """Analyze a single URL for suspicious characteristics"""
        analysis = {
            'url': url,
            'risk_score': 0.0,
            'suspicious_indicators': [],
            'domain_info': {},
            'is_suspicious': False
        }
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            
            # Domain analysis
            analysis['domain_info'] = {
                'domain': domain,
                'subdomain': domain.split('.')[0] if '.' in domain else '',
                'tld': '.' + domain.split('.')[-1] if '.' in domain else '',
                'path': path
            }
            
            # Check for suspicious TLD
            if analysis['domain_info']['tld'] in self.suspicious_tlds:
                analysis['risk_score'] += 0.3
                analysis['suspicious_indicators'].append(f"Suspicious TLD: {analysis['domain_info']['tld']}")
            
            # Check for domain spoofing
            spoofing_score = self._check_domain_spoofing(domain)
            analysis['risk_score'] += spoofing_score
            if spoofing_score > 0:
                analysis['suspicious_indicators'].append("Potential domain spoofing detected")
            
            # Check for suspicious keywords in URL
            if any(keyword in url.lower() for keyword in self.phishing_keywords):
                analysis['risk_score'] += 0.2
                analysis['suspicious_indicators'].append("Contains phishing-related keywords")
            
            # Check for URL shorteners (higher risk)
            shortener_domains = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly']
            if any(shortener in domain for shortener in shortener_domains):
                analysis['risk_score'] += 0.4
                analysis['suspicious_indicators'].append("Uses URL shortening service")
            
            # Check for suspicious path patterns
            if re.search(r'/login|/signin|/verify|/account|/security', path):
                analysis['risk_score'] += 0.2
                analysis['suspicious_indicators'].append("Path suggests credential harvesting")
            
            # Check for IP address instead of domain
            if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                analysis['risk_score'] += 0.5
                analysis['suspicious_indicators'].append("Uses IP address instead of domain name")
            
            # Check domain length (very long domains can be suspicious)
            if len(domain) > 30:
                analysis['risk_score'] += 0.1
                analysis['suspicious_indicators'].append("Unusually long domain name")
            
            # Check for excessive subdomains
            subdomain_count = domain.count('.')
            if subdomain_count > 3:
                analysis['risk_score'] += 0.2
                analysis['suspicious_indicators'].append("Excessive number of subdomains")
            
            # Determine if suspicious
            analysis['is_suspicious'] = analysis['risk_score'] >= 0.5
            
            # Ensure risk score doesn't exceed 1.0
            analysis['risk_score'] = min(1.0, analysis['risk_score'])
            
        except Exception as e:
            analysis['suspicious_indicators'].append(f"URL parsing error: {str(e)}")
            analysis['risk_score'] = 0.5  # Medium risk for unparseable URLs
        
        return analysis
    
    def _check_domain_spoofing(self, domain):
        """Check if domain might be spoofing a legitimate service"""
        spoofing_score = 0.0
        
        for legit_domain in self.legitimate_domains:
            # Check for character substitution
            if self._similar_domain(domain, legit_domain):
                spoofing_score += 0.4
                break
            
            # Check for legitimate domain as substring
            if legit_domain in domain and domain != legit_domain:
                spoofing_score += 0.3
                break
        
        return spoofing_score
    
    def _similar_domain(self, domain1, domain2):
        """Check if two domains are suspiciously similar"""
        # Simple character substitution check
        substitutions = {
            'a': ['@', '4'], 'e': ['3'], 'i': ['1', '!'], 'o': ['0'],
            's': ['$', '5'], 'g': ['9'], 'l': ['1', 'i']
        }
        
        # Remove TLD for comparison
        d1 = domain1.split('.')[0] if '.' in domain1 else domain1
        d2 = domain2.split('.')[0] if '.' in domain2 else domain2
        
        # Check if domains are similar length and have character substitutions
        if abs(len(d1) - len(d2)) <= 2:
            differences = 0
            min_len = min(len(d1), len(d2))
            
            for i in range(min_len):
                if d1[i] != d2[i]:
                    differences += 1
            
            # If only 1-2 character differences, might be spoofing
            return differences <= 2 and len(d1) > 4
        
        return False
    
    def analyze_email_urls(self, email_content):
        """Analyze all URLs in an email and return summary"""
        urls = self.extract_urls(email_content)
        
        if not urls:
            return {
                'total_urls': 0,
                'suspicious_urls': [],
                'safe_urls': [],
                'overall_risk': 0.0
            }
        
        suspicious_urls = []
        safe_urls = []
        total_risk = 0.0
        
        for url in urls:
            analysis = self.analyze_url(url)
            total_risk += analysis['risk_score']
            
            if analysis['is_suspicious']:
                suspicious_urls.append({
                    'url': url,
                    'risk_score': analysis['risk_score'],
                    'indicators': analysis['suspicious_indicators']
                })
            else:
                safe_urls.append(url)
        
        return {
            'total_urls': len(urls),
            'suspicious_urls': suspicious_urls,
            'safe_urls': safe_urls,
            'overall_risk': total_risk / len(urls) if urls else 0.0
        }
    
    def check_url_reputation(self, url):
        """Check URL reputation using simple heuristics"""
        # In a real implementation, this would query threat intelligence APIs
        # For demo purposes, we'll use pattern matching
        
        reputation = {
            'is_malicious': False,
            'reputation_score': 0.5,  # 0 = clean, 1 = malicious
            'source': 'local_analysis',
            'last_checked': datetime.now().isoformat()
        }
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Check against known bad domains (simplified)
            bad_domains = [
                'suspicious-bank.com', 'fake-lottery.net', 'paypal-verify.net',
                'debt-collection.biz', 'amazon-security.org'
            ]
            
            if any(bad_domain in domain for bad_domain in bad_domains):
                reputation['is_malicious'] = True
                reputation['reputation_score'] = 0.9
            elif any(good_domain in domain for good_domain in self.legitimate_domains):
                reputation['reputation_score'] = 0.1
            
        except Exception as e:
            reputation['reputation_score'] = 0.5  # Unknown reputation
        
        return reputation