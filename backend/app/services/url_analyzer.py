import requests
import re
import socket
from urllib.parse import urlparse, urljoin
from datetime import datetime
import json
import time
from typing import Dict, List, Optional

class URLAnalyzer:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'QRShield/1.0 Security Scanner'
        })
        
    def analyze_url(self, url: str) -> Dict:
        """
        Comprehensive URL analysis
        
        Args:
            url: URL to analyze
            
        Returns:
            dict: Analysis results
        """
        results = {
            'original_url': url,
            'timestamp': datetime.utcnow().isoformat(),
            'basic_info': {},
            'security_check': {},
            'network_info': {},
            'content_analysis': {},
            'risk_score': 0,
            'risk_level': 'low',
            'warnings': [],
            'recommendations': []
        }
        
        try:
            # Basic URL parsing
            results['basic_info'] = self._parse_url_basic(url)
            
            # Security checks
            results['security_check'] = self._security_checks(url)
            
            # Network information
            results['network_info'] = self._get_network_info(url)
            
            # Content analysis (if accessible)
            results['content_analysis'] = self._analyze_content(url)
            
            # Calculate risk score
            results['risk_score'], results['risk_level'] = self._calculate_risk_score(results)
            
            # Generate warnings and recommendations
            results['warnings'] = self._generate_warnings(results)
            results['recommendations'] = self._generate_recommendations(results)
            
        except Exception as e:
            results['error'] = str(e)
            results['risk_level'] = 'unknown'
            results['warnings'].append(f"Analysis failed: {str(e)}")
            
        return results
    
    def _parse_url_basic(self, url: str) -> Dict:
        """Parse basic URL information"""
        try:
            parsed = urlparse(url)
            
            return {
                'scheme': parsed.scheme,
                'domain': parsed.netloc,
                'path': parsed.path,
                'query': parsed.query,
                'fragment': parsed.fragment,
                'port': parsed.port,
                'is_https': parsed.scheme == 'https',
                'has_query_params': bool(parsed.query),
                'path_depth': len([p for p in parsed.path.split('/') if p]),
                'domain_parts': parsed.netloc.split('.') if parsed.netloc else []
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _security_checks(self, url: str) -> Dict:
        """Perform basic security checks"""
        checks = {
            'suspicious_patterns': [],
            'url_shortener': False,
            'suspicious_tld': False,
            'homograph_attack': False,
            'suspicious_keywords': [],
            'url_length': len(url),
            'encoded_characters': False
        }
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            full_url = url.lower()
            
            # Check for URL shorteners
            shortener_domains = [
                'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
                'tiny.cc', 'is.gd', 'buff.ly', 'adf.ly', 'short.link'
            ]
            checks['url_shortener'] = any(shortener in domain for shortener in shortener_domains)
            
            # Check for suspicious TLDs
            suspicious_tlds = [
                '.tk', '.ml', '.ga', '.cf', '.click', '.download',
                '.science', '.work', '.party', '.cricket', '.accountant'
            ]
            checks['suspicious_tld'] = any(domain.endswith(tld) for tld in suspicious_tlds)
            
            # Check for suspicious keywords
            suspicious_keywords = [
                'login', 'secure', 'verify', 'update', 'confirm',
                'suspended', 'locked', 'winner', 'prize', 'free',
                'urgent', 'immediate', 'click', 'now', 'limited'
            ]
            found_keywords = [kw for kw in suspicious_keywords if kw in full_url]
            checks['suspicious_keywords'] = found_keywords
            
            # Check for encoded characters
            checks['encoded_characters'] = '%' in url
            
            # Check for suspicious patterns
            patterns = []
            
            # Long URLs (potential for hiding)
            if len(url) > 200:
                patterns.append('extremely_long_url')
            
            # Multiple subdomains
            if domain.count('.') > 3:
                patterns.append('excessive_subdomains')
            
            # IP address instead of domain
            if re.match(r'^https?://\d+\.\d+\.\d+\.\d+', url):
                patterns.append('ip_address_url')
            
            # Numbers in domain (potential typosquatting)
            if re.search(r'\d', domain.replace('.', '')):
                patterns.append('numbers_in_domain')
            
            # Hyphen abuse
            if domain.count('-') > 2:
                patterns.append('excessive_hyphens')
            
            checks['suspicious_patterns'] = patterns
            
        except Exception as e:
            checks['error'] = str(e)
            
        return checks
    
    def _get_network_info(self, url: str) -> Dict:
        """Get network information about the URL"""
        info = {
            'ip_address': None,
            'hostname_resolved': False,
            'response_time': None,
            'status_code': None,
            'redirects': [],
            'final_url': url,
            'headers': {},
            'ssl_info': {}
        }
        
        try:
            parsed = urlparse(url)
            hostname = parsed.netloc
            
            # Resolve hostname to IP
            try:
                ip_address = socket.gethostbyname(hostname)
                info['ip_address'] = ip_address
                info['hostname_resolved'] = True
            except socket.gaierror:
                info['hostname_resolved'] = False
            
            # Make HTTP request with timeout
            start_time = time.time()
            
            try:
                response = self.session.get(
                    url, 
                    timeout=10, 
                    allow_redirects=True,
                    verify=True
                )
                
                info['response_time'] = round((time.time() - start_time) * 1000, 2)
                info['status_code'] = response.status_code
                info['final_url'] = response.url
                
                # Track redirects
                if response.history:
                    info['redirects'] = [r.url for r in response.history]
                
                # Get important headers
                important_headers = [
                    'content-type', 'server', 'x-frame-options',
                    'x-content-type-options', 'strict-transport-security',
                    'content-security-policy'
                ]
                
                for header in important_headers:
                    if header in response.headers:
                        info['headers'][header] = response.headers[header]
                
            except requests.exceptions.SSLError as e:
                info['ssl_error'] = str(e)
                info['status_code'] = 'SSL_ERROR'
                
            except requests.exceptions.ConnectionError as e:
                info['connection_error'] = str(e)
                info['status_code'] = 'CONNECTION_ERROR'
                
            except requests.exceptions.Timeout:
                info['status_code'] = 'TIMEOUT'
                
            except Exception as e:
                info['request_error'] = str(e)
                info['status_code'] = 'REQUEST_ERROR'
                
        except Exception as e:
            info['error'] = str(e)
            
        return info
    
    def _analyze_content(self, url: str) -> Dict:
        """Analyze content if accessible"""
        analysis = {
            'accessible': False,
            'content_type': None,
            'title': None,
            'meta_description': None,
            'has_forms': False,
            'external_links': 0,
            'suspicious_content': [],
            'page_size': 0,
            'load_time': None
        }
        
        try:
            start_time = time.time()
            response = self.session.get(url, timeout=15, verify=True)
            analysis['load_time'] = round((time.time() - start_time) * 1000, 2)
            
            if response.status_code == 200:
                analysis['accessible'] = True
                analysis['content_type'] = response.headers.get('content-type', '').split(';')[0]
                analysis['page_size'] = len(response.content)
                
                # Only analyze HTML content
                if 'text/html' in analysis['content_type']:
                    content = response.text.lower()
                    
                    # Extract title
                    title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
                    if title_match:
                        analysis['title'] = title_match.group(1).strip()[:200]
                    
                    # Extract meta description
                    meta_desc = re.search(r'<meta\s+name=["\']description["\']\s+content=["\']([^"\']*)["\']', content, re.IGNORECASE)
                    if meta_desc:
                        analysis['meta_description'] = meta_desc.group(1)[:300]
                    
                    # Check for forms
                    analysis['has_forms'] = '<form' in content
                    
                    # Count external links
                    links = re.findall(r'href=["\']https?://([^"\']*)["\']', content)
                    parsed_original = urlparse(url)
                    external_domains = set()
                    for link in links:
                        link_domain = link.split('/')[0]
                        if link_domain != parsed_original.netloc:
                            external_domains.add(link_domain)
                    analysis['external_links'] = len(external_domains)
                    
                    # Check for suspicious content patterns
                    suspicious_patterns = [
                        'enter your password', 'verify your account', 'suspended account',
                        'click here now', 'limited time offer', 'you have won',
                        'urgent action required', 'confirm your identity', 'update payment',
                        'download now', 'install software', 'free download'
                    ]
                    
                    found_suspicious = []
                    for pattern in suspicious_patterns:
                        if pattern in content:
                            found_suspicious.append(pattern)
                    
                    analysis['suspicious_content'] = found_suspicious
                    
        except Exception as e:
            analysis['error'] = str(e)
            
        return analysis
    
    def _calculate_risk_score(self, results: Dict) -> tuple:
        """Calculate risk score based on analysis results"""
        score = 0
        
        try:
            # Security check scoring
            security = results.get('security_check', {})
            
            if security.get('url_shortener'):
                score += 15
            
            if security.get('suspicious_tld'):
                score += 20
            
            score += len(security.get('suspicious_keywords', [])) * 5
            score += len(security.get('suspicious_patterns', [])) * 10
            
            if security.get('encoded_characters'):
                score += 5
            
            if security.get('url_length', 0) > 100:
                score += 10
            
            # Network info scoring
            network = results.get('network_info', {})
            
            if not network.get('hostname_resolved'):
                score += 30
            
            if network.get('status_code') in ['SSL_ERROR', 'CONNECTION_ERROR']:
                score += 25
            
            if len(network.get('redirects', [])) > 2:
                score += 10
            
            # Content analysis scoring
            content = results.get('content_analysis', {})
            
            if content.get('accessible') and content.get('has_forms'):
                score += 10
            
            score += len(content.get('suspicious_content', [])) * 8
            
            if content.get('external_links', 0) > 10:
                score += 5
            
            # Basic info scoring
            basic = results.get('basic_info', {})
            
            if not basic.get('is_https'):
                score += 15
            
            if basic.get('path_depth', 0) > 5:
                score += 5
            
        except:
            score = 50  # Default medium risk if calculation fails
        
        # Determine risk level
        if score >= 70:
            level = 'high'
        elif score >= 40:
            level = 'medium'
        elif score >= 20:
            level = 'low'
        else:
            level = 'very_low'
        
        return min(score, 100), level
    
    def _generate_warnings(self, results: Dict) -> List[str]:
        """Generate warnings based on analysis"""
        warnings = []
        
        try:
            security = results.get('security_check', {})
            network = results.get('network_info', {})
            content = results.get('content_analysis', {})
            basic = results.get('basic_info', {})
            
            # Security warnings
            if security.get('url_shortener'):
                warnings.append("This is a shortened URL - the actual destination is hidden")
            
            if security.get('suspicious_tld'):
                warnings.append("Uses a top-level domain commonly associated with malicious sites")
            
            if len(security.get('suspicious_keywords', [])) > 0:
                warnings.append("Contains suspicious keywords often used in phishing")
            
            if 'ip_address_url' in security.get('suspicious_patterns', []):
                warnings.append("Uses IP address instead of domain name")
            
            if 'excessive_subdomains' in security.get('suspicious_patterns', []):
                warnings.append("Has an unusual number of subdomains")
            
            # Network warnings
            if not network.get('hostname_resolved'):
                warnings.append("Domain name cannot be resolved")
            
            if network.get('status_code') == 'SSL_ERROR':
                warnings.append("SSL/TLS certificate issues detected")
            
            if len(network.get('redirects', [])) > 2:
                warnings.append("Multiple redirects detected - may be hiding final destination")
            
            # Content warnings
            if content.get('has_forms') and not basic.get('is_https'):
                warnings.append("Contains forms but not using HTTPS encryption")
            
            if len(content.get('suspicious_content', [])) > 0:
                warnings.append("Page content contains suspicious text patterns")
            
            # Basic warnings
            if not basic.get('is_https'):
                warnings.append("Not using secure HTTPS connection")
            
        except:
            warnings.append("Unable to complete full security analysis")
        
        return warnings
    
    def _generate_recommendations(self, results: Dict) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        try:
            risk_level = results.get('risk_level', 'unknown')
            
            if risk_level in ['high', 'medium']:
                recommendations.append("Do not enter personal information on this site")
                recommendations.append("Verify the URL through official channels")
                recommendations.append("Use caution when downloading files from this site")
            
            if not results.get('basic_info', {}).get('is_https'):
                recommendations.append("Avoid entering sensitive data on non-HTTPS sites")
            
            if results.get('security_check', {}).get('url_shortener'):
                recommendations.append("Expand shortened URLs to see the actual destination")
            
            if results.get('network_info', {}).get('status_code') == 'SSL_ERROR':
                recommendations.append("Do not proceed if browser shows SSL warnings")
            
            # General recommendations
            recommendations.extend([
                "Keep your browser and security software updated",
                "Be suspicious of urgent or threatening language",
                "Verify sender identity through alternative communication"
            ])
            
        except:
            recommendations.append("Exercise general caution when visiting unknown websites")
        
        return list(set(recommendations))  # Remove duplicates

# Utility functions for quick analysis
def quick_url_risk_assessment(url: str) -> Dict:
    """Quick risk assessment without deep analysis"""
    analyzer = URLAnalyzer()
    
    try:
        basic_info = analyzer._parse_url_basic(url)
        security_check = analyzer._security_checks(url)
        
        # Quick scoring
        risk_factors = 0
        risk_factors += 1 if security_check.get('url_shortener') else 0
        risk_factors += 1 if security_check.get('suspicious_tld') else 0
        risk_factors += 1 if not basic_info.get('is_https') else 0
        risk_factors += len(security_check.get('suspicious_keywords', []))
        risk_factors += len(security_check.get('suspicious_patterns', []))
        
        if risk_factors >= 3:
            risk_level = 'high'
        elif risk_factors >= 2:
            risk_level = 'medium'
        elif risk_factors >= 1:
            risk_level = 'low'
        else:
            risk_level = 'very_low'
        
        return {
            'url': url,
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'is_https': basic_info.get('is_https', False),
            'domain': basic_info.get('domain', ''),
            'warnings': analyzer._generate_warnings({
                'basic_info': basic_info,
                'security_check': security_check,
                'network_info': {},
                'content_analysis': {}
            })
        }
        
    except Exception as e:
        return {
            'url': url,
            'risk_level': 'unknown',
            'error': str(e),
            'warnings': ['Unable to analyze URL']
        }