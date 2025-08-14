import os
import urllib.parse
from typing import List, Dict, Tuple
import re

class DomainManager:
    """Manages domain input and validation for SQL injection testing"""
    
    def __init__(self):
        self.domains = []
        self.valid_domains = []
        self.invalid_domains = []
    
    def validate_url(self, url: str) -> Tuple[bool, str]:
        """Validate a single URL with enhanced checks"""
        try:
            # Clean the URL
            url = url.strip()
            
            # Skip empty lines and comments
            if not url or url.startswith('#'):
                return False, "Empty or comment line"
            
            # Add http:// if no scheme is provided
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            parsed = urllib.parse.urlparse(url)
            
            # Check if URL has required components
            if not parsed.netloc:
                return False, "Invalid domain format - no hostname"
            
            # Check for valid hostname format
            hostname_pattern = re.compile(
                r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
            )
            
            # Extract hostname (remove port if present)
            hostname = parsed.netloc.split(':')[0]
            
            # Allow localhost and IP addresses
            if hostname not in ['localhost', '127.0.0.1'] and not self._is_valid_ip(hostname):
                if not hostname_pattern.match(hostname):
                    return False, "Invalid hostname format"
            
            # Check if URL has query parameters
            if not parsed.query:
                return False, "URL must contain query parameters for testing"
            
            # Parse query parameters
            params = urllib.parse.parse_qs(parsed.query)
            if not params:
                return False, "No valid query parameters found"
            
            # Check for at least one parameter with a value
            has_testable_param = False
            for param_name, param_values in params.items():
                if param_values and param_values[0]:  # Has non-empty value
                    has_testable_param = True
                    break
            
            if not has_testable_param:
                return False, "No testable parameters found (all parameters are empty)"
            
            return True, "Valid URL"
            
        except Exception as e:
            return False, f"URL validation error: {str(e)}"
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IP address"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                if not 0 <= int(part) <= 255:
                    return False
            return True
        except (ValueError, AttributeError):
            return False
    
    def load_domains_from_file(self, file_path: str) -> Tuple[int, int, List[str]]:
        """Load domains from text file with enhanced error handling"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        domains = []
        errors = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Basic URL format check before adding
                if '://' in line or line.startswith('www.') or '.' in line:
                    domains.append(line)
                else:
                    errors.append(f"Line {line_num}: Invalid URL format - {line}")
            
            return len(domains), len(errors), domains
            
        except Exception as e:
            raise Exception(f"Error reading file: {str(e)}")
    
    def validate_domains(self, domains: List[str]) -> Dict[str, List[str]]:
        """Validate a list of domains with detailed results"""
        results = {
            'valid': [],
            'invalid': [],
            'errors': []
        }
        
        for domain in domains:
            is_valid, message = self.validate_url(domain)
            
            if is_valid:
                results['valid'].append(domain)
            else:
                results['invalid'].append(f"{domain}: {message}")
        
        return results
    
    def filter_valid_domains(self, domains: List[str]) -> Tuple[List[str], List[str]]:
        """Filter domains into valid and invalid lists"""
        valid_domains = []
        invalid_domains = []
        
        for domain in domains:
            is_valid, message = self.validate_url(domain)
            
            if is_valid:
                valid_domains.append(domain)
            else:
                invalid_domains.append(domain)
        
        return valid_domains, invalid_domains
    
    def extract_parameters_from_url(self, url: str) -> List[str]:
        """Extract parameter names from URL"""
        try:
            # Add http:// if no scheme is provided
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            return list(params.keys())
        except:
            return []
    
    def format_url_for_testing(self, url: str) -> str:
        """Ensure URL is properly formatted for testing"""
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url
    
    def get_domain_info(self, url: str) -> Dict[str, str]:
        """Get detailed information about a domain"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                
            parsed = urllib.parse.urlparse(url)
            params = self.extract_parameters_from_url(url)
            
            return {
                'scheme': parsed.scheme,
                'hostname': parsed.netloc,
                'path': parsed.path,
                'parameters': params,
                'parameter_count': len(params),
                'full_url': url
            }
        except Exception as e:
            return {
                'error': str(e),
                'full_url': url
            }
    
    def clean_domain_list(self, domains: List[str]) -> List[str]:
        """Clean and normalize a list of domains"""
        cleaned_domains = []
        
        for domain in domains:
            domain = domain.strip()
            
            # Skip empty lines and comments
            if not domain or domain.startswith('#'):
                continue
                
            # Remove duplicate entries
            if domain not in cleaned_domains:
                cleaned_domains.append(domain)
        
        return cleaned_domains
    
    def save_domains_to_file(self, domains: List[str], file_path: str, include_comments: bool = True) -> bool:
        """Save domains to a text file with optional comments"""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                if include_comments:
                    f.write("# SQL Injection Testing Domains\n")
                    f.write("# Format: One URL per line with parameters\n")
                    f.write("# Example: http://example.com/page.php?id=1&search=test\n")
                    f.write("# Lines starting with # are comments\n\n")
                
                for domain in domains:
                    f.write(domain + '\n')
            
            return True
        except Exception as e:
            raise Exception(f"Error saving domains: {str(e)}")