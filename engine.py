import re
import time
import hashlib
from typing import Dict, List, Tuple, Optional
from urllib.parse import unquote, urlparse, parse_qs, urlencode, urlunparse
import difflib
import requests
from user_agent import UserAgentManager

class DetectionResult:
    def __init__(self, vulnerable, confidence, detection_type, database_type, error_message, response_time, additional_info=None):
        self.vulnerable = vulnerable
        self.confidence = confidence
        self.detection_type = detection_type
        self.database_type = database_type
        self.error_message = error_message
        self.response_time = response_time
        self.additional_info = additional_info or {}
    
    def __str__(self):
        status = "Vulnerable" if self.vulnerable else "Not Vulnerable"
        confidence_pct = f"{self.confidence * 100:.1f}%" if self.vulnerable else "N/A"
        return f"[{status}] Type: {self.detection_type}, Confidence: {confidence_pct}, DB: {self.database_type or 'Unknown'}, Time: {self.response_time:.3f}s"

class SQLDetectionEngine:
    def __init__(self):
        self.user_agent_manager = UserAgentManager()
        self.baseline_response = None
        self.baseline_time = None
        self.baseline_hash = None
        self.baseline_length = 0
        self.response_patterns = {}
        self.time_samples = []

    def detect_waf(self, url: str, timeout: int = 10) -> Tuple[bool, str]:
        """
        Proactively detects the presence of a Web Application Firewall (WAF).
        Sends a benign but suspicious probe and checks for WAF-like responses.
        """
        waf_probes = [
            "' OR 1=1 --",
            "<script>alert('XSS')</script>",
            "UNION SELECT NULL,NULL,NULL--",
            "../etc/passwd"
        ]
        waf_indicators = [
            'firewall', 'blocked', 'forbidden', 'incapsula', 'cloudflare',
            'akamai', 'barracuda', 'f5', 'imperva', 'sucuri', 'wordfence'
        ]

        try:
            # Get a clean baseline response first
            headers = self.user_agent_manager.get_realistic_headers()
            response = requests.get(url, headers=headers, timeout=timeout)
            baseline_status = response.status_code

            # Now send a malicious-looking probe
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            if not params:
                # If no params, add a dummy one
                test_url = url + "?id=" + requests.utils.quote(waf_probes[0])
            else:
                # Add payload to the first parameter
                param_key = list(params.keys())[0]
                params[param_key] = [params[param_key][0] + waf_probes[0]]
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse(parsed_url._replace(query=new_query))

            response = requests.get(test_url, headers=headers, timeout=timeout)

            # 1. Check for a change in status code, especially to a blocking one
            if response.status_code != baseline_status and response.status_code in [403, 406, 429, 503]:
                return (True, f"Status code changed from {baseline_status} to {response.status_code} on probe.")

            # 2. Check response body for WAF indicators
            response_text = response.text.lower()
            for indicator in waf_indicators:
                if indicator in response_text:
                    return (True, f"Found WAF indicator keyword: '{indicator}' in response.")

            # 3. Check for generic blocking pages
            if "access denied" in response_text or "attack detected" in response_text:
                return (True, "Generic blocking page detected in response.")

        except requests.exceptions.RequestException as e:
            # Network errors might hide a WAF, but we can't be certain.
            return (False, f"Could not complete WAF check due to network error: {e}")

        return (False, "No clear WAF indicators found.")
        
        # Enhanced error patterns with context awareness and severity scoring
        self.error_patterns = [
            # MySQL - High Confidence Patterns
            (r"You have an error in your SQL syntax[^;]*near\s*['\"][^'\"]*['\"]", 0.98, "mysql"),
            (r"MySQL server version for the right syntax to use near", 0.97, "mysql"),
            (r"mysql_fetch_array\(\):\s*supplied argument is not a valid MySQL result", 0.95, "mysql"),
            (r"mysql_num_rows\(\):\s*supplied argument is not a valid MySQL result", 0.95, "mysql"),
            (r"Warning:\s*mysql_[a-z_]+\(\)", 0.92, "mysql"),
            (r"Unknown column '[^']*' in 'field list'", 0.94, "mysql"),
            (r"Table '[^']*' doesn't exist", 0.93, "mysql"),
            (r"Duplicate entry '[^']*' for key", 0.91, "mysql"),
            (r"Data truncated for column '[^']*' at row", 0.90, "mysql"),
            (r"Division by zero", 0.89, "mysql"),
            
            # PostgreSQL - High Confidence Patterns
            (r"ERROR:\s*syntax error at or near\s*['\"][^'\"]*['\"]", 0.98, "postgresql"),
            (r"ERROR:\s*column\s*['\"][^'\"]*['\"] does not exist", 0.96, "postgresql"),
            (r"ERROR:\s*relation\s*['\"][^'\"]*['\"] does not exist", 0.95, "postgresql"),
            (r"pg_query\(\):\s*Query failed:", 0.94, "postgresql"),
            (r"Warning:\s*pg_[a-z_]+\(\)", 0.92, "postgresql"),
            (r"ERROR:\s*invalid input syntax for", 0.93, "postgresql"),
            (r"ERROR:\s*operator does not exist:", 0.91, "postgresql"),
            (r"ERROR:\s*function\s*[a-z_]+\([^)]*\) does not exist", 0.90, "postgresql"),
            
            # Microsoft SQL Server - High Confidence Patterns
            (r"Unclosed quotation mark after the character string\s*['\"][^'\"]*['\"]", 0.98, "mssql"),
            (r"Incorrect syntax near\s*['\"][^'\"]*['\"]", 0.97, "mssql"),
            (r"Microsoft OLE DB Provider for SQL Server.*error", 0.96, "mssql"),
            (r"ODBC SQL Server Driver.*SQL Server", 0.95, "mssql"),
            (r"Warning:\s*mssql_[a-z_]+\(\)", 0.92, "mssql"),
            (r"Invalid column name\s*['\"][^'\"]*['\"]", 0.94, "mssql"),
            (r"Cannot convert value of type", 0.91, "mssql"),
            (r"String or binary data would be truncated", 0.90, "mssql"),
            
            # Oracle - High Confidence Patterns
            (r"ORA-00936:\s*missing expression", 0.97, "oracle"),
            (r"ORA-00942:\s*table or view does not exist", 0.96, "oracle"),
            (r"ORA-00904:\s*['\"][^'\"]*['\"]:\s*invalid identifier", 0.95, "oracle"),
            (r"ORA-01756:\s*quoted string not properly terminated", 0.98, "oracle"),
            (r"ORA-01722:\s*invalid number", 0.93, "oracle"),
            (r"Warning:\s*oci_[a-z_]+\(\)", 0.92, "oracle"),
            (r"PLS-\d{5}:", 0.91, "oracle"),
            
            # SQLite - High Confidence Patterns
            (r"SQLite error:\s*near\s*['\"][^'\"]*['\"]:\s*syntax error", 0.97, "sqlite"),
            (r"no such table:\s*[a-zA-Z_][a-zA-Z0-9_]*", 0.95, "sqlite"),
            (r"no such column:\s*[a-zA-Z_][a-zA-Z0-9_]*", 0.94, "sqlite"),
            (r"Warning:\s*sqlite_[a-z_]+\(\)", 0.92, "sqlite"),
            (r"SQLite3::query\(\):\s*", 0.90, "sqlite"),
            
            # Generic SQL Errors - Medium Confidence
            (r"SQL syntax.*error", 0.85, "generic"),
            (r"Warning.*SQL", 0.75, "generic"),
            (r"mysql_connect\(\)", 0.80, "mysql"),
            (r"pg_connect\(\)", 0.80, "postgresql"),
            (r"mssql_connect\(\)", 0.80, "mssql"),
            (r"oci_connect\(\)", 0.80, "oracle"),
            
            # Advanced Error Patterns
            (r"Fatal error.*SQL", 0.88, "generic"),
            (r"Database error.*syntax", 0.87, "generic"),
            (r"Query failed.*error", 0.86, "generic"),
            (r"Invalid query.*SQL", 0.85, "generic"),
        ]
        
        # False positive patterns - These should NOT be considered vulnerabilities
        self.false_positive_patterns = [
            # Educational content
            r"SQL tutorial",
            r"SQL reference",
            r"SQL documentation",
            r"SQL examples",
            r"SQL is a standard language",
            r"SQL Server Management Studio",
            r"SQL Developer",
            r"Learn SQL",
            r"SQL course",
            r"SQL training",
            r"What is SQL",
            r"SQL basics",
            r"SQL commands",

            # Security content
            r"SQL injection prevention",
            r"How to prevent SQL injection",
            r"SQL security",
            r"Parameterized queries",
            r"Prepared statements",
            r"SQL best practices",
            r"Database security",
            r"OWASP",
            r"Security guidelines",
            r"secure coding",
            r"input validation",
            r"sanitization",

            # Developer resources
            r"stackoverflow\.com",
            r"github\.com",
            r"developer\.mozilla",
            r"w3schools",
            r"code example",
            r"programming example",
            r"example\.com",
            r"test\.com",
            r"sample code",

            # Documentation & blogs
            r"API documentation",
            r"error handling",
            r"exception handling",
            r"<pre><code>",
            r"<code[^>]*>.*?SQL.*?</code>",
            r"syntax highlighter",
            r"blog post",
            r"article about",

            # Database documentation
            r"MySQL manual",
            r"PostgreSQL docs",
            r"SQL Server documentation",
            r"Oracle documentation",
            r"database manual"
        ]
        
        # Context-aware patterns for better accuracy
        self.context_patterns = {
            "form_fields": [r"<input[^>]*name\s*=\s*['\"]([^'\"]*)['\"]", r"<select[^>]*name\s*=\s*['\"]([^'\"]*)['\"]"],
            "error_containers": [r"<div[^>]*class\s*=\s*['\"][^'\"]*error[^'\"]*['\"]", r"<span[^>]*class\s*=\s*['\"][^'\"]*error[^'\"]*['\"]"],
            "debug_info": [r"<pre[^>]*>.*?</pre>", r"<code[^>]*>.*?</code>"],
            "stack_traces": [r"Stack trace:", r"Traceback", r"Exception in thread"]
        }
        
        # Database fingerprinting patterns
        self.db_fingerprints = {
            "mysql": [
                r"MySQL",
                r"MariaDB",
                r"mysql_",
                r"SHOW TABLES",
                r"INFORMATION_SCHEMA",
                r"@@version",
                r"CONCAT\(",
                r"LIMIT \d+",
                r"AUTO_INCREMENT"
            ],
            "postgresql": [
                r"PostgreSQL",
                r"pg_",
                r"CURRENT_SCHEMA",
                r"pg_catalog",
                r"OFFSET \d+",
                r"SERIAL",
                r"RETURNING"
            ],
            "mssql": [
                r"Microsoft SQL Server",
                r"T-SQL",
                r"sys\.",
                r"IDENTITY\(",
                r"TOP \d+",
                r"NVARCHAR",
                r"GETDATE\(\)"
            ],
            "oracle": [
                r"Oracle",
                r"ORA-",
                r"DUAL",
                r"ROWNUM",
                r"SYSDATE",
                r"VARCHAR2",
                r"NUMBER\("
            ],
            "sqlite": [
                r"SQLite",
                r"sqlite_",
                r"PRAGMA",
                r"AUTOINCREMENT",
                r"DATETIME\("
            ]
        }

    def set_baseline(self, baseline_response, baseline_time):
        """Enhanced baseline setting with multiple metrics"""
        self.baseline_response = baseline_response
        self.baseline_time = baseline_time
        self.baseline_hash = hashlib.md5(baseline_response.encode('utf-8', errors='ignore')).hexdigest()
        self.baseline_length = len(baseline_response)
        
        # Extract baseline patterns for comparison
        self.baseline_patterns = self._extract_response_patterns(baseline_response)
        
        # Initialize time samples for statistical analysis
        self.time_samples = [baseline_time]

    def _extract_response_patterns(self, response_text: str) -> Dict[str, int]:
        """Extract patterns from response for comparison"""
        patterns = {}
        
        # HTML structure patterns
        patterns['html_tags'] = len(re.findall(r'<[^>]+>', response_text))
        patterns['forms'] = len(re.findall(r'<form[^>]*>', response_text, re.IGNORECASE))
        patterns['inputs'] = len(re.findall(r'<input[^>]*>', response_text, re.IGNORECASE))
        patterns['tables'] = len(re.findall(r'<table[^>]*>', response_text, re.IGNORECASE))
        patterns['divs'] = len(re.findall(r'<div[^>]*>', response_text, re.IGNORECASE))
        
        # Content patterns
        patterns['numbers'] = len(re.findall(r'\b\d+\b', response_text))
        patterns['words'] = len(re.findall(r'\b[a-zA-Z]+\b', response_text))
        patterns['special_chars'] = len(re.findall(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', response_text))
        
        return patterns

    def _calculate_response_similarity(self, response1: str, response2: str) -> float:
        """Calculate similarity between two responses using multiple metrics"""
        if not response1 or not response2:
            return 0.0
        
        # Length similarity
        len1, len2 = len(response1), len(response2)
        length_similarity = 1 - abs(len1 - len2) / max(len1, len2, 1)
        
        # Hash similarity (exact match)
        hash1 = hashlib.md5(response1.encode('utf-8', errors='ignore')).hexdigest()
        hash2 = hashlib.md5(response2.encode('utf-8', errors='ignore')).hexdigest()
        hash_similarity = 1.0 if hash1 == hash2 else 0.0
        
        # Structural similarity
        patterns1 = self._extract_response_patterns(response1)
        patterns2 = self._extract_response_patterns(response2)
        
        structural_similarity = 0.0
        if patterns1 and patterns2:
            total_diff = 0
            total_max = 0
            for key in patterns1:
                if key in patterns2:
                    diff = abs(patterns1[key] - patterns2[key])
                    max_val = max(patterns1[key], patterns2[key], 1)
                    total_diff += diff
                    total_max += max_val
            
            structural_similarity = 1 - (total_diff / max(total_max, 1))
        
        # Content similarity using difflib
        content_similarity = difflib.SequenceMatcher(None, response1, response2).ratio()
        
        # Weighted average
        return (length_similarity * 0.2 + hash_similarity * 0.3 + 
                structural_similarity * 0.3 + content_similarity * 0.2)

    def _is_false_positive(self, response_text: str) -> bool:
        """Enhanced false positive detection"""
        # Check for educational/documentation content
        for pattern in self.false_positive_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        # Check for security-related content (likely educational)
        security_keywords = ['prevent', 'protection', 'secure', 'sanitize', 'validate', 'escape']
        sql_keywords = ['sql', 'injection', 'query', 'database']
        
        security_count = sum(1 for keyword in security_keywords 
                           if keyword in response_text.lower())
        sql_count = sum(1 for keyword in sql_keywords 
                       if keyword in response_text.lower())
        
        # If both security and SQL keywords are present, likely educational
        if security_count >= 2 and sql_count >= 2:
            return True
        
        return False

    def _analyze_error_context(self, response_text: str, error_match: str) -> float:
        """Analyze the context around an error to determine legitimacy"""
        confidence_modifier = 1.0
        
        # Find the position of the error
        error_pos = response_text.lower().find(error_match.lower())
        if error_pos == -1:
            return confidence_modifier
        
        # Extract context around the error (500 chars before and after)
        start = max(0, error_pos - 500)
        end = min(len(response_text), error_pos + len(error_match) + 500)
        context = response_text[start:end]
        
        # Check for error containers (HTML elements that typically contain errors)
        for pattern in self.context_patterns["error_containers"]:
            if re.search(pattern, context, re.IGNORECASE):
                confidence_modifier += 0.1
        
        # Check for debug information
        for pattern in self.context_patterns["debug_info"]:
            if re.search(pattern, context, re.IGNORECASE | re.DOTALL):
                confidence_modifier += 0.15
        
        # Check for stack traces
        for pattern in self.context_patterns["stack_traces"]:
            if re.search(pattern, context, re.IGNORECASE):
                confidence_modifier += 0.2
        
        # Check if error appears in a form context
        form_context = False
        for pattern in self.context_patterns["form_fields"]:
            if re.search(pattern, context, re.IGNORECASE):
                form_context = True
                break
        
        if form_context:
            confidence_modifier += 0.05
        
        return min(confidence_modifier, 1.5)  # Cap at 1.5x

    def _detect_database_type_advanced(self, response_text: str) -> Optional[str]:
        """Advanced database type detection with confidence scoring"""
        db_scores = {}
        
        for db_type, patterns in self.db_fingerprints.items():
            score = 0
            for pattern in patterns:
                matches = len(re.findall(pattern, response_text, re.IGNORECASE))
                score += matches
            
            if score > 0:
                db_scores[db_type] = score
        
        if db_scores:
            # Return the database type with the highest score
            return max(db_scores, key=db_scores.get)
        
        return None

    def _analyze_time_based_advanced(self, response_time: float, payload: str, request_context: Optional[Dict] = None) -> Tuple[bool, float, Dict]:
        """
        Advanced time-based analysis with statistical methods and re-verification.
        """
        if not self.time_samples or len(self.time_samples) < 1:
            return False, 0.0, {}

        self.time_samples.append(response_time)
        if len(self.time_samples) > 50:
            self.time_samples = self.time_samples[-50:]

        avg_time = sum(self.time_samples[:-1]) / len(self.time_samples[:-1])
        variance = sum((t - avg_time) ** 2 for t in self.time_samples[:-1]) / len(self.time_samples[:-1])
        std_dev = variance ** 0.5

        # CRITICAL FIX: Add minimum threshold to prevent false positives from fast responses
        MIN_THRESHOLD = 3.0  # Minimum 3 seconds delay required
        threshold = max(MIN_THRESHOLD, avg_time + (3 * std_dev) + 2)

        time_indicators = ['sleep', 'delay', 'waitfor', 'benchmark', 'pg_sleep', 'dbms_pipe', 'dbms_lock', 'randomblob']
        has_time_payload = any(indicator in payload.lower() for indicator in time_indicators)

        # CRITICAL FIX: Require time payload indicator - don't flag without it
        if not has_time_payload:
            return False, 0.0, {"reason": "No time-based function in payload"}

        if response_time > threshold and has_time_payload:
            # Initial detection looks positive, attempt re-verification if possible
            if request_context is None:
                # Cannot re-verify, return with medium confidence
                return True, 0.75, {"message": "Potential time-based vulnerability detected. Re-verification not possible."}

            # --- Re-verification Logic ---
            sleep_duration_match = re.search(r'(SLEEP|DELAY|WAITFOR|pg_sleep)\s*\(\s*(\d+)\s*\)', payload, re.IGNORECASE)
            if not sleep_duration_match:
                return True, 0.75, {"message": "Potential time-based vulnerability detected. Could not parse sleep duration for re-verification."}

            original_duration = int(sleep_duration_match.group(2))
            new_duration = original_duration * 2

            # Create new payload for verification
            new_payload = payload.replace(f"({original_duration})", f"({new_duration})", 1)

            try:
                # Re-use context to make the verification request
                url = request_context['url']
                headers = request_context['headers']
                timeout = request_context['timeout']

                parsed_url = urlparse(url)
                params = parse_qs(parsed_url.query)
                param_key = list(params.keys())[0] # Assume first param is the one being tested
                original_value = params[param_key][0]

                # We need to construct the test URL carefully, replacing the old payload part with the new one
                base_value = original_value.replace(payload, '')
                params[param_key] = [base_value + new_payload]
                new_query = urlencode(params, doseq=True)
                verify_url = urlunparse(parsed_url._replace(query=new_query))

                start_time = time.time()
                requests.get(verify_url, headers=headers, timeout=timeout + new_duration)
                verify_response_time = time.time() - start_time

                # Check if the verification response time matches the new expected delay
                if verify_response_time >= new_duration * 0.8 and verify_response_time < new_duration * 1.5:
                    return True, 0.98, {
                        "message": f"Time-based vulnerability confirmed via re-verification with {new_duration}s delay.",
                        "original_response_time": response_time,
                        "verification_response_time": verify_response_time
                    }
                else:
                    # Verification failed
                    return False, 0.0, {"message": "Initial time-based anomaly was not confirmed upon re-verification."}

            except Exception as e:
                return False, 0.0, {"message": f"Re-verification failed due to an error: {e}"}

        return False, 0.0, {}

    def _analyze_boolean_based_advanced(self, response_text: str, payload: str) -> Tuple[bool, float]:
        """
        Advanced boolean-based analysis with improved accuracy.
        CRITICAL FIX: Requires more evidence to reduce false positives from dynamic content.
        """
        if not self.baseline_response:
            return False, 0.0

        # Calculate similarity with baseline
        similarity = self._calculate_response_similarity(response_text, self.baseline_response)

        # Check for boolean payload indicators
        boolean_indicators = ['and', 'or', '=', '!=', '<>', 'true', 'false', '1=1', '1=0']
        has_boolean_payload = any(indicator in payload.lower() for indicator in boolean_indicators)

        # IMPROVED: Require boolean payload indicator
        if not has_boolean_payload:
            return False, 0.0

        # IMPROVED: More strict similarity threshold and multiple checks
        length_diff = abs(len(response_text) - len(self.baseline_response))
        length_diff_ratio = length_diff / max(len(self.baseline_response), 1)

        # Check for specific boolean response patterns
        baseline_patterns = self.baseline_patterns if hasattr(self, 'baseline_patterns') else {}
        current_patterns = self._extract_response_patterns(response_text)

        # Look for significant structural differences
        structural_diff = 0
        pattern_count = 0
        for key in baseline_patterns:
            if key in current_patterns:
                diff = abs(baseline_patterns[key] - current_patterns[key])
                max_val = max(baseline_patterns[key], current_patterns[key], 1)
                if max_val > 0:
                    structural_diff += diff / max_val
                    pattern_count += 1

        if pattern_count > 0:
            structural_diff = structural_diff / pattern_count

        # IMPROVED: Require BOTH similarity AND structural changes
        # This reduces false positives from dynamic content like ads, timestamps, etc.
        significant_difference = (similarity < 0.4 or structural_diff > 0.4 or length_diff_ratio > 0.3)

        if significant_difference:
            # IMPROVED: Lower confidence for boolean-based (prone to false positives)
            # Calculate confidence based on multiple factors
            sim_score = (1.0 - similarity) * 0.4
            struct_score = structural_diff * 0.4
            length_score = min(length_diff_ratio, 1.0) * 0.2

            confidence = min(0.75, sim_score + struct_score + length_score)  # Max 75% for boolean

            # IMPROVED: Only report if confidence is reasonable
            if confidence > 0.50:
                return True, confidence

        return False, 0.0

    def _analyze_union_based_advanced(self, response_text: str, payload: str) -> Tuple[bool, float]:
        """Advanced union-based analysis"""
        # Enhanced union detection patterns
        union_patterns = [
            (r"The used SELECT statements have a different number of columns", 0.95),
            (r"All queries combined using a UNION.*must have an equal number of expressions", 0.95),
            (r"SELECTs to the left and right of UNION do not have the same number of result columns", 0.95),
            (r"Column count doesn't match value count", 0.90),
            (r"Unknown column.*in 'field list'", 0.85),
            (r"Operand should contain \d+ column\(s\)", 0.90),
            (r"ORDER BY position \d+ is not in select list", 0.85),
            (r"Invalid column ordinal: \d+", 0.80),
        ]
        
        # Check for union payload indicators
        union_indicators = ['union', 'select', 'order by', 'group by']
        has_union_payload = any(indicator in payload.lower() for indicator in union_indicators)
        
        if not has_union_payload:
            return False, 0.0
        
        # Check for union-specific error patterns
        for pattern, confidence in union_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True, confidence
        
        # Check for successful union injection indicators
        success_patterns = [
            r"<td[^>]*>\s*\d+\s*</td>\s*<td[^>]*>\s*\d+\s*</td>",  # Multiple columns with numbers
            r"user\(\)|database\(\)|version\(\)",  # Database functions
            r"information_schema",  # Information schema access
            r"mysql\.user|pg_user|sys\.databases",  # System tables
        ]
        
        for pattern in success_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True, 0.85
        
        return False, 0.0

    def analyze_response_comprehensive(self, response_text, payload, response_time, injection_type, request_context=None):
        """Comprehensive response analysis with maximum accuracy"""
        if self.baseline_response is None:
            return DetectionResult(
                False, 0, injection_type, None, None, response_time, 
                {"error": "Baseline response not set. Please establish a baseline before testing."}
            )

        # Decode URL-encoded payload for better analysis
        decoded_payload = unquote(payload)
        
        # Check for false positives first
        if self._is_false_positive(response_text):
            return DetectionResult(
                False, 0, injection_type, None, None, response_time,
                {"reason": "False positive detected - educational/documentation content"}
            )

        # Error-based detection with enhanced context analysis
        for pattern, base_confidence, db_hint in self.error_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE | re.DOTALL)
            if match:
                matched_error = match.group(0)

                # CRITICAL FIX: Verify payload caused this error (correlation check)
                correlation_found = False

                # Check if payload is reflected in the error message
                if decoded_payload.lower() in matched_error.lower():
                    correlation_found = True
                else:
                    # Extract SQL fragment from error message
                    sql_fragment_match = re.search(r"(?:near|use|syntax to use near|at or near)\s+['\"]([^'\"]{1,200})['\"]|'([^']{1,200})'", matched_error, re.IGNORECASE)
                    if sql_fragment_match:
                        error_sql = (sql_fragment_match.group(1) or sql_fragment_match.group(2) or "").lower()
                        # Check if any significant part of payload appears in error
                        payload_parts = [p for p in decoded_payload.lower().split() if len(p) > 3]
                        if any(part in error_sql for part in payload_parts):
                            correlation_found = True

                    # Also check if payload is reflected anywhere in the response
                    if decoded_payload[:50].lower() in response_text.lower():
                        correlation_found = True

                # If no correlation, this error existed before our payload
                if not correlation_found and base_confidence < 0.95:
                    continue  # Skip to next pattern

                # Analyze context around the error
                context_modifier = self._analyze_error_context(response_text, matched_error)

                # IMPROVED: Reduce confidence if correlation is weak
                if not correlation_found:
                    context_modifier *= 0.7  # Reduce confidence by 30%

                final_confidence = min(0.99, base_confidence * context_modifier)

                # Advanced database type detection
                detected_db = self._detect_database_type_advanced(response_text) or db_hint

                return DetectionResult(
                    True, final_confidence, "error_based", detected_db,
                    f"SQL error pattern detected: {matched_error[:100]}...",
                    response_time,
                    {
                        "error_pattern": pattern,
                        "matched_text": matched_error,
                        "context_confidence": context_modifier,
                        "payload_decoded": decoded_payload,
                        "payload_correlation": correlation_found
                    }
                )

        # Time-based detection with statistical analysis
        if injection_type == "time_based":
            is_vulnerable, confidence, additional_info = self._analyze_time_based_advanced(response_time, decoded_payload, request_context)
            if is_vulnerable:
                # Add standard info to the details from the analysis function
                details = {
                    "baseline_time": self.baseline_time,
                    "response_time": response_time,
                    "payload_decoded": decoded_payload
                }
                details.update(additional_info)

                return DetectionResult(
                    True, confidence, injection_type, 
                    self._detect_database_type_advanced(response_text),
                    details.get("message", "Time-based vulnerability detected"),
                    response_time,
                    details
                )

        # Boolean-based detection with advanced similarity analysis
        if injection_type == "boolean":
            is_vulnerable, confidence = self._analyze_boolean_based_advanced(response_text, decoded_payload)
            if is_vulnerable:
                return DetectionResult(
                    True, confidence, injection_type,
                    self._detect_database_type_advanced(response_text),
                    "Boolean-based vulnerability detected through response analysis", 
                    response_time,
                    {
                        "similarity_score": self._calculate_response_similarity(response_text, self.baseline_response),
                        "payload_decoded": decoded_payload
                    }
                )

        # Union-based detection with enhanced pattern matching
        if injection_type == "union":
            is_vulnerable, confidence = self._analyze_union_based_advanced(response_text, decoded_payload)
            if is_vulnerable:
                return DetectionResult(
                    True, confidence, injection_type,
                    self._detect_database_type_advanced(response_text),
                    "Union-based vulnerability detected", 
                    response_time,
                    {
                        "payload_decoded": decoded_payload
                    }
                )

        # Advanced heuristic analysis for other injection types
        if injection_type in ["advanced", "bypass", "json"]:
            # Check for subtle indicators
            subtle_indicators = [
                (r"Warning.*mysql", 0.75, "mysql"),
                (r"Warning.*pg_", 0.75, "postgresql"),
                (r"Warning.*mssql", 0.75, "mssql"),
                (r"Warning.*oci_", 0.75, "oracle"),
                (r"Notice.*Undefined", 0.65, "generic"),
                (r"Parse error.*syntax error", 0.70, "generic"),
                (r"Fatal error.*Call to undefined function", 0.60, "generic"),
            ]
            
            for pattern, confidence, db_type in subtle_indicators:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return DetectionResult(
                        True, confidence, injection_type, db_type,
                        f"Subtle vulnerability indicator detected: {pattern}", 
                        response_time,
                        {"payload_decoded": decoded_payload}
                    )

        # No vulnerability detected
        return DetectionResult(
            False, 0, injection_type, None, None, response_time,
            {
                "similarity_score": self._calculate_response_similarity(response_text, self.baseline_response) if self.baseline_response else 0,
                "payload_decoded": decoded_payload,
                "analysis": "No vulnerability indicators found"
            }
        )

    def detect_database_type(self, response_text):
        """Legacy method for backward compatibility"""
        return self._detect_database_type_advanced(response_text)

    def detect_union_based(self, response_text):
        """Legacy method for backward compatibility"""
        is_vulnerable, _ = self._analyze_union_based_advanced(response_text, "")
        return is_vulnerable
        
    def detect_boolean_based(self, response_text, baseline_response):
        """Legacy method for backward compatibility"""
        if baseline_response:
            self.baseline_response = baseline_response
        is_vulnerable, _ = self._analyze_boolean_based_advanced(response_text, "")
        return is_vulnerable

if __name__ == "__main__":
    # Test the enhanced detection engine
    engine = SQLDetectionEngine()
    engine.set_baseline("Sample baseline response", 0.5)
    
    # Test error-based detection
    result = engine.analyze_response_comprehensive(
        "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''test'' at line 1", 
        "' OR 1=1 --", 1.0, "error_based"
    )
    print(f"Test Result: {result}")
    print(f"Vulnerable: {result.vulnerable}, Confidence: {result.confidence:.2f}")