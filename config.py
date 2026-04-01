"""
config.py - Configuration loader and logging setup for SQL-Tester.
Loads settings from config.yaml with hardcoded fallback defaults.
Provides a centralized logger with file + console handlers.
"""

import os
import logging
import copy
from logging.handlers import RotatingFileHandler

# Optional: yaml support
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# ═══════════════════════════════════════════════════════════
# Default configuration (used when config.yaml is missing)
# ═══════════════════════════════════════════════════════════

DEFAULT_CONFIG = {
    "scanning": {
        "mode": "sync",
        "concurrency": 10,
        "timeout": 10,
        "retry": 3,
        "delay": 1.0,
        "max_payloads_per_run": 50,
    },
    "detection": {
        "confidence_threshold": 0.75,
        "false_positive_filter": True,
        "enable_reverification": True,
        "time_based_min_delay": 3,
    },
    "proxy": {
        "enabled": False,
        "type": "http",
        "host": "127.0.0.1",
        "port": 9050,
    },
    "user_agent": {
        "rotate": True,
        "custom_agents_file": None,
    },
    "output": {
        "log_level": "INFO",
        "log_to_file": True,
        "log_file": "sqltester.log",
        "save_responses": False,
        "output_dir": "./results",
    },
}


class Config:
    """
    Configuration manager for SQL-Tester.
    
    Loads config.yaml if available, falls back to DEFAULT_CONFIG.
    Provides dot-notation access via get() method.
    
    Usage:
        config = Config()
        timeout = config.get("scanning.timeout", 10)
        log_level = config.get("output.log_level", "INFO")
    """

    def __init__(self, config_path: str = None):
        if config_path is None:
            # Look for config.yaml in the same directory as this file
            base_dir = os.path.dirname(os.path.abspath(__file__))
            config_path = os.path.join(base_dir, "config.yaml")
        
        self.config_path = config_path
        self.data = self._load(config_path)
        self._logger = None

    def _load(self, path: str) -> dict:
        """Load config from YAML file, fall back to defaults if missing."""
        config = copy.deepcopy(DEFAULT_CONFIG)

        if not HAS_YAML:
            return config

        if not os.path.exists(path):
            # Auto-create config.yaml with defaults
            self._write_default_config(path)
            return config

        try:
            with open(path, "r", encoding="utf-8") as f:
                user_config = yaml.safe_load(f)

            if user_config and isinstance(user_config, dict):
                self._deep_merge(config, user_config)
        except Exception:
            # If YAML is corrupt, use defaults silently
            pass

        return config

    def _deep_merge(self, base: dict, override: dict):
        """Recursively merge override into base dict."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value

    def _write_default_config(self, path: str):
        """Write default config.yaml file."""
        if not HAS_YAML:
            return

        try:
            default_yaml = """# ═══════════════════════════════════════════════════════════
# SQL-Tester Configuration
# These are default values. GUI settings override at runtime.
# ═══════════════════════════════════════════════════════════

scanning:
  mode: sync            # sync | async (async available in future)
  concurrency: 10       # Max concurrent requests (async mode)
  timeout: 10           # Request timeout in seconds
  retry: 3              # Retry attempts on failure
  delay: 1.0            # Delay between requests (seconds)
  max_payloads_per_run: 50  # Limit payloads in quick scan mode

detection:
  confidence_threshold: 0.75
  false_positive_filter: true
  enable_reverification: true
  time_based_min_delay: 3

proxy:
  enabled: false
  type: http            # http | socks5
  host: 127.0.0.1
  port: 9050

user_agent:
  rotate: true
  custom_agents_file: null

output:
  log_level: INFO       # DEBUG | INFO | WARNING | ERROR
  log_to_file: true
  log_file: sqltester.log
  save_responses: false
  output_dir: ./results
"""
            with open(path, "w", encoding="utf-8") as f:
                f.write(default_yaml)
        except Exception:
            pass  # Non-critical: defaults still work in memory

    def get(self, key_path: str, default=None):
        """
        Access nested config values using dot notation.
        
        Args:
            key_path: Dot-separated path, e.g. "scanning.timeout"
            default: Fallback value if key doesn't exist
            
        Returns:
            Config value or default
            
        Example:
            config.get("scanning.timeout", 10)  → 10
            config.get("proxy.enabled", False)   → False
        """
        keys = key_path.split(".")
        value = self.data
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value

    def get_section(self, section: str) -> dict:
        """Get an entire config section as a dict."""
        return self.data.get(section, {})

    @property
    def logger(self) -> logging.Logger:
        """Lazy-initialize and return the application logger."""
        if self._logger is None:
            self._logger = self._setup_logging()
        return self._logger

    def _setup_logging(self) -> logging.Logger:
        """Setup structured logging with file + console handlers."""
        logger = logging.getLogger("sqltester")

        # Prevent duplicate handlers on re-init
        if logger.handlers:
            return logger

        log_level_str = self.get("output.log_level", "INFO").upper()
        log_level = getattr(logging, log_level_str, logging.INFO)
        logger.setLevel(log_level)

        # Format
        fmt = logging.Formatter(
            fmt="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_handler.setFormatter(fmt)
        logger.addHandler(console_handler)

        # File handler (optional, based on config)
        if self.get("output.log_to_file", True):
            try:
                log_file = self.get("output.log_file", "sqltester.log")
                file_handler = RotatingFileHandler(
                    log_file,
                    maxBytes=5 * 1024 * 1024,  # 5 MB
                    backupCount=3,
                    encoding="utf-8",
                )
                file_handler.setLevel(log_level)
                file_handler.setFormatter(fmt)
                logger.addHandler(file_handler)
            except Exception:
                # Can't write to file — console only
                pass

        return logger


# ═══════════════════════════════════════════════════════════
# Global access functions
# ═══════════════════════════════════════════════════════════

_config_instance = None


def get_config(config_path: str = None) -> Config:
    """Get the global Config singleton."""
    global _config_instance
    if _config_instance is None:
        _config_instance = Config(config_path)
    return _config_instance


def get_logger(name: str = None) -> logging.Logger:
    """
    Get a named logger under the 'sqltester' hierarchy.
    
    Args:
        name: Optional child logger name (e.g. "engine", "scanner")
              If None, returns the root 'sqltester' logger.
              
    Returns:
        logging.Logger instance
        
    Usage:
        logger = get_logger("engine")
        logger.info("Scan started", extra={"target": url})
    """
    config = get_config()
    base_logger = config.logger
    if name:
        return base_logger.getChild(name)
    return base_logger
