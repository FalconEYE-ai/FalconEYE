"""Configuration loader with support for YAML files and environment variables."""

import os
from pathlib import Path
from typing import Optional, Dict, Any
import yaml

from .config_models import FalconEyeConfig


class ConfigLoader:
    """
    Load and manage FalconEYE configuration.

    Configuration is loaded in the following order (later sources override earlier):
    1. Default configuration (embedded in code)
    2. Global configuration (~/.falconeye/config.yaml)
    3. Project configuration (./falconeye.yaml or .falconeye.yaml)
    4. User-specified configuration file
    5. Environment variables (FALCONEYE_*)
    """

    DEFAULT_CONFIG_PATHS = [
        Path.home() / ".falconeye" / "config.yaml",
        Path("./falconeye.yaml"),
        Path("./.falconeye.yaml"),
    ]

    @classmethod
    def load(cls, config_path: Optional[str] = None) -> FalconEyeConfig:
        """
        Load configuration from multiple sources.

        Args:
            config_path: Optional path to configuration file

        Returns:
            FalconEyeConfig instance
        """
        # Start with default configuration
        config_dict = {}

        # Load from default paths
        for path in cls.DEFAULT_CONFIG_PATHS:
            if path.exists():
                config_dict = cls._merge_dicts(
                    config_dict,
                    cls._load_yaml_file(path)
                )

        # Load from user-specified path
        if config_path:
            user_path = Path(config_path)
            if not user_path.exists():
                raise FileNotFoundError(f"Configuration file not found: {config_path}")
            config_dict = cls._merge_dicts(
                config_dict,
                cls._load_yaml_file(user_path)
            )

        # Override with environment variables
        config_dict = cls._merge_dicts(
            config_dict,
            cls._load_from_env()
        )

        # Create and validate configuration
        return FalconEyeConfig(**config_dict)

    @staticmethod
    def _load_yaml_file(path: Path) -> Dict[str, Any]:
        """
        Load YAML configuration file.

        Args:
            path: Path to YAML file

        Returns:
            Configuration dictionary
        """
        try:
            with open(path, 'r') as f:
                data = yaml.safe_load(f)
                return data if data else {}
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in {path}: {e}")

    @staticmethod
    def _merge_dicts(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recursively merge two dictionaries.

        Args:
            base: Base dictionary
            override: Dictionary with overrides

        Returns:
            Merged dictionary
        """
        result = base.copy()

        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = ConfigLoader._merge_dicts(result[key], value)
            else:
                result[key] = value

        return result

    # Known top-level config sections that map to FalconEyeConfig fields
    KNOWN_CONFIG_SECTIONS = {
        "llm", "vector_store", "metadata", "index_registry",
        "chunking", "analysis", "languages", "file_discovery",
        "output", "logging",
    }

    @staticmethod
    def _load_from_env() -> Dict[str, Any]:
        """
        Load configuration from environment variables.

        Environment variables are prefixed with FALCONEYE_ and use underscores
        to represent nested keys. For example:
        - FALCONEYE_LLM_BASE_URL -> llm.base_url
        - FALCONEYE_OUTPUT_COLOR -> output.color

        Only variables whose first key part maps to a known config section
        are processed. This prevents env vars like FALCONEYE_HOME from
        polluting the config and causing validation errors.

        Returns:
            Configuration dictionary from environment
        """
        config = {}
        prefix = "FALCONEYE_"

        for key, value in os.environ.items():
            if not key.startswith(prefix):
                continue

            # Remove prefix and convert to lowercase
            key_parts = key[len(prefix):].lower().split('_')

            # Filter: only process env vars that map to known config sections
            if key_parts[0] not in ConfigLoader.KNOWN_CONFIG_SECTIONS:
                continue

            # Build nested dictionary
            current = config
            for part in key_parts[:-1]:
                if part not in current:
                    current[part] = {}
                current = current[part]

            # Set the value (handle type conversion)
            final_key = key_parts[-1]
            current[final_key] = ConfigLoader._convert_env_value(value)

        return config

    @staticmethod
    def _convert_env_value(value: str) -> Any:
        """
        Convert environment variable string to appropriate type.

        Args:
            value: String value from environment

        Returns:
            Converted value
        """
        # Boolean
        if value.lower() in ('true', 'yes', '1'):
            return True
        if value.lower() in ('false', 'no', '0'):
            return False

        # Integer
        try:
            return int(value)
        except ValueError:
            pass

        # Float
        try:
            return float(value)
        except ValueError:
            pass

        # List (comma-separated)
        if ',' in value:
            return [item.strip() for item in value.split(',')]

        # String
        return value

    @staticmethod
    def create_default_config(path: Optional[str] = None) -> Path:
        """
        Create a default configuration file.

        Args:
            path: Optional path for config file. If not provided, creates in ~/.falconeye/

        Returns:
            Path to created configuration file
        """
        if path:
            config_path = Path(path)
        else:
            config_dir = Path.home() / ".falconeye"
            config_dir.mkdir(parents=True, exist_ok=True)
            config_path = config_dir / "config.yaml"

        # Generate default configuration
        default_config = FalconEyeConfig()
        yaml_content = default_config.to_yaml()

        # Add comments to YAML
        yaml_with_comments = f"""# FalconEYE v2.0 Configuration
#
# This file configures FalconEYE's behavior. You can override these settings
# with environment variables (FALCONEYE_*) or by specifying --config at runtime.

{yaml_content}
"""

        # Write to file
        config_path.write_text(yaml_with_comments)

        return config_path

    @staticmethod
    def get_config_info() -> Dict[str, Any]:
        """
        Get information about configuration sources.

        Returns:
            Dictionary with configuration information
        """
        info = {
            "default_paths": [str(p) for p in ConfigLoader.DEFAULT_CONFIG_PATHS],
            "existing_configs": [],
            "env_overrides": [],
        }

        # Check which default configs exist
        for path in ConfigLoader.DEFAULT_CONFIG_PATHS:
            if path.exists():
                info["existing_configs"].append(str(path))

        # Check for environment overrides
        prefix = "FALCONEYE_"
        for key in os.environ.keys():
            if key.startswith(prefix):
                info["env_overrides"].append(key)

        return info