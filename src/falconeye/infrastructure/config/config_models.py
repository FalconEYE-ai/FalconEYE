"""Configuration data models using Pydantic."""

from typing import List
from pydantic import BaseModel, Field, field_validator, ConfigDict


class LLMModelConfig(BaseModel):
    """LLM model configuration."""
    analysis: str = Field(
        default="qwen3-coder:30b",
        description="Model for security analysis"
    )
    embedding: str = Field(
        default="embeddinggemma:300m",
        description="Model for generating embeddings"
    )


class MLXModelConfig(BaseModel):
    """MLX model configuration for Apple Silicon."""
    analysis: str = Field(
        default="mlx-community/Qwen3-Coder-30B-A3B-Instruct-4bit",
        description="HuggingFace model path for MLX inference"
    )
    max_tokens: int = Field(
        default=32768,
        ge=1024,
        le=131072,
        description="Maximum tokens to generate per response (higher needed for thinking models)"
    )


class RetryConfigModel(BaseModel):
    """Retry logic configuration."""
    max_retries: int = Field(
        default=3,
        ge=0,
        le=10,
        description="Maximum number of retry attempts"
    )
    initial_delay: float = Field(
        default=1.0,
        ge=0.1,
        le=60.0,
        description="Initial delay in seconds before first retry"
    )
    max_delay: float = Field(
        default=30.0,
        ge=1.0,
        le=300.0,
        description="Maximum delay in seconds between retries"
    )
    exponential_base: float = Field(
        default=2.0,
        ge=1.5,
        le=3.0,
        description="Exponential backoff base"
    )
    jitter: float = Field(
        default=0.1,
        ge=0.0,
        le=0.5,
        description="Jitter factor (0.1 = ±10% randomness)"
    )


class CircuitBreakerConfigModel(BaseModel):
    """Circuit breaker configuration."""
    failure_threshold: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Number of failures before opening circuit"
    )
    success_threshold: int = Field(
        default=2,
        ge=1,
        le=10,
        description="Number of successes to close circuit from half-open"
    )
    timeout: float = Field(
        default=60.0,
        ge=10.0,
        le=600.0,
        description="Seconds to wait before transitioning to half-open"
    )


class LLMConfig(BaseModel):
    """LLM provider configuration."""
    provider: str = Field(
        default="ollama",
        description="LLM provider (ollama, mlx)"
    )
    model: LLMModelConfig = Field(default_factory=LLMModelConfig)
    mlx: MLXModelConfig = Field(default_factory=MLXModelConfig)
    base_url: str = Field(
        default="http://localhost:11434",
        description="Base URL for LLM API"
    )
    timeout: int = Field(
        default=120,
        ge=10,
        le=600,
        description="Request timeout in seconds"
    )
    max_retries: int = Field(
        default=3,
        ge=0,
        le=10,
        description="[DEPRECATED] Use retry.max_retries instead"
    )
    retry: RetryConfigModel = Field(
        default_factory=RetryConfigModel,
        description="Retry logic configuration"
    )
    circuit_breaker: CircuitBreakerConfigModel = Field(
        default_factory=CircuitBreakerConfigModel,
        description="Circuit breaker configuration"
    )

    @field_validator('provider')
    @classmethod
    def validate_provider(cls, v):
        """Ensure provider is valid."""
        valid = ["ollama", "mlx"]
        if v not in valid:
            raise ValueError(f"provider must be one of {valid}")
        return v


class VectorStoreConfig(BaseModel):
    """Vector store configuration."""
    provider: str = Field(
        default="chroma",
        description="Vector store provider (chroma, postgres)"
    )
    persist_directory: str = Field(
        default="./falconeye_data/vectorstore",
        description="Directory for vector store persistence"
    )
    collection_prefix: str = Field(
        default="falconeye",
        description="Prefix for collection names"
    )


class MetadataConfig(BaseModel):
    """Metadata repository configuration."""
    provider: str = Field(
        default="chroma",
        description="Metadata provider (chroma, postgres)"
    )
    persist_directory: str = Field(
        default="./falconeye_data/metadata",
        description="Directory for metadata persistence"
    )
    collection_name: str = Field(
        default="metadata",
        description="Collection name for metadata"
    )


class IndexRegistryConfig(BaseModel):
    """Index registry configuration for project tracking."""
    persist_directory: str = Field(
        default="./falconeye_data/registry",
        description="Directory for registry persistence"
    )
    collection_name: str = Field(
        default="index_registry",
        description="Collection name for index registry"
    )


class ChunkingConfig(BaseModel):
    """Code chunking configuration."""
    default_size: int = Field(
        default=50,
        ge=10,
        le=500,
        description="Default lines per chunk"
    )
    default_overlap: int = Field(
        default=10,
        ge=0,
        le=100,
        description="Default lines of overlap between chunks"
    )
    max_chunk_size: int = Field(
        default=200,
        ge=50,
        le=1000,
        description="Maximum lines per chunk"
    )

    @field_validator('default_overlap')
    @classmethod
    def validate_overlap(cls, v, info):
        """Ensure overlap is less than chunk size."""
        if 'default_size' in info.data and v >= info.data['default_size']:
            raise ValueError("overlap must be less than chunk_size")
        return v


class AnalysisConfig(BaseModel):
    """Security analysis configuration."""
    top_k_context: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Number of similar chunks for RAG context"
    )
    validate_findings: bool = Field(
        default=False,
        description="Enable AI-based validation to reduce false positives"
    )
    batch_size: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Number of files to process in parallel"
    )


class LanguagesConfig(BaseModel):
    """Language support configuration."""
    enabled: List[str] = Field(
        default_factory=lambda: [
            "python",
            "javascript",
            "typescript",
            "go",
            "rust",
            "c",
            "cpp",
            "java",
            "dart",
            "php",
        ],
        description="List of enabled languages"
    )


class FileDiscoveryConfig(BaseModel):
    """File discovery configuration."""
    default_exclusions: List[str] = Field(
        default_factory=lambda: [
            "*/node_modules/*",
            "*/venv/*",
            "*/virtualenv/*",
            "*/.git/*",
            "*/dist/*",
            "*/build/*",
            "*/__pycache__/*",
            "*/target/*",
            "*.min.js",
            "*.pyc",
        ],
        description="Default file/directory exclusion patterns"
    )


class OutputConfig(BaseModel):
    """Output configuration."""
    default_format: str = Field(
        default="json",
        description="Default output format (console, json, sarif, html)"
    )
    color: bool = Field(
        default=True,
        description="Enable colored console output"
    )
    verbose: bool = Field(
        default=False,
        description="Enable verbose output"
    )
    save_to_file: bool = Field(
        default=True,
        description="Save output to file (auto-saves JSON + HTML reports)"
    )
    output_directory: str = Field(
        default="./falconeye_reports",
        description="Directory for saving reports"
    )

    @field_validator('default_format')
    @classmethod
    def validate_format(cls, v):
        """Ensure format is valid."""
        valid_formats = ["console", "json", "sarif", "html"]
        if v not in valid_formats:
            raise ValueError(f"format must be one of {valid_formats}")
        return v


class LoggingConfig(BaseModel):
    """Logging configuration."""
    level: str = Field(
        default="INFO",
        description="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)"
    )
    file: str = Field(
        default="./falconeye.log",
        description="Log file path"
    )
    console: bool = Field(
        default=True,
        description="Enable console logging"
    )
    rotation: str = Field(
        default="daily",
        description="Log rotation strategy (daily, none)"
    )
    retention_days: int = Field(
        default=30,
        ge=1,
        le=365,
        description="Number of days to retain logs"
    )

    @field_validator('level')
    @classmethod
    def validate_level(cls, v):
        """Ensure log level is valid."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        v = v.upper()
        if v not in valid_levels:
            raise ValueError(f"level must be one of {valid_levels}")
        return v

    @field_validator('rotation')
    @classmethod
    def validate_rotation(cls, v):
        """Ensure rotation strategy is valid."""
        valid_strategies = ["daily", "none"]
        v = v.lower()
        if v not in valid_strategies:
            raise ValueError(f"rotation must be one of {valid_strategies}")
        return v


class FalconEyeConfig(BaseModel):
    """Complete FalconEYE configuration."""
    model_config = ConfigDict(
        extra="forbid",  # Forbid extra fields
        validate_assignment=True  # Validate on assignment
    )

    llm: LLMConfig = Field(default_factory=LLMConfig)
    vector_store: VectorStoreConfig = Field(default_factory=VectorStoreConfig)
    metadata: MetadataConfig = Field(default_factory=MetadataConfig)
    index_registry: IndexRegistryConfig = Field(default_factory=IndexRegistryConfig)
    chunking: ChunkingConfig = Field(default_factory=ChunkingConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    languages: LanguagesConfig = Field(default_factory=LanguagesConfig)
    file_discovery: FileDiscoveryConfig = Field(default_factory=FileDiscoveryConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    def to_yaml(self) -> str:
        """Convert configuration to YAML string."""
        import yaml
        return yaml.dump(self.model_dump(), default_flow_style=False, sort_keys=False)