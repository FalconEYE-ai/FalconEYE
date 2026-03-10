"""Dependency injection container for FalconEYE."""

from dataclasses import dataclass
from typing import Optional
from pathlib import Path

from ..config.config_loader import ConfigLoader
from ..config.config_models import FalconEyeConfig
from ..llm_providers.ollama_adapter import OllamaLLMAdapter
from ...domain.services.llm_service import LLMService
from ..resilience import RetryConfig, CircuitBreakerConfig
from ..vector_stores.chroma_adapter import ChromaVectorStoreAdapter
from ..persistence.chroma_metadata_repository import ChromaMetadataRepository
from ..registry.chroma_registry_adapter import ChromaIndexRegistryAdapter
from ..ast.ast_analyzer import EnhancedASTAnalyzer
from ..plugins.plugin_registry import PluginRegistry
from ...domain.services.security_analyzer import SecurityAnalyzer
from ...domain.services.context_assembler import ContextAssembler
from ...domain.services.language_detector import LanguageDetector
from ...domain.services.project_identifier import ProjectIdentifier
from ...domain.services.checksum_service import ChecksumService
from ...application.commands.index_codebase import IndexCodebaseHandler
from ...application.commands.review_file import ReviewFileHandler


@dataclass
class DIContainer:
    """
    Dependency injection container for FalconEYE.

    Assembles all components with proper dependency injection.
    This container is created once at application startup.
    """

    # Configuration
    config: FalconEyeConfig

    # Infrastructure
    llm_service: LLMService
    vector_store: ChromaVectorStoreAdapter
    metadata_repo: ChromaMetadataRepository
    index_registry: ChromaIndexRegistryAdapter
    ast_analyzer: EnhancedASTAnalyzer
    plugin_registry: PluginRegistry

    # Domain Services
    security_analyzer: SecurityAnalyzer
    context_assembler: ContextAssembler
    language_detector: LanguageDetector
    project_identifier: ProjectIdentifier
    checksum_service: ChecksumService

    # Application Handlers
    index_handler: IndexCodebaseHandler
    review_file_handler: ReviewFileHandler

    @classmethod
    def create(cls, config_path: Optional[str] = None, backend_override: Optional[str] = None) -> "DIContainer":
        """
        Create and wire all dependencies.

        Args:
            config_path: Optional path to configuration file

        Returns:
            DIContainer with all dependencies wired
        """
        # Load configuration
        config = ConfigLoader.load(config_path)

        # Create data directories if they don't exist
        Path(config.vector_store.persist_directory).mkdir(parents=True, exist_ok=True)
        Path(config.metadata.persist_directory).mkdir(parents=True, exist_ok=True)
        Path(config.index_registry.persist_directory).mkdir(parents=True, exist_ok=True)
        Path(config.output.output_directory).mkdir(parents=True, exist_ok=True)

        # Infrastructure layer - Adapters

        # Create retry config from configuration
        retry_config = RetryConfig(
            max_retries=config.llm.retry.max_retries,
            initial_delay=config.llm.retry.initial_delay,
            max_delay=config.llm.retry.max_delay,
            exponential_base=config.llm.retry.exponential_base,
            jitter=config.llm.retry.jitter,
            retryable_exceptions=(ConnectionError, TimeoutError, OSError)
        )

        # Create circuit breaker config from configuration
        circuit_breaker_config = CircuitBreakerConfig(
            failure_threshold=config.llm.circuit_breaker.failure_threshold,
            success_threshold=config.llm.circuit_breaker.success_threshold,
            timeout=config.llm.circuit_breaker.timeout,
            exclude_exceptions=(ValueError, TypeError)
        )

        # Determine which backend to use
        provider = backend_override or config.llm.provider

        if provider == "mlx":
            # MLX backend for Apple Silicon
            from ..llm_providers.mlx_adapter import MLXLLMAdapter, is_apple_silicon, is_mlx_available

            if not is_apple_silicon():
                raise RuntimeError(
                    "MLX backend requires Apple Silicon (M1/M2/M3/M4). "
                    "Use --backend ollama instead."
                )
            if not is_mlx_available():
                raise RuntimeError(
                    "MLX packages not installed. Install with: pip install falconeye[mlx]"
                )

            llm_service = MLXLLMAdapter(
                model_path=config.llm.mlx.analysis,
                ollama_host=config.llm.base_url,
                embedding_model=config.llm.model.embedding,
                max_tokens=config.llm.mlx.max_tokens,
                circuit_breaker_config=circuit_breaker_config,
            )
        else:
            llm_service = OllamaLLMAdapter(
                host=config.llm.base_url,
                chat_model=config.llm.model.analysis,
                embedding_model=config.llm.model.embedding,
                retry_config=retry_config,
                circuit_breaker_config=circuit_breaker_config,
            )

        vector_store = ChromaVectorStoreAdapter(
            persist_directory=config.vector_store.persist_directory,
            collection_prefix=config.vector_store.collection_prefix,
        )

        metadata_repo = ChromaMetadataRepository(
            persist_directory=config.metadata.persist_directory,
            collection_name=config.metadata.collection_name,
        )

        index_registry = ChromaIndexRegistryAdapter(
            persist_directory=config.index_registry.persist_directory,
            collection_name=config.index_registry.collection_name,
        )

        ast_analyzer = EnhancedASTAnalyzer()

        plugin_registry = PluginRegistry()
        plugin_registry.load_all_plugins()

        # Domain services - Business logic
        security_analyzer = SecurityAnalyzer(llm_service)
        context_assembler = ContextAssembler(vector_store, metadata_repo)
        language_detector = LanguageDetector()
        project_identifier = ProjectIdentifier()
        checksum_service = ChecksumService()

        # Application handlers - Use cases
        index_handler = IndexCodebaseHandler(
            vector_store=vector_store,
            metadata_repo=metadata_repo,
            llm_service=llm_service,
            language_detector=language_detector,
            ast_analyzer=ast_analyzer,
            project_identifier=project_identifier,
            checksum_service=checksum_service,
            index_registry=index_registry,
        )

        review_file_handler = ReviewFileHandler(
            security_analyzer=security_analyzer,
            context_assembler=context_assembler,
        )

        return cls(
            config=config,
            llm_service=llm_service,
            vector_store=vector_store,
            metadata_repo=metadata_repo,
            index_registry=index_registry,
            ast_analyzer=ast_analyzer,
            plugin_registry=plugin_registry,
            security_analyzer=security_analyzer,
            context_assembler=context_assembler,
            language_detector=language_detector,
            project_identifier=project_identifier,
            checksum_service=checksum_service,
            index_handler=index_handler,
            review_file_handler=review_file_handler,
        )

    def get_system_prompt(self, language: str) -> str:
        """
        Get system prompt for a language.

        Appends severity calibration guidelines to every prompt to ensure
        accurate severity classification across all LLM backends.

        Args:
            language: Language name

        Returns:
            System prompt string with severity guidelines
        """
        from ..plugins.base_plugin import LanguagePlugin

        severity_guidelines = LanguagePlugin.get_severity_guidelines()

        plugin = self.plugin_registry.get_plugin(language)
        if plugin:
            return plugin.get_system_prompt() + severity_guidelines

        # Default generic prompt if no plugin
        default_prompt = """You are a security expert analyzing code for vulnerabilities.
Analyze the provided code and identify any security issues.

Output format (JSON):
{
  "reviews": [
    {
      "issue": "Brief description",
      "reasoning": "Detailed explanation",
      "mitigation": "How to fix",
      "severity": "critical|high|medium|low|info",
      "confidence": 0.9,
      "code_snippet": "Vulnerable code"
    }
  ]
}

If no issues found, return: {"reviews": []}"""
        return default_prompt + severity_guidelines

    def __repr__(self) -> str:
        """String representation."""
        return f"<DIContainer: {len(self.plugin_registry.get_supported_languages())} languages>"