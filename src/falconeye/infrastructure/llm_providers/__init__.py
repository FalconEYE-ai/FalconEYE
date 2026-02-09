"""LLM provider implementations."""

from .ollama_adapter import OllamaLLMAdapter

__all__ = ["OllamaLLMAdapter"]

# Conditional MLX imports (only available on Apple Silicon with mlx installed)
try:
    from .mlx_adapter import MLXLLMAdapter, is_apple_silicon, is_mlx_available
    __all__ += ["MLXLLMAdapter", "is_apple_silicon", "is_mlx_available"]
except ImportError:
    # MLX not installed - provide stubs
    def is_apple_silicon() -> bool:
        import platform
        return platform.system() == "Darwin" and platform.machine() == "arm64"

    def is_mlx_available() -> bool:
        return False

    MLXLLMAdapter = None
    __all__ += ["MLXLLMAdapter", "is_apple_silicon", "is_mlx_available"]
