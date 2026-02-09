"""MLX LLM adapter for Apple Silicon local inference."""

import asyncio
import platform
import time
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, Callable

from ...domain.services.llm_service import LLMService
from ...domain.models.prompt import PromptContext
from ..logging import FalconEyeLogger, logging_context
from ..resilience import CircuitBreaker, CircuitBreakerConfig


def is_apple_silicon() -> bool:
    """Check if running on Apple Silicon (ARM64 Mac)."""
    return platform.system() == "Darwin" and platform.machine() == "arm64"


def is_mlx_available() -> bool:
    """Check if mlx and mlx_lm packages are installed."""
    try:
        import mlx  # noqa: F401
        import mlx_lm  # noqa: F401
        return True
    except ImportError:
        return False


class MLXLLMAdapter(LLMService):
    """
    MLX LLM adapter for Apple Silicon local inference.

    Uses MLX for fast local inference on Apple Silicon,
    leveraging unified memory and the Neural Engine.

    Embeddings are delegated to Ollama since MLX has no
    native embedding support (hybrid mode).
    """

    def __init__(
        self,
        model_path: str = "mlx-community/Qwen3-Coder-30B-A3B-Instruct-4bit",
        ollama_host: str = "http://localhost:11434",
        embedding_model: str = "embeddinggemma:300m",
        temperature: float = 0.0,
        max_tokens: int = 8192,
        circuit_breaker_config: CircuitBreakerConfig = None,
    ):
        """
        Initialize MLX adapter.

        Args:
            model_path: HuggingFace repo ID for the MLX model
            ollama_host: Ollama server URL (for embeddings)
            embedding_model: Ollama model for embeddings
            temperature: Sampling temperature (0.0 = deterministic)
            max_tokens: Max tokens in response
            circuit_breaker_config: Circuit breaker configuration
        """
        self.model_path = model_path
        self.ollama_host = ollama_host
        self.embedding_model = embedding_model
        self.temperature = temperature
        self.max_tokens = max_tokens

        # Lazy-loaded model and tokenizer (loaded on first call)
        self._model = None
        self._tokenizer = None

        # Single-thread executor for MLX calls (thread safety)
        self._executor = ThreadPoolExecutor(max_workers=1)

        # Ollama client for embeddings (lazy-loaded)
        self._ollama_client = None

        # Logger
        self.logger = FalconEyeLogger.get_instance()

        # Circuit breaker (no retry for local inference -- failures are deterministic)
        cb_config = circuit_breaker_config if circuit_breaker_config else CircuitBreakerConfig(
            failure_threshold=3,
            success_threshold=1,
            timeout=30.0,
            exclude_exceptions=(ValueError, TypeError)
        )
        self.circuit_breaker = CircuitBreaker(
            name="mlx_llm",
            config=cb_config
        )

    def _ensure_model_loaded(self):
        """Load model and tokenizer on first use (lazy loading)."""
        if self._model is None:
            from mlx_lm import load

            self.logger.info(
                "Loading MLX model (first use)",
                extra={"model_path": self.model_path}
            )
            start = time.time()
            self._model, self._tokenizer = load(self.model_path)
            duration = time.time() - start
            self.logger.info(
                "MLX model loaded",
                extra={
                    "model_path": self.model_path,
                    "load_time_seconds": round(duration, 2)
                }
            )

    def _ensure_ollama_client(self):
        """Initialize Ollama client for embeddings on first use."""
        if self._ollama_client is None:
            import ollama
            self._ollama_client = ollama.Client(host=self.ollama_host)

    def _build_prompt(self, system_prompt: str, user_prompt: str) -> str:
        """
        Build a prompt string using the model's chat template.

        Args:
            system_prompt: System instructions
            user_prompt: User query

        Returns:
            Formatted prompt string
        """
        self._ensure_model_loaded()
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        return self._tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True
        )

    async def analyze_code_security(
        self,
        context: PromptContext,
        system_prompt: str,
        stream_callback: Optional[Callable[[str], None]] = None,
    ) -> str:
        """
        Analyze code for security vulnerabilities using MLX inference.

        Args:
            context: Full context for AI analysis
            system_prompt: System instructions for AI
            stream_callback: Optional callback for streaming tokens

        Returns:
            Raw AI response with security findings
        """
        with logging_context(operation="mlx_analysis"):
            start_time = time.time()
            user_prompt = context.format_for_ai()
            prompt_length = len(user_prompt)

            self.logger.info(
                "Starting MLX security analysis",
                extra={
                    "model": self.model_path,
                    "prompt_length": prompt_length,
                    "streaming": stream_callback is not None
                }
            )

            try:
                if stream_callback:
                    response = await self._generate_stream(
                        system_prompt=system_prompt,
                        user_prompt=user_prompt,
                        stream_callback=stream_callback,
                    )
                else:
                    response = await self._generate(
                        system_prompt=system_prompt,
                        user_prompt=user_prompt,
                    )

                duration = time.time() - start_time
                self.logger.info(
                    "MLX security analysis completed",
                    extra={
                        "duration_seconds": round(duration, 2),
                        "prompt_length": prompt_length,
                        "response_length": len(response) if response else 0,
                        "model": self.model_path
                    }
                )
                return response

            except Exception as e:
                duration = time.time() - start_time
                self.logger.error(
                    "MLX security analysis failed",
                    exc_info=True,
                    extra={
                        "duration_seconds": round(duration, 2),
                        "error_type": type(e).__name__,
                        "model": self.model_path
                    }
                )
                raise

    async def generate_embedding(self, text: str) -> List[float]:
        """
        Generate embedding via Ollama (MLX has no native embedding support).

        Args:
            text: Text to embed

        Returns:
            Embedding vector
        """
        self._ensure_ollama_client()
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: self._ollama_client.embeddings(
                model=self.embedding_model,
                prompt=text,
            )
        )
        return response["embedding"]

    async def generate_embeddings_batch(
        self,
        texts: List[str],
    ) -> List[List[float]]:
        """
        Generate embeddings for multiple texts via Ollama.

        Args:
            texts: List of texts to embed

        Returns:
            List of embedding vectors
        """
        with logging_context(operation="mlx_embedding_batch"):
            start_time = time.time()
            batch_size = len(texts)

            self.logger.info(
                "Starting batch embedding generation (via Ollama)",
                extra={
                    "batch_size": batch_size,
                    "embedding_model": self.embedding_model
                }
            )

            try:
                tasks = [self.generate_embedding(text) for text in texts]
                embeddings = await asyncio.gather(*tasks)

                duration = time.time() - start_time
                self.logger.info(
                    "Batch embedding generation completed (via Ollama)",
                    extra={
                        "batch_size": batch_size,
                        "duration_seconds": round(duration, 2),
                        "model": self.embedding_model
                    }
                )
                return embeddings

            except Exception as e:
                duration = time.time() - start_time
                self.logger.error(
                    "Batch embedding generation failed",
                    exc_info=True,
                    extra={
                        "batch_size": batch_size,
                        "duration_seconds": round(duration, 2),
                        "error_type": type(e).__name__
                    }
                )
                raise

    async def validate_findings(
        self,
        code_snippet: str,
        findings: str,
        context: str,
    ) -> str:
        """
        Use MLX to validate findings and remove false positives.

        Args:
            code_snippet: Original code
            findings: Initial findings (JSON)
            context: Additional context

        Returns:
            Validated findings (AI-filtered)
        """
        system_prompt = """You are a security expert validating security findings.
Review each finding carefully and determine if it's a genuine security issue.

Remove false positives by checking:
1. Is the vulnerability actually present in the code?
2. Are there mitigations already in place?
3. Is the severity assessment accurate?
4. Is the reasoning sound?

Return only the VALID findings in the same JSON format.
If all findings are false positives, return: {"reviews": []}
"""

        user_prompt = f"""CODE:
{code_snippet}

INITIAL FINDINGS:
{findings}

ADDITIONAL CONTEXT:
{context}

Validate these findings and return only genuine security issues."""

        return await self._generate(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )

    async def summarize_findings(
        self,
        findings: List[str],
    ) -> str:
        """
        Use MLX to summarize multiple findings.

        Args:
            findings: List of finding descriptions

        Returns:
            Summary of findings
        """
        system_prompt = """You are a security expert summarizing security findings.
Create a concise but comprehensive summary of all identified issues."""

        user_prompt = f"""Summarize these security findings:

{chr(10).join(findings)}"""

        return await self._generate(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )

    def count_tokens(self, text: str) -> int:
        """
        Estimate token count for text.

        Args:
            text: Text to count tokens for

        Returns:
            Estimated token count
        """
        # Rough estimate: ~4 characters per token
        return len(text) // 4

    async def health_check(self) -> bool:
        """
        Check if MLX is available and model can be loaded.

        Returns:
            True if MLX is ready
        """
        if not is_apple_silicon():
            return False
        if not is_mlx_available():
            return False
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(self._executor, self._ensure_model_loaded)
            return True
        except Exception as e:
            self.logger.warning(f"MLX health check failed: {e}")
            return False

    async def _generate(
        self,
        system_prompt: str,
        user_prompt: str,
    ) -> str:
        """
        Generate a response using MLX (non-streaming).

        Protected by circuit breaker.

        Args:
            system_prompt: System instructions
            user_prompt: User query

        Returns:
            AI response text
        """
        @self.circuit_breaker.protect
        async def _call_with_protection():
            prompt = self._build_prompt(system_prompt, user_prompt)
            loop = asyncio.get_event_loop()

            def _run():
                from mlx_lm import generate
                from mlx_lm.sample_utils import make_sampler
                self._ensure_model_loaded()
                sampler = make_sampler(temp=self.temperature)
                return generate(
                    self._model,
                    self._tokenizer,
                    prompt=prompt,
                    max_tokens=self.max_tokens,
                    sampler=sampler,
                )

            return await loop.run_in_executor(self._executor, _run)

        return await _call_with_protection()

    async def _generate_stream(
        self,
        system_prompt: str,
        user_prompt: str,
        stream_callback: Callable[[str], None],
    ) -> str:
        """
        Generate a response using MLX with streaming.

        Args:
            system_prompt: System instructions
            user_prompt: User query
            stream_callback: Callback for each token

        Returns:
            Complete AI response text
        """
        prompt = self._build_prompt(system_prompt, user_prompt)
        loop = asyncio.get_event_loop()

        def _run_stream():
            from mlx_lm import stream_generate
            from mlx_lm.sample_utils import make_sampler
            self._ensure_model_loaded()
            sampler = make_sampler(temp=self.temperature)
            full_response = ""
            for token_result in stream_generate(
                self._model,
                self._tokenizer,
                prompt=prompt,
                max_tokens=self.max_tokens,
                sampler=sampler,
            ):
                # stream_generate yields (token_text, ...) or objects with .text
                if isinstance(token_result, str):
                    token = token_result
                elif hasattr(token_result, 'text'):
                    token = token_result.text
                elif isinstance(token_result, tuple):
                    token = token_result[0]
                else:
                    token = str(token_result)
                full_response += token
                if stream_callback:
                    stream_callback(token)
            return full_response

        return await loop.run_in_executor(self._executor, _run_stream)
