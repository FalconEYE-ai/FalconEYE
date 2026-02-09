"""Context assembler domain service."""

from typing import List, Optional, Dict, Any
import time
from ..models.prompt import PromptContext
from ..repositories.vector_store_repository import VectorStoreRepository
from ..repositories.metadata_repository import MetadataRepository
from ...infrastructure.logging import FalconEyeLogger


class ContextAssembler:
    """
    Domain service for assembling rich context for AI analysis.

    This service gathers all relevant information that the AI needs
    to perform accurate security analysis:
    - Code to analyze
    - Structural metadata (AST)
    - Related code (from RAG)
    - Control/data flow information

    NO pattern matching - just context assembly for AI.
    """

    def __init__(
        self,
        vector_store: VectorStoreRepository,
        metadata_repo: MetadataRepository,
    ):
        """
        Initialize context assembler.

        Args:
            vector_store: Vector store for semantic search
            metadata_repo: Metadata repository for structural info
        """
        self.vector_store = vector_store
        self.metadata_repo = metadata_repo
        self.logger = FalconEyeLogger.get_instance()

    async def assemble_context(
        self,
        file_path: str,
        code_snippet: str,
        language: str,
        top_k_similar: int = 5,
        top_k_docs: int = 3,
        original_file: Optional[str] = None,
        analysis_type: str = "review",
    ) -> PromptContext:
        """
        Assemble comprehensive context for AI analysis.

        This method gathers all information the AI needs to understand
        the code deeply and identify security issues.

        Args:
            file_path: Path to file being analyzed
            code_snippet: Code to analyze
            language: Programming language
            top_k_similar: Number of similar code chunks to retrieve
            top_k_docs: Number of relevant documentation chunks to retrieve
            original_file: Original file content (for patch analysis)
            analysis_type: Type of analysis (review, validation, etc.)

        Returns:
            PromptContext with all assembled information
        """
        start_time = time.time()

        # Log start
        self.logger.info(
            "Starting context assembly",
            extra={
                "file_path": file_path,
                "language": language,
                "code_size": len(code_snippet),
                "top_k_similar": top_k_similar,
                "analysis_type": analysis_type,
            }
        )

        # Get structural metadata
        structural_metadata = await self._get_structural_metadata(file_path)

        # Get related code through semantic search
        related_code = await self._get_related_code(
            code_snippet,
            file_path,
            top_k_similar,
        )

        # Get relevant documentation
        related_docs = await self._get_related_documentation(
            code_snippet,
            top_k_docs,
        )

        # Assemble context
        context = PromptContext(
            file_path=file_path,
            code_snippet=code_snippet,
            language=language,
            structural_metadata=structural_metadata,
            related_code=related_code,
            related_docs=related_docs,
            original_file=original_file,
            analysis_type=analysis_type,
        )

        # Calculate duration
        duration = time.time() - start_time

        # Log completion with metrics
        self.logger.info(
            "Context assembly completed",
            extra={
                "file_path": file_path,
                "has_metadata": structural_metadata is not None,
                "has_related_code": related_code is not None,
                "has_related_docs": related_docs is not None,
                "duration_seconds": round(duration, 2),
            }
        )

        return context

    async def _get_structural_metadata(
        self,
        file_path: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieve structural metadata for the file.

        This provides the AI with:
        - Functions and their signatures
        - Import statements
        - Function calls
        - Control flow paths
        - Data flow information

        Args:
            file_path: Path to file

        Returns:
            Structural metadata dict or None
        """
        try:
            metadata = await self.metadata_repo.get_metadata(file_path)
            if metadata:
                return metadata.to_dict()
            return None
        except Exception as e:
            # Log but don't fail - metadata is optional for context
            self.logger.warning(
                "Failed to retrieve structural metadata",
                extra={
                    "file_path": file_path,
                    "error": str(e),
                },
                exc_info=True
            )
            return None

    async def _get_related_code(
        self,
        code_snippet: str,
        current_file: str,
        top_k: int,
    ) -> Optional[str]:
        """
        Use RAG to find related code chunks.

        This helps the AI understand:
        - How the code is called
        - What dependencies it has
        - Similar patterns in the codebase
        - Security context from related code

        Args:
            code_snippet: Code being analyzed
            current_file: File being analyzed (to exclude from results)
            top_k: Number of similar chunks to retrieve

        Returns:
            Formatted related code or None
        """
        try:
            # Generate embedding for query using same LLM as indexing
            # This is imported lazily to avoid circular imports
            from ...infrastructure.llm_providers.ollama_adapter import OllamaLLMAdapter

            # Note: In production, LLM service should be injected
            # For now, create a temporary instance
            temp_llm = OllamaLLMAdapter()
            # Truncate to 2048 chars for embeddinggemma:300m context limit
            truncated_query = code_snippet[:2048] if len(code_snippet) > 2048 else code_snippet
            query_embedding = await temp_llm.generate_embedding(truncated_query)

            # Semantic search for similar code using consistent embeddings
            similar_chunks = await self.vector_store.search_similar(
                query=code_snippet,
                top_k=top_k + 5,  # Get extra in case we need to filter
                collection="code",
                query_embedding=query_embedding,
            )

            # Filter out chunks from the current file
            filtered_chunks = [
                chunk for chunk in similar_chunks
                if chunk.metadata.file_path != current_file
            ][:top_k]

            if not filtered_chunks:
                return None

            # Format related code for AI context
            related_parts = []
            for i, chunk in enumerate(filtered_chunks, 1):
                related_parts.append(
                    f"[Related Code {i}] From {chunk.metadata.file_path}:\n"
                    f"{chunk.content}\n"
                )

            return "\n".join(related_parts)

        except Exception as e:
            # Don't fail if RAG retrieval fails
            self.logger.warning(
                "Failed to retrieve related code",
                extra={
                    "current_file": current_file,
                    "error": str(e),
                },
                exc_info=True
            )
            return None

    async def _get_related_documentation(
        self,
        code_snippet: str,
        top_k: int,
    ) -> Optional[str]:
        """
        Use RAG to find relevant documentation.

        This helps the AI understand:
        - Architecture and design decisions
        - Security policies and requirements
        - API documentation
        - Configuration guidelines
        - Best practices defined in docs

        Args:
            code_snippet: Code being analyzed
            top_k: Number of document chunks to retrieve

        Returns:
            Formatted documentation or None
        """
        try:
            # Generate embedding for query
            from ...infrastructure.llm_providers.ollama_adapter import OllamaLLMAdapter

            temp_llm = OllamaLLMAdapter()
            # Truncate to 2048 chars for embeddinggemma:300m context limit
            truncated_query = code_snippet[:2048] if len(code_snippet) > 2048 else code_snippet
            query_embedding = await temp_llm.generate_embedding(truncated_query)

            # Semantic search in documents collection
            doc_chunks = await self.vector_store.search_similar_documents(
                query=code_snippet,
                top_k=top_k,
                collection="documents",
                query_embedding=query_embedding,
            )

            if not doc_chunks:
                return None

            # Format documentation for AI context
            doc_parts = []
            for i, chunk in enumerate(doc_chunks, 1):
                doc_type = chunk.metadata.document_type.replace("_", " ").title()
                doc_parts.append(
                    f"[Documentation {i}] {doc_type} - {chunk.metadata.file_path}:\n"
                    f"{chunk.content}\n"
                )

            return "\n".join(doc_parts)

        except Exception as e:
            # Don't fail if documentation retrieval fails
            self.logger.warning(
                "Failed to retrieve related documentation",
                extra={
                    "error": str(e),
                },
                exc_info=True
            )
            return None

    async def assemble_multi_file_context(
        self,
        file_contexts: List[tuple[str, str, str]],  # (path, code, language)
        top_k_per_file: int = 3,
    ) -> List[PromptContext]:
        """
        Assemble contexts for multiple files.

        Used for codebase-wide analysis.

        Args:
            file_contexts: List of (file_path, code, language) tuples
            top_k_per_file: Similar chunks per file

        Returns:
            List of PromptContext objects
        """
        contexts = []
        for file_path, code, language in file_contexts:
            context = await self.assemble_context(
                file_path=file_path,
                code_snippet=code,
                language=language,
                top_k_similar=top_k_per_file,
            )
            contexts.append(context)
        return contexts