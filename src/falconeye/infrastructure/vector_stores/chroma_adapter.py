"""ChromaDB vector store adapter implementation."""

import json
from typing import List, Optional, Dict, Any
from pathlib import Path
import time
import chromadb
from chromadb.config import Settings

from ...domain.repositories.vector_store_repository import VectorStoreRepository
from ...domain.models.code_chunk import CodeChunk, ChunkMetadata
from ...domain.models.document import DocumentChunk, DocumentMetadata
from ..logging import FalconEyeLogger, logging_context


class ChromaVectorStoreAdapter(VectorStoreRepository):
    """
    ChromaDB implementation of vector store.

    Provides local persistent storage for code embeddings
    used in RAG for AI context assembly.

    NOTE: This stores embeddings for semantic search, NOT for
    pattern-based vulnerability detection. All detection is done by AI.
    """

    def __init__(
        self,
        persist_directory: str = "./chromadb",
        collection_prefix: str = "falconeye",
        project_id: Optional[str] = None,
        use_project_isolation: bool = True,
    ):
        """
        Initialize ChromaDB adapter.

        Args:
            persist_directory: Directory for ChromaDB persistence
            collection_prefix: Prefix for collection names
            project_id: Project identifier for isolated collections
            use_project_isolation: Whether to use project-scoped collections
        """
        self.persist_directory = Path(persist_directory)
        self.collection_prefix = collection_prefix
        self.project_id = project_id
        self.use_project_isolation = use_project_isolation

        # Create directory if it doesn't exist
        self.persist_directory.mkdir(parents=True, exist_ok=True)

        # Initialize ChromaDB client
        self.client = chromadb.PersistentClient(
            path=str(self.persist_directory),
            settings=Settings(
                anonymized_telemetry=False,
                allow_reset=True,
            )
        )

        # Cache for collections
        self._collections: Dict[str, Any] = {}

        # Initialize logger
        self.logger = FalconEyeLogger.get_instance()

    def _get_collection(self, collection: str):
        """
        Get or create a collection with project isolation.

        Args:
            collection: Collection type (e.g., 'code', 'documents')

        Returns:
            ChromaDB collection
        """
        # Build collection name with project isolation
        if self.use_project_isolation and self.project_id:
            # Project-scoped: falconeye_{project_id}_{collection}
            collection_name = f"{self.collection_prefix}_{self.project_id}_{collection}"
        else:
            # Legacy/global: falconeye_{collection}
            collection_name = f"{self.collection_prefix}_{collection}"

        if collection_name not in self._collections:
            # Get or create collection
            self._collections[collection_name] = self.client.get_or_create_collection(
                name=collection_name,
                metadata={
                    "description": f"FalconEYE {collection} collection",
                    "project_id": self.project_id or "global",
                    "collection_type": collection,
                }
            )

        return self._collections[collection_name]

    async def store_chunks(
        self,
        chunks: List[CodeChunk],
        collection: str = "code"
    ) -> None:
        """
        Store code chunks with embeddings.

        Args:
            chunks: List of code chunks with embeddings
            collection: Collection name
        """
        if not chunks:
            return

        with logging_context(operation="vector_store_write"):
            start_time = time.time()
            chunk_count = len(chunks)

            self.logger.info(
                "Storing chunks in vector store",
                extra={
                    "chunk_count": chunk_count,
                    "collection": collection,
                    "project_id": self.project_id
                }
            )

            try:
                coll = self._get_collection(collection)

                # Prepare data for ChromaDB
                ids = [str(chunk.id) for chunk in chunks]
                embeddings = [chunk.embedding for chunk in chunks]
                documents = [chunk.content for chunk in chunks]
                metadatas = [self._chunk_metadata_to_dict(chunk.metadata) for chunk in chunks]

                # Validate embeddings
                if any(emb is None for emb in embeddings):
                    raise ValueError("All chunks must have embeddings")

                # Store in ChromaDB
                coll.add(
                    ids=ids,
                    embeddings=embeddings,
                    documents=documents,
                    metadatas=metadatas,
                )

                duration = time.time() - start_time
                self.logger.info(
                    "Chunks stored successfully",
                    extra={
                        "chunk_count": chunk_count,
                        "duration_seconds": round(duration, 3),
                        "chunks_per_second": round(chunk_count / duration, 2) if duration > 0 else 0,
                        "collection": collection
                    }
                )

            except Exception as e:
                duration = time.time() - start_time
                self.logger.error(
                    "Failed to store chunks",
                    exc_info=True,
                    extra={
                        "chunk_count": chunk_count,
                        "duration_seconds": round(duration, 3),
                        "error_type": type(e).__name__,
                        "collection": collection
                    }
                )
                raise

    async def search_similar(
        self,
        query: str,
        top_k: int = 5,
        collection: str = "code",
        filters: Optional[dict] = None,
        query_embedding: Optional[List[float]] = None,
    ) -> List[CodeChunk]:
        """
        Search for similar code chunks using semantic search.

        This is used for RAG to provide context to the AI,
        NOT for pattern-based vulnerability detection.

        Args:
            query: Search query (not used if query_embedding provided)
            top_k: Number of results
            collection: Collection to search
            filters: Optional metadata filters
            query_embedding: Pre-computed embedding (recommended)

        Returns:
            List of similar code chunks
        """
        with logging_context(operation="vector_store_search"):
            start_time = time.time()

            self.logger.info(
                "Searching vector store",
                extra={
                    "top_k": top_k,
                    "collection": collection,
                    "has_filters": filters is not None,
                    "search_type": "embedding" if query_embedding else "text"
                }
            )

            try:
                coll = self._get_collection(collection)

                # Build where clause if filters provided
                where = None
                if filters:
                    where = filters

                # Use embedding search if provided, otherwise use text query
                # Note: Text query uses ChromaDB's default embedding which may have different dimensions
                if query_embedding:
                    results = coll.query(
                        query_embeddings=[query_embedding],
                        n_results=top_k,
                        where=where,
                    )
                else:
                    # This path uses ChromaDB's built-in embedding
                    # For consistency, always provide query_embedding
                    results = coll.query(
                        query_texts=[query],
                        n_results=top_k,
                        where=where,
                    )

                # Convert results to CodeChunk objects
                chunks = []
                if results["ids"] and results["ids"][0]:
                    for i, chunk_id in enumerate(results["ids"][0]):
                        metadata = self._dict_to_chunk_metadata(results["metadatas"][0][i])
                        chunk = CodeChunk.create(
                            content=results["documents"][0][i],
                            metadata=metadata,
                            token_count=len(results["documents"][0][i]) // 4,  # Rough estimate
                            embedding=results["embeddings"][0][i] if results.get("embeddings") else None,
                        )
                        chunks.append(chunk)

                duration = time.time() - start_time
                self.logger.info(
                    "Vector search completed",
                    extra={
                        "results_found": len(chunks),
                        "duration_seconds": round(duration, 3),
                        "collection": collection
                    }
                )

                return chunks

            except Exception as e:
                duration = time.time() - start_time
                
                # Check for embedding dimension mismatch
                error_msg = str(e)
                if "dimension" in error_msg.lower() and "expecting" in error_msg.lower():
                    self.logger.error(
                        "Embedding dimension mismatch detected",
                        exc_info=True,
                        extra={
                            "duration_seconds": round(duration, 3),
                            "error_type": type(e).__name__,
                            "collection": collection,
                            "error": error_msg,
                            "solution": "Delete the project and re-index with: falconeye projects delete <project_id> && falconeye index <path>"
                        }
                    )
                    raise ValueError(
                        f"Embedding dimension mismatch: {error_msg}\n\n"
                        f"This happens when the embedding model changed after indexing.\n"
                        f"Solution: Delete and re-index the project:\n"
                        f"  1. List projects: falconeye projects list\n"
                        f"  2. Delete project: falconeye projects delete <project_id>\n"
                        f"  3. Re-index: falconeye index <path>"
                    ) from e
                
                self.logger.error(
                    "Vector search failed",
                    exc_info=True,
                    extra={
                        "duration_seconds": round(duration, 3),
                        "error_type": type(e).__name__,
                        "collection": collection
                    }
                )
                raise

    async def search_by_embedding(
        self,
        embedding: List[float],
        top_k: int = 5,
        collection: str = "code",
    ) -> List[CodeChunk]:
        """
        Search using a pre-computed embedding.

        Args:
            embedding: Query embedding vector
            top_k: Number of results
            collection: Collection to search

        Returns:
            List of similar code chunks
        """
        coll = self._get_collection(collection)

        # Query ChromaDB with embedding
        results = coll.query(
            query_embeddings=[embedding],
            n_results=top_k,
        )

        # Convert results to CodeChunk objects
        chunks = []
        if results["ids"] and results["ids"][0]:
            for i, chunk_id in enumerate(results["ids"][0]):
                metadata = self._dict_to_chunk_metadata(results["metadatas"][0][i])
                chunk = CodeChunk.create(
                    content=results["documents"][0][i],
                    metadata=metadata,
                    token_count=len(results["documents"][0][i]) // 4,
                    embedding=results["embeddings"][0][i] if results.get("embeddings") else None,
                )
                chunks.append(chunk)

        return chunks

    async def delete_collection(self, collection: str) -> None:
        """
        Delete an entire collection.

        Args:
            collection: Collection type to delete
        """
        # Build collection name with project isolation
        if self.use_project_isolation and self.project_id:
            collection_name = f"{self.collection_prefix}_{self.project_id}_{collection}"
        else:
            collection_name = f"{self.collection_prefix}_{collection}"

        try:
            self.client.delete_collection(name=collection_name)
            if collection_name in self._collections:
                del self._collections[collection_name]
            self.logger.info(
                f"Deleted collection: {collection_name}",
                extra={"collection": collection_name}
            )
        except ValueError as e:
            # Collection doesn't exist - this is expected in some cases
            self.logger.debug(
                f"Collection {collection_name} doesn't exist (may be expected): {e}",
                extra={"collection": collection_name}
            )
        except Exception as e:
            # Unexpected error during deletion - log and re-raise
            self.logger.error(
                f"Failed to delete collection {collection_name}: {e}",
                extra={"collection": collection_name, "error": str(e)},
                exc_info=True
            )
            raise

    async def collection_exists(self, collection: str) -> bool:
        """
        Check if collection exists.

        Args:
            collection: Collection type

        Returns:
            True if collection exists
        """
        # Build collection name with project isolation
        if self.use_project_isolation and self.project_id:
            collection_name = f"{self.collection_prefix}_{self.project_id}_{collection}"
        else:
            collection_name = f"{self.collection_prefix}_{collection}"

        try:
            collections = self.client.list_collections()
            return any(c.name == collection_name for c in collections)
        except Exception:
            return False

    async def get_chunk_count(self, collection: str) -> int:
        """
        Get number of chunks in collection.

        Args:
            collection: Collection type

        Returns:
            Number of chunks
        """
        if not await self.collection_exists(collection):
            return 0

        coll = self._get_collection(collection)
        return coll.count()

    async def delete_project_collections(self) -> None:
        """
        Delete all collections for the current project.

        Only works when use_project_isolation is True and project_id is set.
        """
        if not self.use_project_isolation or not self.project_id:
            raise ValueError("Project isolation must be enabled with a project_id")

        # Delete code, documents, and metadata collections
        for collection_type in ["code", "documents", "metadata"]:
            await self.delete_collection(collection_type)

    def list_all_project_collections(self) -> List[str]:
        """
        List all project-scoped collections in the database.

        Returns:
            List of collection names
        """
        try:
            collections = self.client.list_collections()
            return [c.name for c in collections]
        except Exception:
            return []

    def _chunk_metadata_to_dict(self, metadata: ChunkMetadata) -> Dict[str, Any]:
        """
        Convert ChunkMetadata to dictionary for ChromaDB.

        ChromaDB requires flat dictionaries with string values.

        Args:
            metadata: ChunkMetadata object

        Returns:
            Dictionary representation
        """
        return {
            "file_path": metadata.file_path,
            "language": metadata.language,
            "start_line": str(metadata.start_line),
            "end_line": str(metadata.end_line),
            "chunk_index": str(metadata.chunk_index),
            "total_chunks": str(metadata.total_chunks),
            "has_functions": str(metadata.has_functions),
            "has_imports": str(metadata.has_imports),
            "function_names": json.dumps(metadata.function_names),
        }

    def _dict_to_chunk_metadata(self, data: Dict[str, Any]) -> ChunkMetadata:
        """
        Convert dictionary to ChunkMetadata.

        Args:
            data: Dictionary from ChromaDB

        Returns:
            ChunkMetadata object
        """
        return ChunkMetadata(
            file_path=data["file_path"],
            language=data["language"],
            start_line=int(data["start_line"]),
            end_line=int(data["end_line"]),
            chunk_index=int(data["chunk_index"]),
            total_chunks=int(data["total_chunks"]),
            has_functions=data["has_functions"] == "True",
            has_imports=data["has_imports"] == "True",
            function_names=json.loads(data.get("function_names", "[]")),
        )

    async def store_document_chunks(
        self,
        chunks: List[DocumentChunk],
        collection: str = "documents"
    ) -> None:
        """
        Store document chunks with embeddings.

        Args:
            chunks: List of document chunks with embeddings
            collection: Collection name (defaults to "documents")
        """
        if not chunks:
            return

        coll = self._get_collection(collection)

        # Prepare data for ChromaDB
        ids = [chunk.chunk_id for chunk in chunks]
        embeddings = [chunk.embedding for chunk in chunks]
        documents = [chunk.content for chunk in chunks]
        metadatas = [self._doc_metadata_to_dict(chunk) for chunk in chunks]

        # Validate embeddings
        if any(emb is None for emb in embeddings):
            raise ValueError("All document chunks must have embeddings")

        # Store in ChromaDB
        coll.add(
            ids=ids,
            embeddings=embeddings,
            documents=documents,
            metadatas=metadatas,
        )

    async def search_similar_documents(
        self,
        query: str,
        top_k: int = 5,
        collection: str = "documents",
        query_embedding: Optional[List[float]] = None,
    ) -> List[DocumentChunk]:
        """
        Search for similar document chunks using semantic search.

        Args:
            query: Search query
            top_k: Number of results to return
            collection: Collection to search
            query_embedding: Pre-computed query embedding (optional)

        Returns:
            List of similar document chunks
        """
        try:
            coll = self._get_collection(collection)

            # Use embedding search if provided
            if query_embedding:
                results = coll.query(
                    query_embeddings=[query_embedding],
                    n_results=top_k,
                )
            else:
                results = coll.query(
                    query_texts=[query],
                    n_results=top_k,
                )

            # Convert results to DocumentChunk objects
            chunks = []
            if results["ids"] and results["ids"][0]:
                for i, chunk_id in enumerate(results["ids"][0]):
                    chunk = self._dict_to_document_chunk(
                        chunk_id=chunk_id,
                        content=results["documents"][0][i],
                        metadata_dict=results["metadatas"][0][i],
                        embedding=results["embeddings"][0][i] if results.get("embeddings") else None,
                    )
                    chunks.append(chunk)

            return chunks
            
        except Exception as e:
            # Check for embedding dimension mismatch
            error_msg = str(e)
            if "dimension" in error_msg.lower() and "expecting" in error_msg.lower():
                self.logger.error(
                    "Embedding dimension mismatch in document search",
                    exc_info=True,
                    extra={
                        "error_type": type(e).__name__,
                        "collection": collection,
                        "error": error_msg,
                        "solution": "Delete the project and re-index"
                    }
                )
                raise ValueError(
                    f"Embedding dimension mismatch: {error_msg}\n\n"
                    f"This happens when the embedding model changed after indexing.\n"
                    f"Solution: Delete and re-index the project:\n"
                    f"  1. List projects: falconeye projects list\n"
                    f"  2. Delete project: falconeye projects delete <project_id>\n"
                    f"  3. Re-index: falconeye index <path>"
                ) from e
            raise

    def _doc_metadata_to_dict(self, chunk: DocumentChunk) -> Dict[str, Any]:
        """
        Convert DocumentChunk metadata to dictionary for ChromaDB.

        Args:
            chunk: DocumentChunk object

        Returns:
            Dictionary representation
        """
        return {
            "file_path": chunk.metadata.file_path,
            "document_type": chunk.metadata.document_type,
            "title": chunk.metadata.title or "",
            "sections": json.dumps(chunk.metadata.sections),
            "keywords": json.dumps(chunk.metadata.keywords),
            "start_char": str(chunk.start_char),
            "end_char": str(chunk.end_char),
            "chunk_index": str(chunk.chunk_index),
            "total_chunks": str(chunk.total_chunks),
        }

    def _dict_to_document_chunk(
        self,
        chunk_id: str,
        content: str,
        metadata_dict: Dict[str, Any],
        embedding: Optional[List[float]] = None,
    ) -> DocumentChunk:
        """
        Convert dictionary to DocumentChunk.

        Args:
            chunk_id: Chunk ID
            content: Chunk content
            metadata_dict: Metadata dictionary from ChromaDB
            embedding: Optional embedding vector

        Returns:
            DocumentChunk object
        """
        from datetime import datetime

        metadata = DocumentMetadata(
            file_path=metadata_dict["file_path"],
            document_type=metadata_dict["document_type"],
            title=metadata_dict.get("title") or None,
            sections=json.loads(metadata_dict.get("sections", "[]")),
            keywords=json.loads(metadata_dict.get("keywords", "[]")),
        )

        return DocumentChunk(
            chunk_id=chunk_id,
            content=content,
            metadata=metadata,
            start_char=int(metadata_dict["start_char"]),
            end_char=int(metadata_dict["end_char"]),
            chunk_index=int(metadata_dict["chunk_index"]),
            total_chunks=int(metadata_dict["total_chunks"]),
            embedding=embedding,
            created_at=datetime.utcnow(),
        )