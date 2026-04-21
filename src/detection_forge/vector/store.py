from __future__ import annotations

import structlog
from qdrant_client import AsyncQdrantClient
from qdrant_client.models import Distance, PointStruct, VectorParams

log = structlog.get_logger()

COLLECTION = "cti_rules"
VECTOR_SIZE = 384  # all-MiniLM-L6-v2


class VectorStore:
    def __init__(self, host: str = "localhost", port: int = 6333) -> None:
        self._client = AsyncQdrantClient(host=host, port=port, timeout=3)
        self._encoder = None

    def _get_encoder(self):
        if self._encoder is None:
            from sentence_transformers import SentenceTransformer
            self._encoder = SentenceTransformer("all-MiniLM-L6-v2")
        return self._encoder

    async def ensure_collection(self) -> None:
        collections = await self._client.get_collections()
        names = [c.name for c in collections.collections]
        if COLLECTION not in names:
            await self._client.create_collection(
                collection_name=COLLECTION,
                vectors_config=VectorParams(size=VECTOR_SIZE, distance=Distance.COSINE),
            )

    def _embed(self, text: str) -> list[float]:
        return self._get_encoder().encode(text, normalize_embeddings=True).tolist()

    async def upsert(self, doc_id: str, text: str, payload: dict) -> None:
        vector = self._embed(text)
        await self._client.upsert(
            collection_name=COLLECTION,
            points=[PointStruct(id=doc_id, vector=vector, payload=payload)],
        )

    async def search(self, text: str, limit: int = 5) -> list[dict]:
        vector = self._embed(text)
        results = await self._client.search(
            collection_name=COLLECTION,
            query_vector=vector,
            limit=limit,
        )
        return [{"id": r.id, "score": r.score, **r.payload} for r in results]
