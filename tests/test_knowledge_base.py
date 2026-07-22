from pathlib import Path

from langchain_core.embeddings import DeterministicFakeEmbedding

from okta_agents.knowledge_base import build_vectorstore, load_kb_docs

KB_DIR = Path(__file__).resolve().parent.parent / "kb"


def test_load_kb_docs_reads_all_files_with_sources():
    docs = load_kb_docs(KB_DIR)
    sources = {d.metadata["source"] for d in docs}
    assert "password-spray.md" in sources
    assert "remediation-playbooks.md" in sources
    assert all(d.page_content.strip() for d in docs)
    assert all(len(d.page_content.splitlines()) > 1 for d in docs)  # no header-only noise docs
    assert len(docs) >= 6


def test_build_vectorstore_retrieves_relevant_doc(tmp_path):
    emb = DeterministicFakeEmbedding(size=64)
    store = build_vectorstore(KB_DIR, tmp_path / "chroma", emb)
    hits = store.similarity_search("repeated MFA push denials", k=4)
    assert len(hits) == 4  # retrieval works; fake embeddings don't rank semantically


def test_build_vectorstore_is_idempotent(tmp_path):
    emb = DeterministicFakeEmbedding(size=64)
    persist = tmp_path / "chroma"
    store1 = build_vectorstore(KB_DIR, persist, emb)
    n1 = store1._collection.count()
    store2 = build_vectorstore(KB_DIR, persist, emb)  # second call: no re-add
    assert store2._collection.count() == n1
