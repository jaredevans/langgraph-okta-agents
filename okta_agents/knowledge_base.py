"""Builds/opens the persistent Chroma collection over kb/*.md."""

import hashlib
import shutil
from pathlib import Path

from langchain_chroma import Chroma
from langchain_core.documents import Document

COLLECTION = "threat_kb"


def _split_sections(text: str, source: str) -> list[Document]:
    """One Document per '## ' section; the doc title (H1) is prepended to each."""
    lines = text.splitlines()
    title = next((l.removeprefix("# ").strip() for l in lines if l.startswith("# ")), source)
    docs: list[Document] = []
    current: list[str] = []
    header = title
    for line in lines:
        if line.startswith("## "):
            if "\n".join(current).strip():
                docs.append(Document(
                    page_content=f"{title} — {header}\n" + "\n".join(current).strip(),
                    metadata={"source": source},
                ))
            header, current = line.removeprefix("## ").strip(), []
        elif not line.startswith("# "):
            current.append(line)
    if "\n".join(current).strip():
        docs.append(Document(
            page_content=f"{title} — {header}\n" + "\n".join(current).strip(),
            metadata={"source": source},
        ))
    return [d for d in docs if d.page_content.strip()]


def load_kb_docs(kb_dir: Path) -> list[Document]:
    docs: list[Document] = []
    for path in sorted(Path(kb_dir).glob("*.md")):
        docs.extend(_split_sections(path.read_text(), path.name))
    return docs


def _fingerprint(kb_dir: Path) -> str:
    h = hashlib.sha256()
    for path in sorted(Path(kb_dir).glob("*.md")):
        h.update(path.name.encode())
        h.update(path.read_bytes())
    return h.hexdigest()


def build_vectorstore(
    kb_dir: Path, persist_dir: Path, embeddings, rebuild: bool = False
) -> Chroma:
    persist_dir = Path(persist_dir)
    marker = persist_dir / "kb.fingerprint"
    fp = _fingerprint(kb_dir)
    if rebuild or not marker.exists() or marker.read_text() != fp:
        if persist_dir.exists():
            shutil.rmtree(persist_dir)
        persist_dir.mkdir(parents=True)
        store = Chroma(
            collection_name=COLLECTION,
            embedding_function=embeddings,
            persist_directory=str(persist_dir),
        )
        store.add_documents(load_kb_docs(kb_dir))
        marker.write_text(fp)
        return store
    return Chroma(
        collection_name=COLLECTION,
        embedding_function=embeddings,
        persist_directory=str(persist_dir),
    )
