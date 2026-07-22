from langchain_core.documents import Document
from langchain_core.runnables import RunnableLambda


class FakeStructuredModel:
    """Stands in for ChatOpenAI: returns canned Pydantic objects per schema."""

    def __init__(self, outputs: dict[type, object]):
        self._outputs = outputs
        self.calls: list[type] = []
        self.prompts: list[object] = []

    def with_structured_output(self, schema: type):
        def _run(_input):
            self.calls.append(schema)
            self.prompts.append(_input)
            return self._outputs[schema]

        return RunnableLambda(_run)


def fake_retriever(docs: list[Document] | None = None):
    docs = docs or [
        Document(page_content="MFA Fatigue — Indicators\n...", metadata={"source": "mfa-fatigue.md"}),
        Document(page_content="Playbook: MFA Fatigue\n1. Clear sessions", metadata={"source": "remediation-playbooks.md"}),
    ]
    return RunnableLambda(lambda _q: docs)
