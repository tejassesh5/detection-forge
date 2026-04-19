from detection_forge.llm.providers.base import LLMProvider
from detection_forge.llm.providers.groq import GroqLlamaProvider
from detection_forge.llm.providers.ollama import OllamaProvider


def test_groq_implements_protocol():
    assert isinstance(GroqLlamaProvider("fake-key"), LLMProvider)


def test_ollama_implements_protocol():
    assert isinstance(OllamaProvider(), LLMProvider)


def test_groq_name():
    assert GroqLlamaProvider("fake-key").name == "groq"


def test_ollama_name():
    assert OllamaProvider().name == "ollama"
