from __future__ import annotations

from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
import yara


def validate_sigma(yaml_content: str) -> list[str]:
    try:
        SigmaCollection.from_yaml(yaml_content)
        return []
    except SigmaError as e:
        return [str(e)]
    except Exception as e:
        return [f"parse error: {e}"]


def validate_yara(yara_source: str) -> list[str]:
    try:
        yara.compile(source=yara_source)
        return []
    except yara.SyntaxError as e:
        return [str(e)]
    except Exception as e:
        return [f"compile error: {e}"]
