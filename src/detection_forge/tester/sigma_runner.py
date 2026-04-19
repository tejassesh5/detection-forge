from __future__ import annotations

import yaml


def _field_match_endswith(event_val: str, values: list | str) -> bool:
    vs = values if isinstance(values, list) else [values]
    return any(event_val.lower().endswith(v.lower().lstrip("\\")) for v in vs)


def _field_match_contains(event_val: str, values: list | str) -> bool:
    vs = values if isinstance(values, list) else [values]
    return any(v.lower() in event_val.lower() for v in vs)


def _field_match_startswith(event_val: str, values: list | str) -> bool:
    vs = values if isinstance(values, list) else [values]
    return any(event_val.lower().startswith(v.lower()) for v in vs)


def _field_match_equals(event_val: str, values: list | str) -> bool:
    vs = values if isinstance(values, list) else [values]
    return any(event_val.lower() == v.lower() for v in vs)


def _evaluate_selection(selection: dict, event: dict) -> bool:
    for field_expr, value in selection.items():
        parts = field_expr.split("|")
        field = parts[0]
        modifier = parts[1] if len(parts) > 1 else "equals"
        event_val = str(event.get(field, ""))
        if modifier == "endswith":
            if not _field_match_endswith(event_val, value):
                return False
        elif modifier == "contains":
            if not _field_match_contains(event_val, value):
                return False
        elif modifier == "startswith":
            if not _field_match_startswith(event_val, value):
                return False
        else:
            if not _field_match_equals(event_val, value):
                return False
    return True


def match_sigma_against_events(sigma_yaml: str, events: list[dict]) -> list[dict]:
    """Match a Sigma rule (YAML string) against a list of event dicts.
    Returns events that triggered the rule."""
    rule = yaml.safe_load(sigma_yaml)
    detection = rule.get("detection", {})
    selections = {k: v for k, v in detection.items() if k != "condition"}

    matched = []
    for event in events:
        results: dict[str, bool] = {}
        for sel_name, sel_def in selections.items():
            if isinstance(sel_def, dict):
                results[sel_name] = _evaluate_selection(sel_def, event)
            else:
                results[sel_name] = False

        match = results.get("selection", False)
        if match:
            matched.append(event)

    return matched
