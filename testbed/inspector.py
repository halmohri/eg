#!/usr/bin/env python3
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class ConfigSpec:
    name: str
    directive: str
    context: str
    file_ref: str


class NginxConfigInspector:
    def __init__(self, settings_path: Path) -> None:
        self.settings_path = settings_path
        self.specs: list[ConfigSpec] = []
        self.files: dict[str, Path] = {}
        self._load_settings()

    def _load_settings(self) -> None:
        try:
            import yaml  # type: ignore
        except ModuleNotFoundError as exc:
            raise RuntimeError("PyYAML is required: pip install pyyaml") from exc

        with self.settings_path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}

        nginx = data.get("nginx") or {}
        files = nginx.get("files") or {}
        configs = nginx.get("configs") or {}

        if not files:
            raise ValueError("Missing nginx.files in settings")
        if not configs:
            raise ValueError("Missing nginx.configs in settings")

        for key, value in files.items():
            self.files[str(key)] = Path(str(value).strip())

        for name, cfg in configs.items():
            if not isinstance(cfg, dict):
                raise ValueError(f"Invalid config entry: {name}")
            directive = cfg.get("directive")
            context = cfg.get("context")
            file_ref = cfg.get("file")
            if not directive or context is None or file_ref is None:
                raise ValueError(f"Config {name} missing directive/context/file")
            self.specs.append(
                ConfigSpec(
                    name=str(name),
                    directive=str(directive),
                    context=str(context),
                    file_ref=str(file_ref),
                )
            )

    def _resolve_path(self, file_ref: str) -> Path:
        file_key = str(file_ref).strip()
        return Path(str(self.files.get(file_key, file_key)).strip())

    def _find_value(self, text: str, directive: str, context: str) -> str | None:
        lines = text.splitlines()
        stack: list[str] = []
        has_blocks = any("{" in line for line in lines)
        match_anywhere = context in {"any", "all", "file"} or not has_blocks

        context_start = re.compile(r"^\s*([a-zA-Z0-9_]+)\b.*\{\s*$")
        context_end = re.compile(r"^\s*}\s*;?\s*$")
        directive_re = re.compile(rf"^\s*{re.escape(directive)}\s+(.+?);\s*$")

        for line in lines:
            start_match = context_start.match(line)
            if start_match:
                stack.append(start_match.group(1))
            if context_end.match(line):
                if stack:
                    stack.pop()
                continue

            in_context = match_anywhere or (context == "main" and not stack) or (
                context != "main" and context in stack
            )
            if not in_context:
                continue

            match = directive_re.match(line)
            if match:
                return match.group(1).strip()

        return None

    def get_current_values(self) -> dict[str, dict[str, Any]]:
        results: dict[str, dict[str, Any]] = {}
        cache: dict[Path, str] = {}

        for spec in self.specs:
            path = self._resolve_path(spec.file_ref)
            if path not in cache:
                cache[path] = path.read_text(encoding="utf-8")
            value = self._find_value(cache[path], spec.directive, spec.context)
            results[spec.name] = {
                "directive": spec.directive,
                "context": spec.context,
                "file": str(path),
                "value": value,
            }
        return results
