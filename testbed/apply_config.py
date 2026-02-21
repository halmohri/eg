#!/usr/bin/env python3
import argparse
import datetime
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_SETTINGS = SCRIPT_DIR / "workload_settings.yaml"
LOG_FILE = SCRIPT_DIR / "nginx_config_changes.log"


def log_line(message: str) -> None:
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a", encoding="utf-8") as handle:
        handle.write(f"{timestamp} {message}\n")


def safe_log_line(message: str) -> None:
    try:
        log_line(message)
    except Exception:
        return


def load_settings(settings_path: Path) -> Dict[str, Any]:
    try:
        import yaml  # type: ignore
    except ModuleNotFoundError as exc:
        raise RuntimeError("PyYAML is required: pip install pyyaml") from exc

    with settings_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}

    nginx_section = data.get("nginx") or {}

    return data


def _cast_override_value(value: Any, py_type: str | None) -> Any:
    if isinstance(value, str) and value in {"on", "off"}:
        return value
    if py_type == "int":
        try:
            return int(round(float(value)))
        except Exception:
            return value
    if py_type == "float":
        try:
            return float(value)
        except Exception:
            return value
    return value


def apply_overrides(settings: Dict[str, Any], overrides: Dict[str, Any]) -> None:
    if not overrides:
        return
    nginx_settings = settings.get("nginx") or {}
    nginx_configs = nginx_settings.get("configs") or {}
    for name, value in overrides.items():
        cfg = nginx_configs.get(name)
        if not isinstance(cfg, dict):
            continue
        directive = cfg.get("directive")
        py_type = cfg.get("py_type")
        casted = _cast_override_value(value, py_type)
        if directive == "reset_timedout_connection":
            if isinstance(casted, (int, float)):
                casted = "on" if int(round(casted)) == 1 else "off"
        cfg["learner_value"] = casted
        cfg["value"] = casted
        if not cfg.get("format"):
            cfg["nginx_value"] = casted


def backup_config(config_path: Path, backups_written: set[Path]) -> Path:
    backup_path = config_path.with_suffix(config_path.suffix + ".bak")
    if config_path in backups_written:
        return backup_path
    shutil.copy2(config_path, backup_path)
    backups_written.add(config_path)
    log_line(f"backup_written path={backup_path}")
    print(f"[backup] wrote {backup_path}")
    return backup_path


def format_directive_value(value: Any) -> str:
    if isinstance(value, bool):
        return "on" if value else "off"
    if isinstance(value, (list, tuple)):
        return " ".join(str(item) for item in value)
    return str(value)


def render_directive_value(value: Any, fmt: str | None) -> str:
    raw = format_directive_value(value)
    if not fmt:
        return raw
    return fmt.format(value=raw)


def find_and_replace_directive(
    text: str, directive: str, value: str, context: str
) -> tuple[str, bool, str | None]:
    lines = text.splitlines()
    stack: list[str] = []
    replaced = False
    changed = False
    has_blocks = any("{" in line for line in lines)
    context_start = re.compile(r"^\s*([a-zA-Z0-9_]+)\b.*\{\s*$")
    context_found = False
    for line in lines:
        start_match = context_start.match(line)
        if start_match and start_match.group(1) == context:
            context_found = True
            break
    match_anywhere = (
        context in {"any", "all", "file"} or not has_blocks or not context_found
    )
    candidate_insert_idx: int | None = None
    last_indent_in_context: str | None = None
    target_depth: int | None = None

    context_end = re.compile(r"^\s*}\s*;?\s*$")
    directive_re = re.compile(rf"^(\s*){re.escape(directive)}\b.*;")

    for idx, line in enumerate(lines):
        start_match = context_start.match(line)
        if start_match:
            stack.append(start_match.group(1))
            if start_match.group(1) == context and target_depth is None:
                target_depth = len(stack)
        if context_end.match(line):
            if stack:
                if (
                    target_depth is not None
                    and len(stack) == target_depth
                    and stack[-1] == context
                    and candidate_insert_idx is None
                ):
                    candidate_insert_idx = idx
                stack.pop()
            continue

        if match_anywhere or (context == "main" and not stack) or (
            context != "main" and context in stack
        ):
            if context != "main" and context in stack:
                stripped = line.strip()
                if stripped and stripped != "}" and not stripped.endswith("{"):
                    last_indent_in_context = re.match(r"^\s*", line).group(0)
            match = directive_re.match(line)
            if match:
                indent = match.group(1)
                new_line = f"{indent}{directive} {value};"
                if lines[idx] != new_line:
                    changed = True
                lines[idx] = new_line
                replaced = True

    if replaced:
        matched_line = f"{directive} {value};"
        return "\n".join(lines), changed, matched_line

    insert_line = f"{directive} {value};"
    if match_anywhere:
        lines.append(insert_line)
        return "\n".join(lines), True, insert_line

    if context == "main":
        insert_at = None
        for idx, line in enumerate(lines):
            if context_start.match(line) and not stack:
                insert_at = idx
                break
        if insert_at is None:
            lines.append(insert_line)
        else:
            lines.insert(insert_at, insert_line)
        return "\n".join(lines), True, insert_line

    if candidate_insert_idx is not None:
        closing_indent = re.match(r"^\s*", lines[candidate_insert_idx]).group(0)
        indent = last_indent_in_context or (closing_indent + "    ")
        lines.insert(candidate_insert_idx, f"{indent}{directive} {value};")
        return "\n".join(lines), True, insert_line

    return "\n".join(lines), False, None


def remove_directive(
    text: str, directive: str, context: str
) -> tuple[str, bool]:
    lines = text.splitlines()
    stack: list[str] = []
    removed = False
    has_blocks = any("{" in line for line in lines)
    match_anywhere = context in {"any", "all", "file"} or not has_blocks

    context_start = re.compile(r"^\s*([a-zA-Z0-9_]+)\b.*\{\s*$")
    context_end = re.compile(r"^\s*}\s*;?\s*$")
    directive_re = re.compile(rf"^\s*{re.escape(directive)}\b.*;")

    output: list[str] = []
    for line in lines:
        start_match = context_start.match(line)
        if start_match:
            stack.append(start_match.group(1))
        if context_end.match(line):
            if stack:
                stack.pop()
            output.append(line)
            continue

        in_context = match_anywhere or (context == "main" and not stack) or (
            context != "main" and context in stack
        )
        if in_context and directive_re.match(line):
            removed = True
            continue
        output.append(line)

    return "\n".join(output), removed


def apply_with_rollback(
    main_config_path: Path,
    planned_updates: list[dict[str, Any]],
    backups_written: set[Path],
    initial_texts: dict[Path, str],
) -> bool:
    print("[preflight] applying changes and validating syntax")
    changes_made = False

    touched_files: set[Path] = set()

    try:
        for update in planned_updates:
            config_path = update["config_path"]
            new_text = update["new_text"]
            directive = update["directive"]
            context = update["context"]
            action = update["action"]
            if update.get("format"):
                value_str = render_directive_value(
                    update.get("learner_value", update.get("value")),
                    update.get("format"),
                )
            else:
                value_str = render_directive_value(
                    update.get("nginx_value", update.get("value")), None
                )

            if not update["changed"]:
                if action == "remove":
                    log_line(f"no_change remove={directive} path={config_path}")
                    print(f"[apply] no change needed (remove {directive})")
                else:
                    log_line(
                        f"no_change directive={directive} value={value_str} path={config_path}"
                    )
                    matched = update.get("matched_line")
                    if matched:
                        print(
                            f"[apply] no change needed ({directive}={value_str}) "
                            f"matched={matched}"
                        )
                    else:
                        print(f"[apply] no change needed ({directive}={value_str})")
                continue

            backup_config(config_path, backups_written)
            config_path.write_text(new_text, encoding="utf-8")
            touched_files.add(config_path)
            if action == "remove":
                log_line(
                    f"removed directive={directive} context={context} path={config_path}"
                )
                print(f"[apply] removed {directive} from {context} ({config_path})")
            else:
                log_line(
                    f"updated directive={directive} value={value_str} context={context} "
                    f"path={config_path}"
                )
                print(
                    f"[apply] updated {directive}={value_str} in {context} ({config_path})"
                )
            changes_made = True

        if not changes_made:
            print("[preflight] no changes needed; skipping syntax test")
            return False

        result = subprocess.run(
            ["nginx", "-t", "-c", str(main_config_path)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            log_line(
                f"syntax_fail_dryrun path={main_config_path} stderr={result.stderr.strip()}"
            )
            print(f"[preflight] dry-run failed: {result.stderr.strip()}")
            raise RuntimeError(result.stderr.strip() or "nginx -t dry-run failed")

        log_line(f"syntax_ok_dryrun path={main_config_path}")
        print("[preflight] dry-run ok")
        return True
    except Exception as exc:
        for config_path in touched_files:
            original_text = initial_texts.get(config_path)
            if original_text is not None:
                config_path.write_text(original_text, encoding="utf-8")
        safe_log_line("rollback_completed")
        print("[rollback] restored original config files")
        raise exc



def test_config(config_path: Path) -> None:
    print(f"[test] nginx -t -c {config_path}")
    result = subprocess.run(
        ["nginx", "-t", "-c", str(config_path)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        log_line(f"syntax_fail path={config_path} stderr={result.stderr.strip()}")
        print(f"[test] failed: {result.stderr.strip()}")
        raise RuntimeError(result.stderr.strip() or "nginx -t failed")
    log_line(f"syntax_ok path={config_path}")
    print("[test] ok")


def reload_config(config_path: Path) -> None:
    print(f"[reload] nginx -s reload -c {config_path}")
    result = subprocess.run(
        ["nginx", "-s", "reload", "-c", str(config_path)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        log_line(f"reload_fail path={config_path} stderr={result.stderr.strip()}")
        print(f"[reload] failed: {result.stderr.strip()}")
        raise RuntimeError(result.stderr.strip() or "nginx reload failed")
    log_line(f"reload_ok path={config_path}")
    print("[reload] ok")


def restart_nginx() -> None:
    print("[restart] attempting nginx restart")
    commands = [
        ["systemctl", "restart", "nginx"],
        ["service", "nginx", "restart"],
        ["brew", "services", "restart", "nginx"],
    ]

    for cmd in commands:
        if shutil.which(cmd[0]) is None:
            continue
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            log_line(f"restart_ok cmd={' '.join(cmd)}")
            print(f"[restart] ok via {' '.join(cmd)}")
            return
        log_line(
            f"restart_fail cmd={' '.join(cmd)} stderr={result.stderr.strip()}"
        )
        print(f"[restart] failed via {' '.join(cmd)}: {result.stderr.strip()}")

    raise RuntimeError("Unable to restart nginx with available commands")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Update nginx worker_connections from a YAML settings file and "
            "apply the config."
        )
    )
    parser.add_argument(
        "settings",
        metavar="SETTINGS_YAML",
        help="Path to the YAML settings file (e.g. testbed/workload_settings.yaml)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate and write configs but skip reload/restart",
    )
    parser.add_argument(
        "--reload-only",
        action="store_true",
        help="Reload nginx but skip restart",
    )
    return parser.parse_args()


def check_root() -> bool:
    if os.name != "posix":
        return True
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print(
            "[error] Root privileges are required to modify nginx configs. "
            "Try: sudo ..."
        )
        return False
    return True


def apply_settings(
    settings: Dict[str, Any], dry_run: bool = False, reload_only: bool = False
) -> dict[str, Any]:
    nginx_settings = settings.get("nginx") or {}
    nginx_files = nginx_settings.get("files") or {}
    nginx_configs = nginx_settings.get("configs") or {}
    nginx_remove = nginx_settings.get("remove") or {}
    if "main" not in nginx_files:
        raise ValueError("Missing nginx.files.main in settings")
    if not nginx_configs:
        raise ValueError("Missing nginx.configs in settings")

    main_config_path = Path(str(nginx_files["main"]).strip())
    print(f"[settings] main_config={main_config_path}")

    backups_written: set[Path] = set()
    planned_updates: list[dict[str, Any]] = []
    file_texts: dict[Path, str] = {}
    initial_texts: dict[Path, str] = {}

    def get_config_path(file_ref: Any) -> Path:
        file_key = str(file_ref).strip()
        return Path(str(nginx_files.get(file_key, file_key)).strip())

    def get_current_text(config_path: Path) -> str:
        if config_path not in file_texts:
            text = config_path.read_text(encoding="utf-8")
            file_texts[config_path] = text
            initial_texts[config_path] = text
        return file_texts[config_path]

    for name, config in nginx_configs.items():
        if not isinstance(config, dict):
            raise ValueError(f"Invalid config entry: {name}")
        directive = config.get("directive")
        value = config.get("value")
        nginx_value = config.get("nginx_value")
        learner_value = config.get("learner_value")
        fmt = config.get("format")
        context = config.get("context")
        file_ref = config.get("file")
        if not directive or context is None or file_ref is None:
            raise ValueError(f"Config {name} missing directive/context/file")

        config_path = get_config_path(file_ref)
        print(
            f"[settings] config={name} directive={directive} "
            f"context={context} file={config_path}"
        )
        current_text = get_current_text(config_path)
        if fmt:
            value_str = render_directive_value(
                learner_value if learner_value is not None else value, fmt
            )
        else:
            value_str = render_directive_value(
                nginx_value if nginx_value is not None else value, None
            )
        new_text, changed, matched_line = find_and_replace_directive(
            current_text, str(directive), value_str, str(context)
        )
        file_texts[config_path] = new_text
        planned_updates.append(
            {
                "name": name,
                "config_path": config_path,
                "new_text": new_text,
                "directive": str(directive),
                "context": str(context),
                "value": value,
                "nginx_value": nginx_value,
                "learner_value": learner_value,
                "format": fmt,
                "action": "set",
                "changed": changed and new_text != current_text,
                "matched_line": matched_line,
            }
        )

    for name, config in nginx_remove.items():
        if not isinstance(config, dict):
            raise ValueError(f"Invalid remove entry: {name}")
        directive = config.get("directive")
        context = config.get("context")
        file_ref = config.get("file")
        if not directive or context is None or file_ref is None:
            raise ValueError(f"Remove {name} missing directive/context/file")

        config_path = get_config_path(file_ref)
        print(
            f"[settings] remove={name} directive={directive} "
            f"context={context} file={config_path}"
        )
        current_text = get_current_text(config_path)
        new_text, removed = remove_directive(
            current_text, str(directive), str(context)
        )
        file_texts[config_path] = new_text
        planned_updates.append(
            {
                "name": name,
                "config_path": config_path,
                "new_text": new_text,
                "directive": str(directive),
                "context": str(context),
                "action": "remove",
                "changed": removed and new_text != current_text,
            }
        )

    if not apply_with_rollback(
        main_config_path, planned_updates, backups_written, initial_texts
    ):
        return {"code": 0, "applied": {}}

    test_config(main_config_path)
    if not dry_run:
        reload_config(main_config_path)
        if not reload_only:
            restart_nginx()
    applied = {}
    for update in planned_updates:
        if update.get("action") != "set":
            continue
        name = update.get("name")
        if not name:
            continue
        if update.get("format"):
            applied[name] = update.get("learner_value", update.get("value"))
        else:
            applied[name] = update.get("nginx_value", update.get("value"))
    return {"code": 0, "applied": applied}


class NginxConfigApplier:
    def __init__(self, settings_path: Path) -> None:
        self.settings_path = settings_path

    def apply(
        self,
        overrides: Dict[str, Any] | None = None,
        dry_run: bool = False,
        reload_only: bool = False,
    ) -> dict[str, Any]:
        settings = load_settings(self.settings_path)
        if overrides:
            apply_overrides(settings, overrides)
        return apply_settings(settings, dry_run=dry_run, reload_only=reload_only)


def main() -> int:
    args = parse_args()
    if not check_root():
        return 1
    settings_path = Path(args.settings)
    print(f"[settings] loading {settings_path}")
    applier = NginxConfigApplier(settings_path)
    result = applier.apply(dry_run=args.dry_run, reload_only=args.reload_only)
    return int(result.get("code", 1))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # pragma: no cover - CLI guardrail
        safe_log_line(f"error msg={exc}")
        print(f"[error] {exc}")
        raise SystemExit(1)
