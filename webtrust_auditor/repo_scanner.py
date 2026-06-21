import re
from pathlib import Path


IGNORED_DIRECTORIES = {
    ".git",
    ".venv",
    "venv",
    "env",
    "bin",
    "obj",
    ".vs",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    "reports"
}


SENSITIVE_FILE_NAMES = {
    ".env",
    ".env.local",
    ".env.production",
    "secrets.json",
    "id_rsa",
    "id_dsa"
}


SENSITIVE_EXTENSIONS = {
    ".db",
    ".sqlite",
    ".sqlite3",
    ".db-shm",
    ".db-wal",
    ".bak",
    ".pfx",
    ".pem",
    ".key"
}


SECRET_KEYWORDS = [
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "private_key",
    "connectionstring",
    "connection string"
]


TEXT_FILE_EXTENSIONS = {
    ".txt",
    ".md",
    ".json",
    ".xml",
    ".yml",
    ".yaml",
    ".config",
    ".cs",
    ".py",
    ".js",
    ".ts",
    ".html",
    ".css",
    ".cshtml"
}


RECOMMENDED_GITIGNORE_RULES = [
    ".env",
    ".venv/",
    "__pycache__/",
    "*.pyc",
    "*.db",
    "*.db-shm",
    "*.db-wal",
    "bin/",
    "obj/",
    ".vs/",
    "*.user",
    "secrets.json",
    "desktop.ini"
]


MAX_TEXT_FILE_SIZE_BYTES = 1_000_000


def scan_repository(repo_path: str) -> dict:
    """
    Scans a local project folder for basic public repository hygiene issues.

    This function only reads local file names and selected text files.
    It does not upload files, execute code or modify the repository.
    """
    root_path = Path(repo_path).expanduser().resolve()

    result = {
        "repo_path": str(root_path),
        "exists": root_path.exists(),
        "is_directory": root_path.is_dir() if root_path.exists() else False,
        "files_checked": 0,
        "findings": [],
        "summary": {
            "gitignore_exists": False,
            "readme_exists": False,
            "dockerfile_exists": False,
            "dockerignore_exists": False,
            "sensitive_files_found": 0,
            "database_files_found": 0,
            "secret_keyword_hits": 0
        },
        "error": None
    }

    if not result["exists"]:
        result["error"] = "Repository path does not exist."
        return result

    if not result["is_directory"]:
        result["error"] = "Repository path is not a directory."
        return result

    check_project_metadata(root_path, result)
    check_gitignore_rules(root_path, result)
    scan_files(root_path, result)

    return result


def check_project_metadata(root_path: Path, result: dict) -> None:
    """
    Checks important project files such as README, Dockerfile and .gitignore.
    """
    gitignore_path = root_path / ".gitignore"
    readme_path = root_path / "README.md"
    dockerfile_path = root_path / "Dockerfile"
    dockerignore_path = root_path / ".dockerignore"

    result["summary"]["gitignore_exists"] = gitignore_path.exists()
    result["summary"]["readme_exists"] = readme_path.exists()
    result["summary"]["dockerfile_exists"] = dockerfile_path.exists()
    result["summary"]["dockerignore_exists"] = dockerignore_path.exists()

    if not gitignore_path.exists():
        result["findings"].append({
            "title": ".gitignore is missing",
            "severity": "Medium",
            "evidence": "No .gitignore file was found in the repository root.",
            "why": ".gitignore helps prevent temporary files, build output and secrets from being committed.",
            "recommendation": "Add a .gitignore file with rules for build outputs, local environments and sensitive files."
        })

    if not readme_path.exists():
        result["findings"].append({
            "title": "README.md is missing",
            "severity": "Low",
            "evidence": "No README.md file was found in the repository root.",
            "why": "A README helps other people understand, install and review the project.",
            "recommendation": "Add a README.md with project purpose, setup instructions, usage examples and security notes."
        })


    if dockerfile_path.exists() and not dockerignore_path.exists():
        result["findings"].append({
            "title": ".dockerignore is missing",
            "severity": "Low",
            "evidence": "Dockerfile exists, but .dockerignore was not found.",
            "why": ".dockerignore prevents unnecessary or sensitive files from being copied into Docker images.",
            "recommendation": "Add a .dockerignore file to exclude build output, local environments and sensitive files."
        })


def check_gitignore_rules(root_path: Path, result: dict) -> None:
    """
    Checks whether .gitignore contains recommended rules.
    """
    gitignore_path = root_path / ".gitignore"

    if not gitignore_path.exists():
        return

    try:
        gitignore_content = gitignore_path.read_text(
            encoding="utf-8",
            errors="ignore"
        ).lower()
    except OSError:
        result["findings"].append({
            "title": ".gitignore could not be read",
            "severity": "Low",
            "evidence": "The .gitignore file exists, but could not be read.",
            "why": "The scanner needs to read .gitignore to verify recommended ignore rules.",
            "recommendation": "Check file permissions and encoding."
        })
        return

    for rule in RECOMMENDED_GITIGNORE_RULES:
        if rule.lower() not in gitignore_content:
            result["findings"].append({
                "title": f"Recommended .gitignore rule missing: {rule}",
                "severity": "Info",
                "evidence": f"The rule `{rule}` was not found in .gitignore.",
                "why": "Recommended ignore rules reduce the risk of committing local files, build output or sensitive data.",
                "recommendation": f"Consider adding `{rule}` to .gitignore if it applies to this project."
            })


def scan_files(root_path: Path, result: dict) -> None:
    """
    Walks through repository files and checks for sensitive files and secret-like assignments.
    """
    for file_path in root_path.rglob("*"):
        if should_skip_path(file_path):
            continue

        if file_path.is_dir():
            continue

        result["files_checked"] += 1

        check_sensitive_file(file_path, root_path, result)
        check_secret_assignments(file_path, root_path, result)


def should_skip_path(path: Path) -> bool:
    """
    Skips directories that should not be scanned.
    Works case-insensitively for Windows and Linux paths.
    """
    path_parts = {part.lower() for part in path.parts}

    return any(directory.lower() in path_parts for directory in IGNORED_DIRECTORIES)


def check_sensitive_file(file_path: Path, root_path: Path, result: dict) -> None:
    """
    Detects sensitive file names and risky file extensions.
    """
    relative_path = get_relative_path(file_path, root_path)
    file_name = file_path.name.lower()
    suffix = file_path.suffix.lower()

    if file_name in SENSITIVE_FILE_NAMES:
        result["summary"]["sensitive_files_found"] += 1

        result["findings"].append({
            "title": "Sensitive file found",
            "severity": "High",
            "evidence": f"Sensitive file detected: {relative_path}",
            "why": "Files such as .env or secrets.json often contain credentials, tokens or private configuration.",
            "recommendation": "Remove sensitive files from the repository and store secrets in environment variables or a secret manager."
        })

    if suffix in SENSITIVE_EXTENSIONS:
        if suffix in {".db", ".sqlite", ".sqlite3", ".db-shm", ".db-wal"}:
            result["summary"]["database_files_found"] += 1

        result["findings"].append({
            "title": "Potentially sensitive file extension found",
            "severity": "Medium",
            "evidence": f"File with sensitive extension detected: {relative_path}",
            "why": "Database, key, backup or certificate files can contain private data or credentials.",
            "recommendation": "Verify whether this file should be public. If not, remove it and add the extension to .gitignore."
        })


def check_secret_assignments(file_path: Path, root_path: Path, result: dict) -> None:
    """
    Looks for secret-like assignments in text/code files.

    This is more precise than searching for every keyword everywhere.
    It tries to detect assignment patterns without printing secret values.
    """
    suffix = file_path.suffix.lower()

    if suffix not in TEXT_FILE_EXTENSIONS:
        return

    try:
        if file_path.stat().st_size > MAX_TEXT_FILE_SIZE_BYTES:
            return
    except OSError:
        return

    try:
        lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return

    inside_multiline_string = False

    for line_number, line in enumerate(lines, start=1):
        cleaned_line = line.strip()

        triple_quote_count = cleaned_line.count('"""') + cleaned_line.count("'''")

        if triple_quote_count:
            if triple_quote_count % 2 == 1:
                inside_multiline_string = not inside_multiline_string
            continue

        if inside_multiline_string:
            continue

        if should_skip_line(cleaned_line):
            continue

        for keyword in SECRET_KEYWORDS:
            if looks_like_secret_assignment(cleaned_line, keyword):
                relative_path = get_relative_path(file_path, root_path)
                result["summary"]["secret_keyword_hits"] += 1

                result["findings"].append({
                    "title": "Possible hardcoded secret assignment found",
                    "severity": "Medium",
                    "evidence": f"Keyword `{keyword}` appears in a possible assignment in file: {relative_path}, line {line_number}",
                    "why": "Hardcoded secrets can leak credentials, tokens or private configuration into a public repository.",
                    "recommendation": "Review this line manually. Store real secrets in environment variables or a secret manager."
                })

                return


def should_skip_line(line: str) -> bool:
    """
    Skips empty lines, comments and obvious documentation lines.
    """
    if not line:
        return True

    comment_prefixes = ("#", "//", "/*", "*", "<!--")

    if line.startswith(comment_prefixes):
        return True

    return False


def looks_like_secret_assignment(line: str, keyword: str) -> bool:
    """
    Detects whether a line looks like a secret assignment.

    It only checks the left side of an assignment to reduce false positives.
    """
    separators = ["=", ":"]

    for separator in separators:
        if separator not in line:
            continue

        left_side, right_side = line.split(separator, 1)

        if not contains_keyword(left_side, keyword):
            continue

        right_side = right_side.strip()

        if not right_side:
            continue

        if right_side.startswith(("[", "{", "(")):
            continue

        safe_empty_values = {
            "none",
            "null",
            "nil",
            "false",
            "true",
            "\"\"",
            "''"
        }

        if right_side.lower().rstrip(",") in safe_empty_values:
            continue

        return True

    return False


def contains_keyword(text: str, keyword: str) -> bool:
    """
    Checks whether a keyword appears as a real token.
    """
    pattern = rf"(?<![a-zA-Z0-9_]){re.escape(keyword)}(?![a-zA-Z0-9_])"
    return re.search(pattern, text, flags=re.IGNORECASE) is not None


def get_relative_path(file_path: Path, root_path: Path) -> str:
    """
    Converts an absolute path into a repository-relative path.
    """
    try:
        return str(file_path.relative_to(root_path))
    except ValueError:
        return str(file_path)