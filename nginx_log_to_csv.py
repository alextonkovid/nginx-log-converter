import argparse
import csv
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple

import yaml


# Default pattern/fieldnames used if no YAML config is provided or readable.
DEFAULT_FIELDNAMES: List[str] = [
    "client_ip",
    "remote_ident",
    "remote_user",
    "time_local",
    "request",
    "status",
    "body_bytes_sent",
    "http_referer",
    "http_user_agent",
    "request_length",
    "request_time",
    "proxy_upstream_name",
    "proxy_alternative_upstream_name",
    "upstream_addr",
    "upstream_response_length",
    "upstream_response_time",
    "upstream_status",
    "request_id",
]


DEFAULT_LOG_PATTERN = re.compile(
    r'^(\S+)\s+'  # client_ip
    r'(\S+)\s+'  # remote_ident
    r'(\S+)\s+'  # remote_user
    r'\[([^\]]+)\]\s+'  # time_local
    r'"([^"]*)"\s+'  # request
    r'(\d{3})\s+'  # status
    r'(\d+)\s+'  # body_bytes_sent
    r'"([^"]*)"\s+'  # http_referer
    r'"([^"]*)"\s+'  # http_user_agent
    r'(\d+)\s+'  # request_length
    r'([\d.]+)\s+'  # request_time
    r'\[([^\]]*)\]\s+'  # proxy_upstream_name
    r'\[([^\]]*)\]\s+'  # proxy_alternative_upstream_name
    r'(\S+)\s+'  # upstream_addr
    r'(\d+)\s+'  # upstream_response_length
    r'([\d.]+)\s+'  # upstream_response_time
    r'(\d{3})\s+'  # upstream_status
    r'(\S+)$'  # request_id
)


def load_config(
    config_path: Optional[str],
) -> Tuple[re.Pattern, List[str]]:
    """
    Load parser configuration from a YAML file.

    If config_path is None, tries to load `nginx_log_to_csv.yaml` from the current
    directory. If loading fails, falls back to DEFAULT_LOG_PATTERN/DEFAULT_FIELDNAMES.
    """
    path = config_path or "nginx_log_to_csv.yaml"

    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
    except FileNotFoundError:
        # Fall back to built-in defaults.
        return DEFAULT_LOG_PATTERN, DEFAULT_FIELDNAMES

    pattern_str = cfg.get("pattern")
    fieldnames = cfg.get("fieldnames")

    if not pattern_str or not isinstance(pattern_str, str):
        sys.stderr.write(
            "Config missing valid 'pattern' string; using built-in default pattern.\n"
        )
        pattern = DEFAULT_LOG_PATTERN
    else:
        pattern = re.compile(pattern_str)

    if not fieldnames or not isinstance(fieldnames, list):
        sys.stderr.write(
            "Config missing valid 'fieldnames' list; using built-in default fieldnames.\n"
        )
        fieldnames = DEFAULT_FIELDNAMES

    return pattern, fieldnames  # type: ignore[return-value]


def parse_line(
    line: str,
    pattern: re.Pattern,
    fieldnames: List[str],
) -> Optional[Dict[str, str]]:
    """Parse a single nginx log line into a dict matching fieldnames."""
    line = line.rstrip("\n")
    if not line:
        return None

    match = pattern.match(line)
    if not match:
        return None

    groups = list(match.groups())
    if len(groups) != len(fieldnames):
        return None

    return dict(zip(fieldnames, groups))


def iter_parsed_rows(
    lines: Iterable[str],
    pattern: re.Pattern,
    fieldnames: List[str],
) -> Iterable[Dict[str, str]]:
    """Yield parsed rows, logging unparsable lines to stderr."""
    for idx, line in enumerate(lines, start=1):
        parsed = parse_line(line, pattern, fieldnames)
        if parsed is None:
            sys.stderr.write(f"Failed to parse line {idx}: {line.rstrip()}\n")
            continue
        yield parsed


def apply_filters(
    rows: List[Dict[str, str]], filters: Dict[str, str]
) -> List[Dict[str, str]]:
    """Filter rows by exact match on provided field=value pairs."""
    if not filters:
        return rows

    def matches(row: Dict[str, str]) -> bool:
        return all(row.get(field) == value for field, value in filters.items())

    return [row for row in rows if matches(row)]


def sort_rows(
    rows: List[Dict[str, str]], sort_fields: List[str], descending: bool
) -> List[Dict[str, str]]:
    """Sort rows by one or more fields (lexicographically)."""
    if not sort_fields or not rows:
        return rows

    return sorted(
        rows,
        key=lambda r: tuple(r.get(field, "") for field in sort_fields),
        reverse=descending,
    )


def convert_log_to_csv(
    input_path: str,
    output_path: str,
    pattern: re.Pattern,
    fieldnames: List[str],
    filters: Dict[str, str],
    sort_fields: List[str],
    sort_desc: bool,
    export_fieldnames: List[str],
) -> None:
    """Read nginx log file and write CSV using configurable parser options."""
    with open(input_path, "r", encoding="utf-8") as infile, open(
        output_path, "w", encoding="utf-8", newline=""
    ) as outfile:
        rows = list(iter_parsed_rows(infile, pattern, fieldnames))

        rows = apply_filters(rows, filters)
        rows = sort_rows(rows, sort_fields, sort_desc)

        writer = csv.DictWriter(outfile, fieldnames=export_fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: v for k, v in row.items() if k in export_fieldnames})


def load_env_file(path: str) -> Dict[str, str]:
    """
    Load simple KEY=VALUE pairs from an env file.

    Lines starting with '#' and empty lines are ignored.
    """
    env: Dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key:
                    env[key] = value
    except FileNotFoundError:
        # Silent: absence of env file simply means no git push configuration.
        return {}
    return env


def normalize_git_url(url: str) -> str:
    """
    Normalize Git URL format for GitHub tokens.
    If URL contains a GitHub token starting with 'ghp_', ensure proper format.
    """
    if "github.com" in url and "ghp_" in url:
        # Extract token and repo path
        if url.startswith("https://ghp_"):
            # Format: https://ghp_TOKEN@github.com/user/repo.git
            # This is already correct, but ensure @ is present
            if "@github.com" not in url:
                url = url.replace("github.com", "@github.com", 1)
        elif "://" in url and "@github.com" not in url:
            # Try to extract token if it's in a different format
            parts = url.split("://", 1)
            if len(parts) == 2:
                rest = parts[1]
                if rest.startswith("ghp_"):
                    token_end = rest.find("/")
                    if token_end > 0:
                        token = rest[:token_end]
                        repo_path = rest[token_end:]
                        url = f"{parts[0]}://{token}@github.com{repo_path}"
    return url


def git_push_csv(csv_path: str, env_path: str) -> None:
    """
    Automatically push the generated CSV file to a git repository
    defined via variables in the env file or environment variables.

    Expected env variables (from file or environment):
    - GIT_REPO_URL  (required)  e.g. https://token@github.com/user/repo.git
    - GIT_BRANCH    (optional)  default: main
    - GIT_REPO_DIR  (optional)  directory name for the local clone, default: repo

    Environment variables take precedence over .env file values.
    """
    # First check environment variables (for Docker -e flags)
    env_vars: Dict[str, str] = {}
    for key in ["GIT_REPO_URL", "GIT_BRANCH", "GIT_REPO_DIR"]:
        value = os.environ.get(key)
        if value:
            env_vars[key] = value

    # Then load from .env file (env vars override file values)
    file_env = load_env_file(env_path)
    for key, value in file_env.items():
        if key not in env_vars:  # Don't override env vars
            env_vars[key] = value

    repo_url = env_vars.get("GIT_REPO_URL")
    if not repo_url:
        return

    # Normalize URL format for GitHub
    repo_url = normalize_git_url(repo_url)

    branch = env_vars.get("GIT_BRANCH", "main")
    repo_dir = env_vars.get("GIT_REPO_DIR", "repo")

    try:
        # Ensure git is available
        subprocess.run(
            ["git", "--version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
    except Exception:
        sys.stderr.write("Git not available; skipping automatic git push.\n")
        return

    try:
        is_new_repo = not os.path.isdir(repo_dir)
        
        if is_new_repo:
            # Clone repository if it doesn't exist
            clone_result = subprocess.run(
                ["git", "clone", repo_url, repo_dir],
                capture_output=True,
                text=True,
                check=False,
            )
            if clone_result.returncode != 0:
                error_msg = clone_result.stderr.strip() or clone_result.stdout.strip()
                if "Could not resolve host" in error_msg or "Name or service not known" in error_msg:
                    sys.stderr.write(
                        f"Network error: Cannot reach Git repository. "
                        f"Check your internet connection and DNS settings.\n"
                    )
                elif "Authentication failed" in error_msg or "fatal: could not read Username" in error_msg:
                    sys.stderr.write(
                        f"Authentication error: Invalid token or credentials. "
                        f"Check your GIT_REPO_URL in .env file.\n"
                    )
                else:
                    sys.stderr.write(f"Git clone failed: {error_msg}\n")
                return
        
        # Add repository directory to safe.directory to avoid ownership issues
        # This is needed when running in Docker or with different user permissions
        abs_repo_dir = os.path.abspath(repo_dir)
        subprocess.run(
            ["git", "config", "--global", "--add", "safe.directory", abs_repo_dir],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        
        if not is_new_repo:
            # Repository exists - configure git and update before push
            # Set git config if not already set (needed for commits)
            subprocess.run(
                ["git", "config", "user.name", "nginx-log-converter"],
                cwd=repo_dir,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                ["git", "config", "user.email", "nginx-log-converter@localhost"],
                cwd=repo_dir,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            
            # Ensure we're on the correct branch
            subprocess.run(
                ["git", "checkout", branch],
                cwd=repo_dir,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            
            # Pull latest changes before pushing
            pull_result = subprocess.run(
                ["git", "pull", "origin", branch],
                cwd=repo_dir,
                capture_output=True,
                text=True,
                check=False,
            )
            if pull_result.returncode != 0:
                error_msg = pull_result.stderr.strip() or pull_result.stdout.strip()
                # Ignore "Already up to date" messages
                if "Already up to date" not in error_msg and "up to date" not in error_msg.lower():
                    sys.stderr.write(f"Git pull warning: {error_msg}\n")

        dest_path = os.path.join(repo_dir, os.path.basename(csv_path))
        shutil.copy2(csv_path, dest_path)

        # Commit and push changes if any.
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        commit_message = f"Update CSV {os.path.basename(csv_path)} at {timestamp}"

        subprocess.run(
            ["git", "add", os.path.basename(csv_path)],
            cwd=repo_dir,
            check=True,
        )

        # If there is nothing to commit, git returns non-zero; handle gracefully.
        commit_result = subprocess.run(
            ["git", "commit", "-m", commit_message],
            cwd=repo_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if commit_result.returncode != 0:
            # Nothing to commit
            return

        push_result = subprocess.run(
            ["git", "push", "origin", branch],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            check=False,
        )
        if push_result.returncode != 0:
            error_msg = push_result.stderr.strip() or push_result.stdout.strip()
            sys.stderr.write(f"Git push failed: {error_msg}\n")
            return

        sys.stdout.write(f"Successfully pushed {os.path.basename(csv_path)} to {branch} branch.\n")
    except Exception as exc:  # pylint: disable=broad-except
        sys.stderr.write(f"Automatic git push failed: {exc}\n")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Convert nginx access log to CSV using a configurable YAML parser "
            "definition."
        )
    )
    parser.add_argument(
        "input",
        help="Path to nginx log file (e.g. nginx.log).",
    )
    parser.add_argument(
        "output",
        help="Path to output CSV file (e.g. nginx.csv).",
    )
    parser.add_argument(
        "-c",
        "--config",
        help=(
            "Path to YAML config with 'pattern' and 'fieldnames'. "
            "Defaults to nginx_log_to_csv.yaml if present; otherwise built-in defaults."
        ),
    )
    parser.add_argument(
        "--filter",
        action="append",
        default=[],
        metavar="FIELD=VALUE",
        help=(
            "Filter rows by exact FIELD=VALUE match. Can be specified multiple "
            "times, e.g. --filter status=200 --filter client_ip=1.2.3.4"
        ),
    )
    parser.add_argument(
        "--sort-by",
        metavar="FIELDS",
        help=(
            "Comma-separated list of fields to sort by, e.g. "
            "--sort-by time_local,status"
        ),
    )
    parser.add_argument(
        "--desc",
        action="store_true",
        help="Sort in descending order (default is ascending).",
    )
    parser.add_argument(
        "--columns",
        metavar="FIELDS",
        help=(
            "Comma-separated list of fields to export to CSV header, e.g. "
            "--columns client_ip,request,status. By default all fields "
            "from the config are exported."
        ),
    )
    parser.add_argument(
        "--env-file",
        default=".env",
        help=(
            "Path to env file with git configuration (GIT_REPO_URL, GIT_BRANCH, "
            "GIT_REPO_DIR). Defaults to .env in the current directory."
        ),
    )
    parser.add_argument(
        "--no-git-push",
        action="store_true",
        help=(
            "Disable automatic git push of the generated CSV file, even if "
            "git configuration is present in the env file."
        ),
    )

    args = parser.parse_args(argv)

    pattern, fieldnames = load_config(args.config)

    filters: Dict[str, str] = {}
    for flt in args.filter:
        if "=" not in flt:
            sys.stderr.write(
                f"Ignoring invalid filter '{flt}', expected format FIELD=VALUE.\n"
            )
            continue
        field, value = flt.split("=", 1)
        field = field.strip()
        value = value.strip()
        if not field:
            sys.stderr.write(
                f"Ignoring filter with empty field name: '{flt}'.\n"
            )
            continue
        filters[field] = value

    sort_fields: List[str] = []
    if args.sort_by:
        sort_fields = [
            field.strip() for field in args.sort_by.split(",") if field.strip()
        ]

    # Determine which columns to export. By default, export all parsed fields.
    export_fieldnames: List[str] = fieldnames
    if args.columns:
        requested = [
            field.strip() for field in args.columns.split(",") if field.strip()
        ]
        valid: List[str] = []
        for field in requested:
            if field not in fieldnames:
                sys.stderr.write(
                    f"Ignoring unknown column '{field}' in --columns; "
                    "it is not defined in config fieldnames.\n"
                )
                continue
            valid.append(field)
        if valid:
            export_fieldnames = valid
        else:
            sys.stderr.write(
                "No valid columns specified in --columns; exporting all fields.\n"
            )

    try:
        convert_log_to_csv(
            args.input,
            args.output,
            pattern,
            fieldnames,
            filters,
            sort_fields,
            args.desc,
            export_fieldnames,
        )
    except FileNotFoundError as exc:
        sys.stderr.write(f"File not found: {exc.filename}\n")
        return 1
    except Exception as exc:  # pylint: disable=broad-except
        sys.stderr.write(f"Unexpected error: {exc}\n")
        return 1

    # By default, attempt to push the generated CSV to git if configuration is present.
    if not args.no_git_push:
        git_push_csv(args.output, args.env_file)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

