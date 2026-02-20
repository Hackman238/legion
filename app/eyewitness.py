import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


def _is_text_script_without_shebang(path: str) -> bool:
    try:
        with open(path, "rb") as handle:
            data = handle.read(512)
    except Exception:
        return False
    if not data:
        return False
    if data.startswith(b"#!"):
        return False
    if b"\x00" in data:
        return False
    return True


def resolve_eyewitness_executables() -> List[str]:
    # Prefer PATH resolution first so custom installs work.
    path_names = [
        "eyewitness",
        "EyeWitness.py",
        "EyeWitness",
    ]
    candidates: List[str] = []
    seen = set()
    for name in path_names:
        resolved = shutil.which(name)
        if resolved and os.path.isfile(resolved):
            real = os.path.realpath(resolved)
            if real not in seen:
                seen.add(real)
                candidates.append(real)

    # Fallback to common distro/package paths.
    fallback_paths = [
        "/usr/bin/eyewitness",
        "/usr/local/bin/eyewitness",
        "/usr/bin/EyeWitness.py",
        "/usr/local/bin/EyeWitness.py",
        "/opt/EyeWitness/EyeWitness.py",
        "/usr/share/eyewitness/EyeWitness.py",
    ]
    for candidate in fallback_paths:
        if os.path.isfile(candidate):
            real = os.path.realpath(candidate)
            if real not in seen:
                seen.add(real)
                candidates.append(real)
    return candidates


def resolve_eyewitness_executable() -> Optional[str]:
    candidates = resolve_eyewitness_executables()
    if not candidates:
        return None
    return candidates[0]


def build_eyewitness_command(
        url: str,
        output_dir: str,
        delay: int = 5,
        use_xvfb: bool = True,
        executable: Optional[str] = None,
) -> Tuple[Optional[List[str]], str]:
    executable = executable or resolve_eyewitness_executable()
    if not executable:
        return None, "eyewitness missing"

    command: List[str] = []
    if use_xvfb:
        xvfb_run = shutil.which("xvfb-run")
        if xvfb_run:
            command.extend([xvfb_run, "-a"])

    lower_exec = executable.lower()
    if lower_exec.endswith(".py"):
        python_exec = shutil.which("python3") or sys.executable or "python3"
        command.extend([python_exec, executable])
    elif _is_text_script_without_shebang(executable):
        shell_exec = shutil.which("sh") or "/bin/sh"
        command.extend([shell_exec, executable])
    else:
        command.append(executable)

    command.extend([
        "--single", str(url),
        "--no-prompt",
        "--web",
        "--delay", str(int(delay)),
        "-d", str(output_dir),
    ])
    return command, executable


def build_eyewitness_env(base_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    env = dict(base_env or os.environ)
    # Force stdlib HTTPS clients to skip certificate validation.
    env["PYTHONHTTPSVERIFY"] = "0"
    return env


def find_eyewitness_screenshot(output_dir: str) -> Optional[str]:
    roots: List[str] = []
    preferred = os.path.join(output_dir, "screens")
    if os.path.isdir(preferred):
        roots.append(preferred)
    if os.path.isdir(output_dir):
        roots.append(output_dir)
    if not roots:
        return None

    candidates: List[str] = []
    seen = set()
    for root in roots:
        for current, _dirs, files in os.walk(root):
            for name in files:
                if not str(name).lower().endswith(".png"):
                    continue
                path = os.path.join(current, name)
                real = os.path.realpath(path)
                if real in seen:
                    continue
                seen.add(real)
                candidates.append(path)

    if not candidates:
        return None

    def _mtime(path: str) -> float:
        try:
            return os.path.getmtime(path)
        except Exception:
            return 0.0

    candidates.sort(key=_mtime, reverse=True)
    return candidates[0]


def _attempt_failure_text(attempt: Dict[str, Any]) -> str:
    raw_error = str(attempt.get("error", "") or "").strip()
    raw_stderr = str(attempt.get("stderr", "") or "").strip()
    raw_stdout = str(attempt.get("stdout", "") or "").strip()
    if raw_error:
        raw = raw_error
    elif raw_stderr:
        raw = raw_stderr
    else:
        lines = [line.strip() for line in raw_stdout.splitlines() if line.strip()]
        raw = lines[-1] if lines else raw_stdout

    # Strip ANSI control sequences from tool output.
    raw = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", raw)
    raw = " ".join(raw.split())
    executable = str(attempt.get("executable", "")).strip()
    if executable and raw:
        return f"{executable}: {raw}"
    return executable or raw


def summarize_eyewitness_failure(attempts: List[Dict[str, Any]], max_len: int = 240) -> str:
    if not attempts:
        return ""

    fragments: List[str] = []
    for attempt in attempts[-3:]:
        text = _attempt_failure_text(attempt)
        if text and text not in fragments:
            fragments.append(text)

    raw = " | ".join(fragments) if fragments else ""
    if len(raw) > max_len:
        raw = raw[: max_len - 3] + "..."
    return raw


def _resolve_browser_screenshot_executables() -> List[str]:
    names = [
        "chromium",
        "chromium-browser",
        "google-chrome",
        "google-chrome-stable",
        "chrome",
        "microsoft-edge",
        "msedge",
    ]
    candidates: List[str] = []
    seen = set()
    for name in names:
        resolved = shutil.which(name)
        if not resolved:
            continue
        resolved_path = os.path.abspath(resolved)
        if resolved_path in seen:
            continue
        seen.add(resolved_path)
        candidates.append(resolved_path)
    return candidates


def _summarize_process_text(stdout: str, stderr: str, max_len: int = 280) -> str:
    text = str(stderr or "").strip() or str(stdout or "").strip()
    text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)
    text = " ".join(text.split())
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text


def _find_latest_png(root_dir: str) -> Optional[str]:
    if not os.path.isdir(root_dir):
        return None
    candidates: List[str] = []
    for current, _dirs, files in os.walk(root_dir):
        for name in files:
            if not str(name).lower().endswith(".png"):
                continue
            path = os.path.join(current, name)
            if os.path.isfile(path):
                candidates.append(path)
    if not candidates:
        return None
    try:
        candidates.sort(key=lambda path: os.path.getmtime(path), reverse=True)
    except Exception:
        candidates.sort(reverse=True)
    return candidates[0]


def _resolve_browser_screenshot_path(
        *,
        attempt_output_dir: str,
        preferred_path: str,
        wait_seconds: float = 2.0,
) -> Optional[str]:
    deadline = time.monotonic() + max(0.0, float(wait_seconds))
    implicit_path = os.path.join(attempt_output_dir, "screenshot.png")

    while True:
        if preferred_path and os.path.isfile(preferred_path):
            return preferred_path
        if os.path.isfile(implicit_path):
            return implicit_path
        latest = _find_latest_png(attempt_output_dir)
        if latest and os.path.isfile(latest):
            return latest
        if time.monotonic() >= deadline:
            return None
        time.sleep(0.12)


def _run_browser_cli_fallback_capture(
        *,
        url: str,
        output_parent_dir: str,
        timeout: int,
) -> Dict[str, Any]:
    executables = _resolve_browser_screenshot_executables()
    if not executables:
        return {
            "ok": False,
            "executable": "browser-cli-fallback",
            "output_dir": "",
            "command": [],
            "error": "no supported browser binary found",
            "returncode": 127,
            "stdout": "",
            "stderr": "",
            "screenshot_path": None,
        }

    attempts: List[Dict[str, Any]] = []
    effective_timeout = max(10, min(int(timeout), 45))

    for executable in executables:
        # Try variants because browser wrappers differ on accepted flags:
        # `--headless=new` vs `--headless`, and `--screenshot=PATH` vs `--screenshot`.
        variants = [
            ("--headless=new", True),
            ("--headless", True),
            ("--headless", False),
        ]

        for headless_flag, use_explicit_path in variants:
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
            attempt_output_dir = os.path.join(
                output_parent_dir,
                f"browser-fallback-{stamp}-{os.getpid()}",
            )
            screens_dir = os.path.join(attempt_output_dir, "screens")
            os.makedirs(screens_dir, exist_ok=True)
            screenshot_path = os.path.join(screens_dir, "capture.png")
            profile_dir = os.path.join(attempt_output_dir, "profile")
            os.makedirs(profile_dir, exist_ok=True)

            command = [
                executable,
                headless_flag,
                "--disable-gpu",
                "--disable-dev-shm-usage",
                "--hide-scrollbars",
                "--ignore-certificate-errors",
                "--allow-insecure-localhost",
                "--allow-running-insecure-content",
                "--no-default-browser-check",
                "--no-first-run",
                "--no-sandbox",
                "--disable-setuid-sandbox",
                f"--window-size=1366,768",
                f"--virtual-time-budget={max(3000, min(effective_timeout * 1000, 15000))}",
                f"--user-data-dir={profile_dir}",
            ]

            if use_explicit_path:
                command.append(f"--screenshot={screenshot_path}")
            else:
                command.append("--screenshot")
            command.append(str(url))

            try:
                completed = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=effective_timeout + 10,
                    env=build_eyewitness_env(),
                    cwd=attempt_output_dir,
                )
            except subprocess.TimeoutExpired as exc:
                attempt = {
                    "ok": False,
                    "executable": executable,
                    "output_dir": attempt_output_dir,
                    "command": command,
                    "error": f"browser fallback timeout: {exc}",
                    "returncode": 124,
                    "stdout": str(getattr(exc, "stdout", "") or ""),
                    "stderr": str(getattr(exc, "stderr", "") or ""),
                    "screenshot_path": None,
                }
                attempts.append(attempt)
                continue
            except Exception as exc:
                attempt = {
                    "ok": False,
                    "executable": executable,
                    "output_dir": attempt_output_dir,
                    "command": command,
                    "error": str(exc),
                    "returncode": 1,
                    "stdout": "",
                    "stderr": "",
                    "screenshot_path": None,
                }
                attempts.append(attempt)
                continue

            resolved_screenshot = _resolve_browser_screenshot_path(
                attempt_output_dir=attempt_output_dir,
                preferred_path=screenshot_path,
                wait_seconds=2.4,
            )
            if resolved_screenshot and os.path.realpath(resolved_screenshot) != os.path.realpath(screenshot_path):
                try:
                    os.makedirs(os.path.dirname(screenshot_path), exist_ok=True)
                    shutil.copy2(resolved_screenshot, screenshot_path)
                    resolved_screenshot = screenshot_path
                except Exception:
                    pass

            if resolved_screenshot and os.path.isfile(resolved_screenshot):
                return {
                    "ok": True,
                    "executable": executable,
                    "output_dir": attempt_output_dir,
                    "command": command,
                    "returncode": int(getattr(completed, "returncode", 0) or 0),
                    "stdout": str(getattr(completed, "stdout", "") or ""),
                    "stderr": str(getattr(completed, "stderr", "") or ""),
                    "screenshot_path": resolved_screenshot,
                }

            stdout = str(getattr(completed, "stdout", "") or "")
            stderr = str(getattr(completed, "stderr", "") or "")
            detail = _summarize_process_text(stdout, stderr)
            error = "browser fallback did not create screenshot"
            if detail:
                error = f"{error} ({detail})"
            attempts.append({
                "ok": False,
                "executable": executable,
                "output_dir": attempt_output_dir,
                "command": command,
                "error": error,
                "returncode": int(getattr(completed, "returncode", 1) or 1),
                "stdout": stdout,
                "stderr": stderr,
                "screenshot_path": None,
            })

    return attempts[-1] if attempts else {
        "ok": False,
        "executable": "browser-cli-fallback",
        "output_dir": "",
        "command": [],
        "error": "browser fallback failed",
        "returncode": 1,
        "stdout": "",
        "stderr": "",
        "screenshot_path": None,
    }


def _run_selenium_chromium_fallback_capture(
        *,
        url: str,
        output_parent_dir: str,
        delay: int,
        timeout: int,
) -> Dict[str, Any]:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    attempt_output_dir = os.path.join(
        output_parent_dir,
        f"selenium-chromium-fallback-{stamp}-{os.getpid()}",
    )
    screens_dir = os.path.join(attempt_output_dir, "screens")
    os.makedirs(screens_dir, exist_ok=True)
    screenshot_path = os.path.join(screens_dir, "capture.png")
    effective_timeout = max(10, min(int(timeout), 45))

    python_exec = shutil.which("python3") or sys.executable or "python3"
    capture_script = (
        "import os,sys,time\n"
        "from selenium import webdriver\n"
        "from selenium.webdriver.chrome.options import Options as ChromeOptions\n"
        "from selenium.webdriver.chrome.service import Service as ChromeService\n"
        "url=sys.argv[1]\n"
        "screenshot=sys.argv[2]\n"
        "delay_s=max(0,int(sys.argv[3]))\n"
        "timeout_s=max(5,int(sys.argv[4]))\n"
        "os.makedirs(os.path.dirname(screenshot), exist_ok=True)\n"
        "driver=None\n"
        "last_error=None\n"
        "for headless_flag in ('--headless=new', '--headless'):\n"
        "  options=ChromeOptions()\n"
        "  options.add_argument(headless_flag)\n"
        "  options.add_argument('--disable-gpu')\n"
        "  options.add_argument('--disable-dev-shm-usage')\n"
        "  options.add_argument('--hide-scrollbars')\n"
        "  options.add_argument('--ignore-certificate-errors')\n"
        "  options.add_argument('--allow-insecure-localhost')\n"
        "  options.add_argument('--allow-running-insecure-content')\n"
        "  options.add_argument('--no-default-browser-check')\n"
        "  options.add_argument('--no-first-run')\n"
        "  options.add_argument('--no-sandbox')\n"
        "  options.add_argument('--disable-setuid-sandbox')\n"
        "  options.add_argument('--window-size=1366,768')\n"
        "  options.set_capability('acceptInsecureCerts', True)\n"
        "  try:\n"
        "    try:\n"
        "      service=ChromeService(log_output=os.devnull)\n"
        "      driver=webdriver.Chrome(options=options, service=service)\n"
        "    except TypeError:\n"
        "      driver=webdriver.Chrome(options=options)\n"
        "    driver.set_page_load_timeout(timeout_s)\n"
        "    driver.set_window_size(1366,768)\n"
        "    driver.get(url)\n"
        "    if delay_s>0:\n"
        "      time.sleep(min(delay_s,30))\n"
        "    saved=bool(driver.save_screenshot(screenshot))\n"
        "    if (not saved) and (not os.path.isfile(screenshot)):\n"
        "      raise RuntimeError('save_screenshot returned false')\n"
        "    last_error=None\n"
        "    break\n"
        "  except Exception as exc:\n"
        "    last_error=exc\n"
        "  finally:\n"
        "    if driver is not None:\n"
        "      try:\n"
        "        driver.quit()\n"
        "      except Exception:\n"
        "        pass\n"
        "      driver=None\n"
        "if last_error is not None:\n"
        "  raise last_error\n"
    )
    command = [
        python_exec,
        "-c",
        capture_script,
        str(url),
        screenshot_path,
        str(int(delay)),
        str(effective_timeout),
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=effective_timeout + 20,
            env=build_eyewitness_env(),
        )
        if int(getattr(completed, "returncode", 0) or 0) != 0:
            return {
                "ok": False,
                "executable": "selenium-chromium-direct",
                "output_dir": attempt_output_dir,
                "command": command,
                "error": "selenium chromium fallback command returned non-zero",
                "returncode": int(getattr(completed, "returncode", 1) or 1),
                "stdout": str(getattr(completed, "stdout", "") or ""),
                "stderr": str(getattr(completed, "stderr", "") or ""),
                "screenshot_path": None,
            }
        if not os.path.isfile(screenshot_path):
            return {
                "ok": False,
                "executable": "selenium-chromium-direct",
                "output_dir": attempt_output_dir,
                "command": command,
                "error": "selenium chromium fallback did not create screenshot",
                "returncode": 1,
                "stdout": str(getattr(completed, "stdout", "") or ""),
                "stderr": str(getattr(completed, "stderr", "") or ""),
                "screenshot_path": None,
            }
        return {
            "ok": True,
            "executable": "selenium-chromium-direct",
            "output_dir": attempt_output_dir,
            "command": command,
            "returncode": int(getattr(completed, "returncode", 0) or 0),
            "stdout": str(getattr(completed, "stdout", "") or ""),
            "stderr": str(getattr(completed, "stderr", "") or ""),
            "screenshot_path": screenshot_path,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "executable": "selenium-chromium-direct",
            "output_dir": attempt_output_dir,
            "command": command,
            "error": f"selenium chromium fallback timeout: {exc}",
            "returncode": 124,
            "stdout": str(getattr(exc, "stdout", "") or ""),
            "stderr": str(getattr(exc, "stderr", "") or ""),
            "screenshot_path": None,
        }
    except Exception as exc:
        return {
            "ok": False,
            "executable": "selenium-chromium-direct",
            "output_dir": attempt_output_dir,
            "command": command,
            "error": str(exc),
            "returncode": 1,
            "stdout": "",
            "stderr": "",
            "screenshot_path": None,
        }


def _run_selenium_fallback_capture(
        *,
        url: str,
        output_parent_dir: str,
        delay: int,
        timeout: int,
) -> Dict[str, Any]:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    attempt_output_dir = os.path.join(
        output_parent_dir,
        f"selenium-fallback-{stamp}-{os.getpid()}",
    )
    screens_dir = os.path.join(attempt_output_dir, "screens")
    os.makedirs(screens_dir, exist_ok=True)
    screenshot_path = os.path.join(screens_dir, "capture.png")
    effective_timeout = max(10, min(int(timeout), 45))

    python_exec = shutil.which("python3") or sys.executable or "python3"
    capture_script = (
        "import os,sys,time\n"
        "from selenium import webdriver\n"
        "from selenium.webdriver.firefox.options import Options as FirefoxOptions\n"
        "from selenium.webdriver.firefox.service import Service as FirefoxService\n"
        "url=sys.argv[1]\n"
        "screenshot=sys.argv[2]\n"
        "delay_s=max(0,int(sys.argv[3]))\n"
        "timeout_s=max(5,int(sys.argv[4]))\n"
        "os.makedirs(os.path.dirname(screenshot), exist_ok=True)\n"
        "options=FirefoxOptions()\n"
        "options.add_argument('--headless')\n"
        "options.accept_insecure_certs=True\n"
        "options.set_preference('security.enterprise_roots.enabled', True)\n"
        "options.set_preference('network.stricttransportsecurity.preloadlist', False)\n"
        "options.set_preference('security.cert_pinning.enforcement_level', 0)\n"
        "driver=None\n"
        "try:\n"
        "  try:\n"
        "    service=FirefoxService(log_output=os.devnull)\n"
        "    driver=webdriver.Firefox(options=options, service=service)\n"
        "  except TypeError:\n"
        "    driver=webdriver.Firefox(options=options)\n"
        "  driver.set_page_load_timeout(timeout_s)\n"
        "  driver.set_window_size(1366,768)\n"
        "  driver.get(url)\n"
        "  if delay_s>0:\n"
        "    time.sleep(min(delay_s,30))\n"
        "  saved=bool(driver.save_screenshot(screenshot))\n"
        "  if (not saved) and (not os.path.isfile(screenshot)):\n"
        "    raise RuntimeError('save_screenshot returned false')\n"
        "finally:\n"
        "  if driver is not None:\n"
        "    try:\n"
        "      driver.quit()\n"
        "    except Exception:\n"
        "      pass\n"
    )
    command = [
        python_exec,
        "-c",
        capture_script,
        str(url),
        screenshot_path,
        str(int(delay)),
        str(effective_timeout),
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=effective_timeout + 20,
            env=build_eyewitness_env(),
        )
        if int(getattr(completed, "returncode", 0) or 0) != 0:
            return {
                "ok": False,
                "executable": "selenium-firefox-direct",
                "output_dir": attempt_output_dir,
                "command": command,
                "error": "selenium fallback command returned non-zero",
                "returncode": int(getattr(completed, "returncode", 1) or 1),
                "stdout": str(getattr(completed, "stdout", "") or ""),
                "stderr": str(getattr(completed, "stderr", "") or ""),
                "screenshot_path": None,
            }
        if not os.path.isfile(screenshot_path):
            return {
                "ok": False,
                "executable": "selenium-firefox-direct",
                "output_dir": attempt_output_dir,
                "command": command,
                "error": "selenium fallback did not create screenshot",
                "returncode": 1,
                "stdout": str(getattr(completed, "stdout", "") or ""),
                "stderr": str(getattr(completed, "stderr", "") or ""),
                "screenshot_path": None,
            }
        return {
            "ok": True,
            "executable": "selenium-firefox-direct",
            "output_dir": attempt_output_dir,
            "command": command,
            "returncode": int(getattr(completed, "returncode", 0) or 0),
            "stdout": str(getattr(completed, "stdout", "") or ""),
            "stderr": str(getattr(completed, "stderr", "") or ""),
            "screenshot_path": screenshot_path,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "executable": "selenium-firefox-direct",
            "output_dir": attempt_output_dir,
            "command": command,
            "error": f"selenium fallback timeout: {exc}",
            "returncode": 124,
            "stdout": str(getattr(exc, "stdout", "") or ""),
            "stderr": str(getattr(exc, "stderr", "") or ""),
            "screenshot_path": None,
        }
    except Exception as exc:
        return {
            "ok": False,
            "executable": "selenium-firefox-direct",
            "output_dir": attempt_output_dir,
            "command": command,
            "error": str(exc),
            "returncode": 1,
            "stdout": "",
            "stderr": "",
            "screenshot_path": None,
        }


def run_eyewitness_capture(
        *,
        url: str,
        output_parent_dir: str,
        delay: int = 5,
        use_xvfb: bool = True,
        timeout: int = 180,
) -> Dict[str, Any]:
    executables = resolve_eyewitness_executables()
    if not executables:
        return {
            "ok": False,
            "reason": "eyewitness missing",
            "attempts": [],
        }

    os.makedirs(output_parent_dir, exist_ok=True)
    attempts: List[Dict[str, Any]] = []

    for index, executable in enumerate(executables):
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
        attempt_output_dir = os.path.join(
            output_parent_dir,
            f"eyewitness-{stamp}-{os.getpid()}-{index}",
        )
        command, resolved = build_eyewitness_command(
            url=url,
            output_dir=attempt_output_dir,
            delay=delay,
            use_xvfb=use_xvfb,
            executable=executable,
        )
        if not command:
            attempts.append({
                "executable": executable,
                "output_dir": attempt_output_dir,
                "command": [],
                "error": "eyewitness missing",
            })
            continue

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=int(timeout),
                env=build_eyewitness_env(),
            )
        except Exception as exc:
            attempts.append({
                "executable": resolved,
                "output_dir": attempt_output_dir,
                "command": command,
                "error": str(exc),
            })
            continue

        screenshot_path = find_eyewitness_screenshot(attempt_output_dir)
        attempt_info = {
            "executable": resolved,
            "output_dir": attempt_output_dir,
            "command": command,
            "returncode": int(getattr(completed, "returncode", 0) or 0),
            "stdout": str(getattr(completed, "stdout", "") or ""),
            "stderr": str(getattr(completed, "stderr", "") or ""),
            "screenshot_path": screenshot_path,
        }
        attempts.append(attempt_info)

        if screenshot_path:
            return {
                "ok": True,
                "reason": "completed",
                "executable": resolved,
                "output_dir": attempt_output_dir,
                "command": command,
                "returncode": attempt_info["returncode"],
                "stdout": attempt_info["stdout"],
                "stderr": attempt_info["stderr"],
                "screenshot_path": screenshot_path,
                "attempts": attempts,
            }

    browser_fallback = _run_browser_cli_fallback_capture(
        url=str(url),
        output_parent_dir=output_parent_dir,
        timeout=int(timeout),
    )
    attempts.append(browser_fallback)
    if browser_fallback.get("ok"):
        return {
            "ok": True,
            "reason": "completed",
            "executable": str(browser_fallback.get("executable", "browser-cli-fallback")),
            "output_dir": str(browser_fallback.get("output_dir", "")),
            "command": list(browser_fallback.get("command", [])),
            "returncode": int(browser_fallback.get("returncode", 0) or 0),
            "stdout": str(browser_fallback.get("stdout", "") or ""),
            "stderr": str(browser_fallback.get("stderr", "") or ""),
            "screenshot_path": str(browser_fallback.get("screenshot_path", "") or ""),
            "attempts": attempts,
        }

    selenium_chromium_fallback = _run_selenium_chromium_fallback_capture(
        url=str(url),
        output_parent_dir=output_parent_dir,
        delay=int(delay),
        timeout=int(timeout),
    )
    attempts.append(selenium_chromium_fallback)
    if selenium_chromium_fallback.get("ok"):
        return {
            "ok": True,
            "reason": "completed",
            "executable": str(selenium_chromium_fallback.get("executable", "selenium-chromium-direct")),
            "output_dir": str(selenium_chromium_fallback.get("output_dir", "")),
            "command": list(selenium_chromium_fallback.get("command", [])),
            "returncode": int(selenium_chromium_fallback.get("returncode", 0) or 0),
            "stdout": str(selenium_chromium_fallback.get("stdout", "") or ""),
            "stderr": str(selenium_chromium_fallback.get("stderr", "") or ""),
            "screenshot_path": str(selenium_chromium_fallback.get("screenshot_path", "") or ""),
            "attempts": attempts,
        }

    fallback = _run_selenium_fallback_capture(
        url=str(url),
        output_parent_dir=output_parent_dir,
        delay=int(delay),
        timeout=int(timeout),
    )
    attempts.append(fallback)
    if fallback.get("ok"):
        return {
            "ok": True,
            "reason": "completed",
            "executable": str(fallback.get("executable", "selenium-firefox-direct")),
            "output_dir": str(fallback.get("output_dir", "")),
            "command": list(fallback.get("command", [])),
            "returncode": int(fallback.get("returncode", 0) or 0),
            "stdout": str(fallback.get("stdout", "") or ""),
            "stderr": str(fallback.get("stderr", "") or ""),
            "screenshot_path": str(fallback.get("screenshot_path", "") or ""),
            "attempts": attempts,
        }

    return {
        "ok": False,
        "reason": "screenshot png missing",
        "attempts": attempts,
    }
