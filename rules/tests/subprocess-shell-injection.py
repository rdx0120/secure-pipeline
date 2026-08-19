import subprocess
import os


def scan_shell(path):
    # ruleid: subprocess-shell-injection
    subprocess.run(f"trivy fs {path}", shell=True)


def scan_popen(path):
    # ruleid: subprocess-shell-injection
    subprocess.Popen("gitleaks detect --source " + path, shell=True)


def scan_system(path):
    # ruleid: subprocess-shell-injection
    os.system("bandit -r " + path)


def scan_fstring_no_shell(path):
    # ruleid: subprocess-shell-injection
    subprocess.check_output(f"semgrep --config auto {path}")


# --- must NOT fire: argument vector, shell=False -----------------------------

def scan_argv(path):
    # ok: subprocess-shell-injection
    subprocess.run(["trivy", "fs", "--format", "sarif", path], check=False)


def scan_argv_capture(path):
    # ok: subprocess-shell-injection
    subprocess.run(["bandit", "-r", path], capture_output=True, text=True, check=False)
