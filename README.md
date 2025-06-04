# Web Vulnerability Scanner

This repository contains a simple asynchronous web vulnerability scanner aimed at CTF and Hack The Box style environments.

## Features

- Scans for common vulnerabilities:
  - SQL Injection (GET parameters)
  - Reflected XSS
  - Command Injection
  - Directory Traversal
  - Local File Inclusion
  - Remote File Inclusion
- Asynchronous requests for speed
- Colorized CLI output
- Basic login form authentication helper
- Generates a Markdown report summarizing findings

## Usage

```bash
pip install -r requirements.txt
python -m scanner.cli http://target/test.php?test=1
```

Use `--proxy` to route traffic through a proxy (e.g., Burp Suite) and `--report` to set the output file.

```bash
python -m scanner.cli --proxy http://127.0.0.1:8080 --report result.md http://target/
```

## Disclaimer

Use this tool only against systems you have explicit permission to test.
