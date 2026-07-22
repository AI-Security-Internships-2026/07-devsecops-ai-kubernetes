"""
DevSecOps AI Pipeline with Kubernetes Security Scanning
CNIT/PNTLab Pisa — AI Security Internship 2026

Starter entry point. Replace this file with your actual implementation.
"""

import sys


PROJECT_NAME = "DevSecOps AI Pipeline with Kubernetes Security Scanning"
ORGANISATION = "CNIT/PNTLab Pisa, TECIP, Scuola Superiore Sant'Anna"
STATUS = "Initialised — ready for development"


def main() -> None:
    print("=" * 60)
    print(f"Project : {PROJECT_NAME}")
    print(f"Org     : {ORGANISATION}")
    print(f"Status  : {STATUS}")
    print("=" * 60)
    print()
    print("Use the unified CLI (from the repo root):")
    print("  python run.py scan <image>       # Trivy scan")
    print("  python run.py enrich <trivy.json># add EPSS scores")
    print("  python run.py triage <epss.json> # SSVC + LLM triage report")
    print("  python run.py pipeline <image>   # scan -> enrich -> triage")
    print("  python run.py --help             # all commands")


if __name__ == "__main__":
    main()
