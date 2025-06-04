import argparse
import asyncio
from colorama import init
from scanner.core import VulnerabilityScanner


def main():
    parser = argparse.ArgumentParser(description="Simple web vulnerability scanner")
    parser.add_argument('targets', nargs='+', help='Target URLs to scan')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--report', default='report.md', help='Output markdown report')
    args = parser.parse_args()

    init(autoreset=True)
    scanner = VulnerabilityScanner(args.targets, proxy=args.proxy)
    asyncio.run(scanner.run())
    report = scanner.generate_report()
    with open(args.report, 'w') as f:
        f.write(report)
    print(f"Report saved to {args.report}")


if __name__ == '__main__':
    main()
