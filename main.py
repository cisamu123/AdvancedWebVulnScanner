'''
       ^ Author    : Cisamu
       ^ Name      : AdvancedWebVulnScanner
       ^ Github    : https://github.com/cisamu123
'''
import asyncio
from scanner import AdvancedVulnScanner
from cli import parse_args

def main():
    args = parse_args()
    scanner = AdvancedVulnScanner(args.target_url, args.report_file, args.user_agent, args.proxies)
    asyncio.run(scanner.run())

if __name__ == "__main__":
    main()
