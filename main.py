import time
import sys
from colorama import init, Fore, Style
from scanner import JobKeywordScanner
from database import JobDatabase

# Initialize colorama for cross-platform colored output
init(autoreset=True)

def main():
    """Main function to run the job keyword scanner"""
    
    # Check for command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == "--db-stats":
            # Show database statistics
            db = JobDatabase()
            all_jobs = db.get_all_analyzed_jobs()
            sfs_jobs = db.get_sfs_eligible_jobs()
            
            print(f"{Fore.MAGENTA}{Style.BRIGHT}DATABASE STATISTICS{Style.RESET_ALL}")
            print(f"{Fore.WHITE}Total jobs in database: {Fore.CYAN}{len(all_jobs)}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}SFS eligible jobs: {Fore.CYAN}{len(sfs_jobs)}{Style.RESET_ALL}")
            print(f"{Fore.WHITE}Database file: {Fore.CYAN}jobs.db{Style.RESET_ALL}")
            print()
            
            if sfs_jobs:
                print(f"{Fore.GREEN}{Style.BRIGHT}SFS ELIGIBLE JOBS IN DATABASE:{Style.RESET_ALL}")
                for i, job in enumerate(sfs_jobs[:10], 1):  # Show top 10
                    print(f"{i}. {job['title']} ({job['department']}) - Score: {job['total_score']}")
                if len(sfs_jobs) > 10:
                    print(f"... and {len(sfs_jobs) - 10} more")
            return
        elif sys.argv[1] == "--include-cached":
            include_cached = True
        elif sys.argv[1] == "--help":
            print(f"{Fore.MAGENTA}{Style.BRIGHT}CYBERCORPS SFS JOB SCANNER - HELP{Style.RESET_ALL}")
            print()
            print("Available commands:")
            print(f"  {Fore.CYAN}python main.py{Style.RESET_ALL}              : Analyze only new jobs (default)")
            print(f"  {Fore.CYAN}python main.py --include-cached{Style.RESET_ALL} : Analyze new jobs + include cached results")
            print(f"  {Fore.CYAN}python main.py --db-stats{Style.RESET_ALL}      : Show database statistics")
            print(f"  {Fore.CYAN}python main.py --help{Style.RESET_ALL}          : Show this help message")
            return
        else:
            print(f"Unknown option: {sys.argv[1]}")
            print("Available options:")
            print("  --db-stats        : Show database statistics")
            print("  --include-cached  : Include cached results in analysis")
            print("  --help            : Show help message")
            return
    else:
        include_cached = False
    
    api_url = "https://www.sdl.usu.edu/dev/api/jobs"
    
    # Configure number of concurrent workers (adjust based on your system and rate limits)
    max_workers = 5  # 5 concurrent workers, 5 requests per second = 25 requests per second total
    
    scanner = JobKeywordScanner(max_workers=max_workers)
    
    print(f"{Fore.MAGENTA}{Style.BRIGHT}Starting concurrent CyberCorps SFS job analysis...{Style.RESET_ALL}")
    print(f"{Fore.WHITE}API URL: {Fore.CYAN}{api_url}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}Concurrent workers: {Fore.CYAN}{max_workers}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Cybersecurity keywords: {Fore.CYAN}{len(scanner.cyber_keywords)}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}Technical skills: {Fore.CYAN}{len(scanner.tech_keywords)}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Note: Cybersecurity keywords are weighted 3x higher for SFS eligibility{Style.RESET_ALL}")
    print(f"{Fore.WHITE}Database: {Fore.CYAN}jobs.db{Style.RESET_ALL} (caches results to avoid re-analysis)")
    print()
    
    # Scan all jobs
    start_time = time.time()
    print("🔄 Fetching and analyzing jobs...")
    results = scanner.scan_all_jobs(api_url, include_cached=include_cached)
    end_time = time.time()
    
    if results:
        # Generate and display report
        report = scanner.generate_report(results)
        print(report)
    else:
        print("No jobs were analyzed. Check the logs for errors.")

if __name__ == "__main__":
    main()
