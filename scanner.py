import requests
import json
import re
import time
from typing import List, Dict, Set
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
from colorama import Fore, Style
from progress_bar import ProgressBar
from database import JobDatabase

class JobKeywordScanner:
    def __init__(self, max_workers: int = 5, db_path: str = "jobs.db"):
        self.max_workers = max_workers
        self.db = JobDatabase(db_path)
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # Thread-safe session for concurrent requests
        self.thread_local = threading.local()
        
        # Rate limiting
        self.request_times = Queue()
        self.rate_limit_delay = 0.2  # 200ms between requests (5 requests per second)
        
        # Cybersecurity-related keywords that indicate CyberCorps SFS eligible positions
        self.cyber_keywords = {
            # Core cybersecurity terms (single "cyber" catches most variations)
            'cyber', 'cybersecurity', 'cyber security', 'information security', 'infosec',
            
            # Primary cybersecurity functions
            'penetration testing', 'penetration tester', 'ethical hacker', 'red team',
            'vulnerability assessment', 'vulnerability analyst', 'vulnerability researcher',
            'security testing', 'security assessment', 'security audit',
            'threat hunting', 'threat intelligence', 'threat analyst', 'threat researcher',
            'incident response', 'incident responder', 'incident handler',
            'security operations', 'soc analyst', 'soc engineer', 'soc manager',
            'security monitoring', 'security analyst', 'security engineer',
            
            # Cybersecurity tools and technologies (primary focus)
            'siem', 'soar', 'edr', 'xdr', 'dlp', 'iam', 'pam', 'vpn',
            'firewall', 'intrusion detection', 'ids', 'ips', 'waf',
            'endpoint security', 'network security', 'cloud security',
            'application security', 'web security', 'mobile security',
            'iot security', 'industrial control systems security', 'scada security',
            
            # Cybersecurity standards and compliance (primary focus)
            'nist cybersecurity framework', 'nist 800-53', 'nist 800-171',
            'iso 27001', 'cis controls', 'mitre att&ck', 'cyber kill chain',
            'risk management', 'risk assessment', 'security governance',
            'security policy', 'security compliance', 'security awareness',
            
            # Defense/military cybersecurity (primary focus)
            'cyber warfare', 'information warfare', 'electronic warfare',
            'signals intelligence', 'communications security', 'comsec',
            'operational security', 'opsec', 'counterintelligence',
            
            # Advanced cybersecurity skills
            'reverse engineering', 'malware analysis', 'malware researcher',
            'exploit development', 'exploit researcher', 'zero-day research',
            'secure coding', 'secure development', 'devsecops',
            'code review', 'static analysis', 'dynamic analysis', 'fuzzing',
            'cryptography', 'cryptographic', 'encryption', 'key management',
            'digital forensics', 'computer forensics', 'network forensics',
            'memory forensics', 'disk forensics', 'mobile forensics'
        }
        
        # Technical skills that support cybersecurity work (secondary focus)
        self.tech_keywords = {
            # Programming languages commonly used in cybersecurity
            'python', 'powershell', 'bash', 'shell scripting', 'assembly',
            'c', 'c++', 'c#', 'java', 'javascript', 'go', 'rust',
            
            # Operating systems and platforms
            'linux', 'windows', 'unix', 'macos', 'android', 'ios',
            'embedded systems', 'real-time systems',
            
            # Networking and protocols (security-focused)
            'tcp/ip', 'udp', 'dns', 'dhcp', 'http', 'https', 'ssl', 'tls',
            'ssh', 'ftp', 'smtp', 'snmp', 'ldap', 'kerberos', 'radius',
            'routing', 'switching', 'vlan', 'subnetting', 'network protocols',
            
            # Cloud and virtualization (security-focused)
            'aws', 'azure', 'gcp', 'docker', 'kubernetes', 'virtualization',
            'vmware', 'hypervisor', 'containerization',
            
            # Databases and data (security-focused)
            'sql', 'nosql', 'database security', 'data protection',
            'data loss prevention', 'data encryption',
            
            # Security tools and frameworks
            'metasploit', 'nmap', 'wireshark', 'burp suite', 'nessus',
            'openvas', 'snort', 'suricata', 'bro', 'zeek', 'elasticsearch',
            'kibana', 'logstash', 'splunk', 'qradar', 'exabeam'
        }
        
        # Combine all keywords
        self.all_keywords = self.cyber_keywords.union(self.tech_keywords)

    def get_session(self):
        """Get thread-local session for concurrent requests"""
        if not hasattr(self.thread_local, 'session'):
            self.thread_local.session = requests.Session()
            self.thread_local.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            })
        return self.thread_local.session

    def rate_limit(self):
        """Implement rate limiting for respectful crawling"""
        current_time = time.time()
        
        # Remove old request times (older than 1 second)
        while not self.request_times.empty():
            try:
                old_time = self.request_times.get_nowait()
                if current_time - old_time < 1.0:
                    self.request_times.put(old_time)
                    break
            except:
                break
        
        # Add current request time
        self.request_times.put(current_time)
        
        # If we've made too many requests recently, wait
        if self.request_times.qsize() >= 5:  # Max 5 requests per second
            sleep_time = 1.0 - (current_time - self.request_times.get())
            if sleep_time > 0:
                time.sleep(sleep_time)

    def fetch_jobs(self, api_url: str) -> List[Dict]:
        """Fetch jobs from the API"""
        try:
            response = self.session.get(api_url, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            if data.get('success') and 'data' in data:
                jobs = data['data']
                return jobs
            else:
                return []
                
        except requests.exceptions.RequestException as e:
            return []
        except json.JSONDecodeError as e:
            return []

    def scrape_job_description(self, job_url: str) -> str:
        """Scrape the job description from a job URL"""
        try:
            # Rate limiting
            self.rate_limit()
            
            session = self.get_session()
            response = session.get(job_url, timeout=30)
            response.raise_for_status()
            
            # Extract text content focusing on the job description section
            content = response.text.lower()
            
            # Look for the job description div specifically
            job_desc_pattern = r'<div[^>]*id=["\']job-description["\'][^>]*>(.*?)</div>'
            job_desc_match = re.search(job_desc_pattern, content, re.DOTALL | re.IGNORECASE)
            
            if job_desc_match:
                # Extract only the job description content
                job_description_html = job_desc_match.group(1)
                
                # Remove HTML tags and extra whitespace from just the job description
                job_description_text = re.sub(r'<[^>]+>', ' ', job_description_html)
                job_description_text = re.sub(r'\s+', ' ', job_description_text).strip()
                
                return job_description_text
            else:
                # Fallback: if we can't find the specific div, try to find common job description patterns
                fallback_patterns = [
                    r'<div[^>]*class=["\'][^"\']*description[^"\']*["\'][^>]*>(.*?)</div>',
                    r'<div[^>]*class=["\'][^"\']*job-description[^"\']*["\'][^>]*>(.*?)</div>',
                    r'<section[^>]*class=["\'][^"\']*description[^"\']*["\'][^>]*>(.*?)</section>'
                ]
                
                for pattern in fallback_patterns:
                    fallback_match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
                    if fallback_match:
                        fallback_html = fallback_match.group(1)
                        fallback_text = re.sub(r'<[^>]+>', ' ', fallback_html)
                        fallback_text = re.sub(r'\s+', ' ', fallback_text).strip()
                        
                        return fallback_text
                
                # If all else fails, extract text from the entire page but log a warning
                return re.sub(r'<[^>]+>', ' ', content)
                return re.sub(r'\s+', ' ', content).strip()
            
        except requests.exceptions.RequestException as e:
            return ""
        except Exception as e:
            return ""

    def find_keywords_in_text(self, text: str) -> Dict[str, List[str]]:
        """Find cybersecurity keywords in the given text"""
        found_keywords = {}
        
        for keyword in self.all_keywords:
            # Use word boundaries to avoid partial matches
            pattern = r'\b' + re.escape(keyword) + r'\b'
            matches = re.findall(pattern, text, re.IGNORECASE)
            
            if matches:
                # Get context around the keyword (50 characters before and after)
                contexts = []
                for match in re.finditer(pattern, text, re.IGNORECASE):
                    start = max(0, match.start() - 50)
                    end = min(len(text), match.end() + 50)
                    context = text[start:end].strip()
                    contexts.append(context)
                
                found_keywords[keyword] = contexts
        
        return found_keywords

    def analyze_job(self, job: Dict) -> Dict:
        """Analyze a single job for cybersecurity keywords"""
        job_url = job.get('url', '')
        if not job_url:
            return {'error': 'No URL found'}
        
        # Check if job has already been analyzed
        if self.db.is_job_analyzed(job['id']):
            print(f"Skipping analysis for job ID: {job['id']} (already analyzed)")
            analyzed_job = self.db.get_analyzed_job(job['id'])
            return {
                'job_id': analyzed_job['job_id'],
                'title': analyzed_job['title'],
                'location': analyzed_job['location'],
                'department': analyzed_job['department'],
                'url': analyzed_job['url'],
                'cyber_score': analyzed_job['cyber_score'],
                'tech_score': analyzed_job['tech_score'],
                'weighted_cyber_score': analyzed_job['weighted_cyber_score'],
                'weighted_tech_score': analyzed_job['weighted_tech_score'],
                'total_score': analyzed_job['total_score'],
                'is_sfs_eligible': analyzed_job['is_sfs_eligible'],
                'found_keywords': {}, # Keywords are saved to DB, not returned here
                'description_length': analyzed_job['description_length'],
                'cached': True
            }

        # Scrape the job description
        job_description = self.scrape_job_description(job_url)
        if not job_description:
            return {'error': 'Could not scrape job description'}
        
        # Find keywords
        found_keywords = self.find_keywords_in_text(job_description)
        
        # Calculate relevance score
        cyber_score = sum(1 for keyword in found_keywords if keyword.lower() in self.cyber_keywords)
        tech_score = sum(1 for keyword in found_keywords if keyword.lower() in self.tech_keywords)
        
        # Weight cybersecurity keywords much higher for CyberCorps SFS eligibility
        # CyberCorps SFS requires positions that are primarily cybersecurity-focused
        weighted_cyber_score = cyber_score * 3  # Cybersecurity keywords are 3x more important
        weighted_tech_score = tech_score * 1    # Technical skills are supporting but not primary
        total_score = weighted_cyber_score + weighted_tech_score
        
        # Determine if this position is likely CyberCorps SFS eligible
        # Must have significant cybersecurity focus (not just some security elements)
        is_sfs_eligible = cyber_score >= 1  # Any cybersecurity keyword makes it eligible
        
        # Save analysis results to database
        self.db.save_job_analysis(job, {
            'job_id': job['id'],
            'title': job['title'],
            'url': job['url'],
            'department': job['department'],
            'location': job['location'],
            'cyber_score': cyber_score,
            'tech_score': tech_score,
            'weighted_cyber_score': weighted_cyber_score,
            'weighted_tech_score': weighted_tech_score,
            'total_score': total_score,
            'is_sfs_eligible': is_sfs_eligible,
            'found_keywords': found_keywords,
            'description_length': len(job_description)
        }, self.cyber_keywords)

        return {
            'job_id': job.get('id', ''),
            'title': job.get('title', ''),
            'location': job.get('location', ''),
            'department': job.get('department', ''),
            'url': job_url,
            'cyber_score': cyber_score,
            'tech_score': tech_score,
            'weighted_cyber_score': weighted_cyber_score,
            'weighted_tech_score': weighted_tech_score,
            'total_score': total_score,
            'is_sfs_eligible': is_sfs_eligible,
            'found_keywords': found_keywords,
            'description_length': len(job_description),
            'cached': False
        }

    def analyze_job_wrapper(self, job: Dict) -> tuple:
        """Wrapper function for concurrent execution"""
        try:
            result = self.analyze_job(job)
            return (job.get('id', ''), result)
        except Exception as e:
            return (job.get('id', ''), {'error': str(e)})

    def scan_all_jobs(self, api_url: str, include_cached: bool = False) -> List[Dict]:
        """Scan all jobs for cybersecurity keywords using multithreading"""
        jobs = self.fetch_jobs(api_url)
        if not jobs:
            return []
        
        # Check database for previously analyzed jobs
        new_jobs = []
        cached_jobs = []
        
        for job in jobs:
            if self.db.is_job_analyzed(job['id']):
                cached_jobs.append(job)
            else:
                new_jobs.append(job)
        
        print(f"Found {len(jobs)} total jobs:")
        print(f"  - {len(cached_jobs)} previously analyzed")
        print(f"  - {len(new_jobs)} new jobs to analyze")
        
        if not include_cached:
            print(f"Only analyzing {len(new_jobs)} new jobs (cached results excluded)")
        else:
            print(f"Starting concurrent analysis of {len(new_jobs)} new jobs with {self.max_workers} workers...")
        
        # Initialize progress bar for new jobs only
        progress_bar = ProgressBar(len(new_jobs), "Analyzing new jobs") if new_jobs else None
        
        results = []
        
        # Add cached results only if requested
        if include_cached:
            for job in cached_jobs:
                cached_result = self.db.get_analyzed_job(job['id'])
                if cached_result:
                    results.append({
                        'job_id': cached_result['job_id'],
                        'title': cached_result['title'],
                        'location': cached_result['location'],
                        'department': cached_result['department'],
                        'url': cached_result['url'],
                        'cyber_score': cached_result['cyber_score'],
                        'tech_score': cached_result['tech_score'],
                        'weighted_cyber_score': cached_result['weighted_cyber_score'],
                        'weighted_tech_score': cached_result['weighted_tech_score'],
                        'total_score': cached_result['total_score'],
                        'is_sfs_eligible': cached_result['is_sfs_eligible'],
                        'found_keywords': {},  # Keywords are in DB
                        'description_length': 0,
                        'cached': True
                    })
        
        # Analyze new jobs if any
        if new_jobs:
            # Use ThreadPoolExecutor for concurrent job analysis
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Submit all new jobs for analysis
                future_to_job = {
                    executor.submit(self.analyze_job_wrapper, job): job 
                    for job in new_jobs
                }
                
                # Process completed jobs as they finish
                for future in as_completed(future_to_job):
                    job = future_to_job[future]
                    try:
                        job_id, result = future.result()
                        results.append(result)
                        
                        # Update progress bar
                        if progress_bar:
                            progress_bar.update()
                        
                    except Exception as e:
                        results.append({'error': f'Processing error: {e}'})
                        if progress_bar:
                            progress_bar.update()
            
            # Finish progress bar
            if progress_bar:
                progress_bar.finish()
        else:
            print("No new jobs to analyze.")
        
        return results

    def generate_report(self, results: List[Dict]) -> str:
        """Generate a focused report highlighting only SFS eligible positions"""
        if not results:
            return "No jobs analyzed."
        
        report = []
        report.append(f"{Fore.WHITE}Analysis completed at: {Fore.CYAN}{time.strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        report.append("")
        
        # Get SFS eligible jobs
        sfs_eligible_jobs = [r for r in results if r.get('is_sfs_eligible', False)]
        
        if sfs_eligible_jobs:
            for i, result in enumerate(sfs_eligible_jobs, 1):
                # Show if job was cached
                cache_indicator = f"{Fore.YELLOW}[CACHED]{Style.RESET_ALL}" if result.get('cached', False) else ""
                report.append(f"{Fore.GREEN}{i}. {result.get('title', 'Unknown Title')}{Style.RESET_ALL} {cache_indicator}")
                report.append(f"   {Fore.WHITE}Department: {Fore.CYAN}{result.get('department', 'Unknown')}{Style.RESET_ALL}")
                report.append(f"   {Fore.WHITE}Location: {Fore.CYAN}{result.get('location', 'Unknown')}{Style.RESET_ALL}")
                report.append(f"   {Fore.CYAN}Cyber Score: {Fore.CYAN}{result.get('cyber_score', 0)} (Weighted: {result.get('weighted_cyber_score', 0)}){Style.RESET_ALL}")
                report.append(f"   {Fore.BLUE}Tech Score: {Fore.CYAN}{result.get('tech_score', 0)} (Weighted: {result.get('weighted_tech_score', 0)}){Style.RESET_ALL}")
                report.append(f"   {Fore.GREEN}Total Score: {Fore.CYAN}{result.get('total_score', 0)}{Style.RESET_ALL}")
                report.append(f"   {Fore.WHITE}URL: {Fore.CYAN}{result.get('url', 'N/A')}{Style.RESET_ALL}")
                
                # Show keywords if available (new jobs) or indicate cached
                if result.get('cached', False):
                    report.append(f"   {Fore.YELLOW}Keywords: Cached in database{Style.RESET_ALL}")
                elif result.get('found_keywords'):
                    cyber_keywords = [k for k in result['found_keywords'].keys() if k.lower() in self.cyber_keywords]
                    tech_keywords = [k for k in result['found_keywords'].keys() if k.lower() in self.tech_keywords]
                    if cyber_keywords:
                        report.append(f"   {Fore.CYAN}Cybersecurity keywords: {Fore.CYAN}{', '.join(cyber_keywords)}{Style.RESET_ALL}")
                    if tech_keywords:
                        report.append(f"   {Fore.BLUE}Technical skills: {Fore.CYAN}{', '.join(tech_keywords)}{Style.RESET_ALL}")
                
                report.append("")
        else:
            report.append(f"{Fore.YELLOW}No CyberCorps SFS eligible positions found.{Style.RESET_ALL}")
        
        return "\n".join(report)
