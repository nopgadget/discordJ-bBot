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
            'security policy', 'security compliance', 'security awareness', 'pci dss',
            
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

    def fetch_icims_jobs(self, icims_url: str) -> List[Dict]:
        """Fetch jobs from iCIMS careers page by extracting jobImpressions JSON"""
        try:
            # Try different URL variations and headers
            urls_to_try = [
                icims_url,
                icims_url.replace('&in_iframe=1', ''),
                icims_url.replace('in_iframe=1&', ''),
                icims_url.replace('&in_iframe=1', '') + '&mobile=false',
                'https://careers-usu.icims.com/jobs/search?searchCategory=8730&ss=1',
                'https://careers-usu.icims.com/jobs/search?searchCategory=8730&ss=1&mobile=false'
            ]
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            }
            
            content = ""
            best_content = ""
            best_url = ""
            
            for url in urls_to_try:
                try:
                    response = self.session.get(url, headers=headers, timeout=30)
                    response.raise_for_status()
                    current_content = response.text
                    
                    # Check if this content contains job-related data
                    if 'jobImpressions' in current_content:
                        content = current_content
                        break
                    elif 'var ' in current_content and '[' in current_content and len(current_content) > len(best_content):
                        # This might contain job data, keep it as backup
                        best_content = current_content
                        best_url = url
                    
                except Exception as e:
                    continue
            
            # If we didn't find jobImpressions, use the best content we found
            if not content and best_content:
                content = best_content
            
            if not content:
                return []
            
            # Debug: Check if we got the expected content
            match = None
            if 'jobImpressions' in content:
                # Found jobImpressions, will process below
                pass
            else:
                # Look for other potential job data patterns
                if 'var ' in content and '[' in content:
                    # Try to find any array that might contain job data
                    array_patterns = [
                        r'var\s+(\w+)\s*=\s*(\[.*?\]);',
                        r'(\w+)\s*=\s*(\[.*?\]);'
                    ]
                    for pattern in array_patterns:
                        matches = re.findall(pattern, content, re.DOTALL)
                        for var_name, var_content in matches:
                            if len(var_content) > 100:  # Likely job data if it's a long array
                                # Try to parse it as JSON
                                try:
                                    test_data = json.loads(var_content)
                                    if isinstance(test_data, list) and len(test_data) > 0:
                                        first_item = test_data[0]
                                        if isinstance(first_item, dict) and 'title' in first_item:
                                            # Use this data instead
                                            match = (var_name, var_content)
                                            break
                                except Exception as e:
                                    continue
                
                # Also look for job data in different formats
                if not match:
                    # Look for job listings in HTML format
                    job_listing_patterns = [
                        r'<div[^>]*class=["\'][^"\']*job-listing[^"\']*["\'][^>]*>(.*?)</div>',
                        r'<div[^>]*class=["\'][^"\']*job-item[^"\']*["\'][^>]*>(.*?)</div>',
                        r'<div[^>]*class=["\'][^"\']*job[^"\']*["\'][^>]*>(.*?)</div>',
                        r'<li[^>]*class=["\'][^"\']*job[^"\']*["\'][^>]*>(.*?)</li>'
                    ]
                    
                    for pattern in job_listing_patterns:
                        job_matches = re.findall(pattern, content, re.DOTALL | re.IGNORECASE)
                        if job_matches:
                            # Try to extract job information from HTML
                            extracted_jobs = []
                            for job_html in job_matches:
                                # Extract job title
                                title_match = re.search(r'<h[1-6][^>]*>(.*?)</h[1-6]>', job_html, re.DOTALL | re.IGNORECASE)
                                title = title_match.group(1).strip() if title_match else "Unknown Title"
                                
                                # Extract job URL
                                url_match = re.search(r'href=["\']([^"\']+)["\']', job_html)
                                job_url = url_match.group(1) if url_match else ""
                                
                                # Extract location
                                location_match = re.search(r'<span[^>]*class=["\'][^"\']*location[^"\']*["\'][^>]*>(.*?)</span>', job_html, re.DOTALL | re.IGNORECASE)
                                location = location_match.group(1).strip() if location_match else "Unknown"
                                
                                # Extract department/category
                                dept_match = re.search(r'<span[^>]*class=["\'][^"\']*category[^"\']*["\'][^>]*>(.*?)</span>', job_html, re.DOTALL | re.IGNORECASE)
                                department = dept_match.group(1).strip() if dept_match else "Unknown Department"
                                
                                if title and title != "Unknown Title":
                                    extracted_jobs.append({
                                        'id': f"icims_{len(extracted_jobs)}",
                                        'title': title,
                                        'department': department,
                                        'location': location,
                                        'url': job_url if job_url.startswith('http') else f"https://careers-usu.icims.com{job_url}",
                                        'company': 'Utah State University',
                                        'position_type': 'Unknown',
                                        'posted_date': 'Unknown',
                                        'icims_id': f"icims_{len(extracted_jobs)}",
                                        'source': 'icims'
                                    })
                            
                            if extracted_jobs:
                                return extracted_jobs
                
                if not match:
                    # Look for specific job titles that might be mentioned
                    potential_titles = re.findall(r'<h[1-6][^>]*>(.*?)</h[1-6]>', content, re.DOTALL | re.IGNORECASE)
                    if potential_titles:
                        # Try to extract jobs from the headings we found
                        extracted_jobs = []
                        for title in potential_titles:
                            title = title.strip()
                            # Skip non-job headings
                            if (title and 
                                title != "Career Opportunities" and 
                                title != "Search Results" and
                                title != "Page 1 of 1" and
                                len(title) > 10 and  # Likely a job title if it's long enough
                                not title.startswith('\n')):
                                
                                # Look for the job URL near this heading
                                # Find the position of this heading in the content
                                heading_pos = content.find(title)
                                if heading_pos != -1:
                                    # Look for a link near this heading (within 500 characters)
                                    nearby_content = content[max(0, heading_pos-250):heading_pos+500]
                                    url_match = re.search(r'href=["\']([^"\']+)["\']', nearby_content)
                                    job_url = url_match.group(1) if url_match else ""
                                    
                                    # Look for location information near the heading
                                    location_match = re.search(r'<span[^>]*class=["\'][^"\']*location[^"\']*["\'][^>]*>(.*?)</span>', nearby_content, re.DOTALL | re.IGNORECASE)
                                    location = location_match.group(1).strip() if location_match else "Logan, UT"  # Default location
                                    
                                    # Look for department/category information
                                    dept_match = re.search(r'<span[^>]*class=["\'][^"\']*category[^"\']*["\'][^>]*>(.*?)</span>', nearby_content, re.DOTALL | re.IGNORECASE)
                                    department = dept_match.group(1).strip() if dept_match else "Information Technology"  # Default department
                                    
                                    # Create the job object
                                    job_id = f"icims_{len(extracted_jobs)}"
                                    if not job_url.startswith('http'):
                                        job_url = f"https://careers-usu.icims.com{job_url}" if job_url else ""
                                    
                                    extracted_jobs.append({
                                        'id': job_id,
                                        'title': title,
                                        'department': department,
                                        'location': location,
                                        'url': job_url,
                                        'company': 'Utah State University',
                                        'position_type': 'Unknown',
                                        'posted_date': 'Unknown',
                                        'icims_id': job_id,
                                        'source': 'icims'
                                    })
                        
                        if extracted_jobs:
                            return extracted_jobs
            
            # Extract the jobImpressions JSON data
            # Pattern: var jobImpressions = [...];
            if not match:
                patterns = [
                    r'var\s+jobImpressions\s*=\s*(\[.*?\]);',
                    r'jobImpressions\s*=\s*(\[.*?\]);',
                    r'var\s+jobImpressions\s*=\s*(\[.*?\]);',
                    r'window\.jobImpressions\s*=\s*(\[.*?\]);'
                ]
                
                for pattern in patterns:
                    match = re.search(pattern, content, re.DOTALL)
                    if match:
                        break
            
            if match:
                try:
                    # Parse the JSON data
                    if isinstance(match, tuple):
                        # New format: (var_name, var_content)
                        var_name, jobs_json = match
                    else:
                        # Original format: regex match object
                        jobs_json = match.group(1)
                    
                    jobs_data = json.loads(jobs_json)
                    
                    # Convert iCIMS format to our standard format
                    converted_jobs = []
                    for job in jobs_data:
                        # Extract location information
                        location_parts = []
                        if job.get('location', {}).get('city'):
                            location_parts.append(job['location']['city'])
                        if job.get('location', {}).get('state'):
                            location_parts.append(job['location']['state'])
                        if job.get('location', {}).get('zip'):
                            location_parts.append(job['location']['zip'])
                        
                        location = ', '.join(location_parts) if location_parts else 'Unknown'
                        
                        # Create job URL from the iCIMS ID
                        base_url = "https://careers-usu.icims.com/jobs"
                        job_url = f"{base_url}/{job.get('idRaw', '')}/job"
                        
                        converted_job = {
                            'id': str(job.get('idRaw', job.get('id', ''))),
                            'title': job.get('title', 'Unknown Title'),
                            'department': job.get('category', 'Unknown Department'),
                            'location': location,
                            'url': job_url,
                            'company': job.get('company', 'Unknown Company'),
                            'position_type': job.get('positionType', 'Unknown'),
                            'posted_date': job.get('postedDate', 'Unknown'),
                            'icims_id': job.get('id', ''),
                            'source': 'icims'
                        }
                        converted_jobs.append(converted_job)
                    
                    return converted_jobs
                    
                except json.JSONDecodeError as e:
                    return []
            else:
                return []
                
        except requests.exceptions.RequestException as e:
            return []
        except Exception as e:
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
            
        except requests.exceptions.RequestException as e:
            return ""
        except Exception as e:
            return ""

    def scrape_icims_job_description(self, job_url: str) -> str:
        """Scrape the job description from an iCIMS job URL with iCIMS-specific patterns"""
        try:
            # Rate limiting
            self.rate_limit()
            
            session = self.get_session()
            response = session.get(job_url, timeout=30)
            response.raise_for_status()
            
            # Extract text content focusing on the job description section
            content = response.text.lower()
            
            # iCIMS-specific job description patterns
            icims_patterns = [
                # Look for the main job description content
                r'<div[^>]*class=["\'][^"\']*iCIMS_JobDescription[^"\']*["\'][^>]*>(.*?)</div>',
                r'<div[^>]*class=["\'][^"\']*job-description[^"\']*["\'][^>]*>(.*?)</div>',
                r'<div[^>]*class=["\'][^"\']*description[^"\']*["\'][^>]*>(.*?)</div>',
                # Look for content in the main job content area
                r'<div[^>]*class=["\'][^"\']*iCIMS_JobContent[^"\']*["\'][^>]*>(.*?)</div>',
                # Look for the job overview section
                r'<div[^>]*class=["\'][^"\']*iCIMS_JobOverview[^"\']*["\'][^>]*>(.*?)</div>',
                # Look for any div with "job" and "content" in the class
                r'<div[^>]*class=["\'][^"\']*[^"\']*job[^"\']*[^"\']*content[^"\']*["\'][^>]*>(.*?)</div>'
            ]
            
            for pattern in icims_patterns:
                match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
                if match:
                    # Extract the job description content
                    job_description_html = match.group(1)
                    
                    # Remove HTML tags and extra whitespace
                    job_description_text = re.sub(r'<[^>]+>', ' ', job_description_html)
                    job_description_text = re.sub(r'\s+', ' ', job_description_text).strip()
                    
                    if len(job_description_text) > 50:  # Ensure we got meaningful content
                        return job_description_text
            
            # If no specific patterns found, try to extract from the main content area
            # Look for content between the job title and the end of the job details
            main_content_pattern = r'<div[^>]*class=["\'][^"\']*iCIMS_JobContent[^"\']*["\'][^>]*>(.*?)</div>'
            main_match = re.search(main_content_pattern, content, re.DOTALL | re.IGNORECASE)
            
            if main_match:
                main_content_html = main_match.group(1)
                main_content_text = re.sub(r'<[^>]+>', ' ', main_content_html)
                main_content_text = re.sub(r'\s+', ' ', main_content_text).strip()
                
                if len(main_content_text) > 50:
                    return main_content_text
            
            # Final fallback: extract text from the entire page
            return re.sub(r'<[^>]+>', ' ', content)
            
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

        # Scrape the job description based on source
        if job.get('source') == 'icims':
            job_description = self.scrape_icims_job_description(job_url)
        else:
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
        
        print(f"Found {Fore.CYAN}{len(jobs)}{Style.RESET_ALL} total jobs:")
        print(f"  - {Fore.CYAN}{len(cached_jobs)}{Style.RESET_ALL} previously analyzed")
        print(f"  - {Fore.CYAN}{len(new_jobs)}{Style.RESET_ALL} new jobs to analyze")
        
        if not include_cached:
            print(f"Only analyzing {Fore.CYAN}{len(new_jobs)}{Style.RESET_ALL} new jobs (cached results excluded)")
        else:
            print(f"Starting concurrent analysis of {Fore.CYAN}{len(new_jobs)}{Style.RESET_ALL} new jobs with {Fore.CYAN}{self.max_workers}{Style.RESET_ALL} workers...")
        
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
                        'cached': True,
                        'source': 'api'  # Add source to identify USU API jobs
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
            if include_cached:
                print("No new jobs to analyze, returning cached results.")
            else:
                print("No new jobs to analyze.")
        
        return results

    def scan_icims_jobs(self, icims_url: str, include_cached: bool = False) -> List[Dict]:
        """Scan jobs from iCIMS careers page for cybersecurity keywords"""
        jobs = self.fetch_icims_jobs(icims_url)
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
        
        print(f"Found {Fore.CYAN}{len(jobs)}{Style.RESET_ALL} total iCIMS jobs:")
        print(f"  - {Fore.CYAN}{len(cached_jobs)}{Style.RESET_ALL} previously analyzed")
        print(f"  - {Fore.CYAN}{len(new_jobs)}{Style.RESET_ALL} new jobs to analyze")
        
        if not include_cached:
            print(f"Only analyzing {Fore.CYAN}{len(new_jobs)}{Style.RESET_ALL} new iCIMS jobs (cached results excluded)")
        else:
            print(f"Starting concurrent analysis of {Fore.CYAN}{len(new_jobs)}{Style.RESET_ALL} new iCIMS jobs with {Fore.CYAN}{self.max_workers}{Style.RESET_ALL} workers...")
        
        # Initialize progress bar for new jobs only
        progress_bar = ProgressBar(len(new_jobs), "Analyzing new iCIMS jobs") if new_jobs else None
        
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
                        'cached': True,
                        'source': 'icims'  # Add source to identify iCIMS jobs
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
            if include_cached:
                print("No new iCIMS jobs to analyze, returning cached results.")
            else:
                print("No new iCIMS jobs to analyze.")
        
        return results

    def scan_both_sources(self, api_url: str, icims_url: str, include_cached: bool = False) -> List[Dict]:
        """Scan jobs from both USU API and iCIMS careers page"""
        print("🔄 Scanning jobs from both sources...")
        
        # Scan API jobs
        print(f"{Fore.WHITE}Scanning USU API jobs...{Style.RESET_ALL}")
        api_results = self.scan_all_jobs(api_url, include_cached=include_cached)
        
        # Scan iCIMS jobs
        print(f"{Fore.WHITE}Scanning iCIMS careers page...{Style.RESET_ALL}")
        icims_results = self.scan_icims_jobs(icims_url, include_cached=include_cached)
        
        # Combine results
        all_results = api_results + icims_results
        
        print(f"{Fore.GREEN}Combined results: {Fore.CYAN}{len(all_results)}{Style.RESET_ALL}{Fore.GREEN} total jobs{Style.RESET_ALL}")
        print(f"  - USU API: {Fore.CYAN}{len(api_results)}{Style.RESET_ALL} jobs")
        print(f"  - iCIMS: {Fore.CYAN}{len(icims_results)}{Style.RESET_ALL} jobs")
        
        # If we have results, generate a report
        if all_results:
            print(f"\n{Fore.GREEN}Generating combined report...{Style.RESET_ALL}")
            report = self.generate_report(all_results)
            print(report)
        
        return all_results

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
