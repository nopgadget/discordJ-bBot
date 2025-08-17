# CyberCorps SFS Job Scanner

A Python-based tool that automatically scans job postings from the Space Dynamics Laboratory API to identify positions eligible for CyberCorps Scholarship for Service (SFS) funding. The tool uses advanced keyword analysis, multithreading for performance, and a SQLite database to avoid re-analyzing previously scanned positions.

## 🎯 CyberCorps SFS Focus

This tool is specifically designed to identify positions that would qualify for **CyberCorps SFS** funding, which requires positions to be primarily cybersecurity-focused. The scoring system is tailored to SFS eligibility requirements:

- **Primary Focus**: Cybersecurity-specific roles and responsibilities
- **Keyword Weighting**: Cybersecurity keywords are weighted 3x higher than technical skills
- **Eligibility Threshold**: Any position with at least 1 cybersecurity keyword is marked as SFS eligible
- **Clear Identification**: Results clearly show which positions meet SFS criteria

### Smart Keyword Strategy

The tool uses "cyber" as a single, powerful keyword that catches most cybersecurity-related variations, making the search more efficient and inclusive while maintaining accuracy.

## 🏗️ Project Structure

The project is organized into modular, maintainable components:

```
discordJ-bBot/
├── main.py              # Main entry point and CLI interface
├── scanner.py           # Core job analysis and scanning logic
├── database.py          # SQLite database operations and management
├── progress_bar.py      # Visual progress indicator
├── requirements.txt     # Python dependencies
└── README.md           # This file
```

### Module Responsibilities

- **`main.py`**: Command-line interface, argument parsing, and program orchestration
- **`scanner.py`**: Job fetching, web scraping, keyword analysis, and multithreading
- **`database.py`**: SQLite database operations, job caching, and result storage
- **`progress_bar.py`**: Visual progress tracking during analysis

## ✨ Features

- **🎯 CyberCorps SFS Focus**: Specifically designed for SFS eligibility assessment
- **🚀 Multithreading**: Concurrent job analysis for significant performance improvements
- **💾 Smart Caching**: SQLite database prevents re-analysis of previously scanned positions
- **🔍 Targeted Scraping**: Focuses on job description content, not entire HTML pages
- **📊 Weighted Scoring**: Cybersecurity keywords weighted 3x higher than technical skills
- **🎨 Colorized Output**: Cross-platform colored terminal output for easy reading
- **📈 Progress Tracking**: Visual progress bar during analysis
- **⚡ Rate Limiting**: Respectful crawling with configurable request limits
- **🔧 Thread-Safe**: Proper session management for concurrent requests

## 🚀 Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd discordJ-bBot
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the scanner**:
   ```bash
   python main.py
   ```

## 📖 Usage

### Basic Usage

```bash
# Analyze only new jobs (default behavior)
python main.py

# Include previously analyzed jobs in results
python main.py --include-cached

# Show database statistics
python main.py --db-stats

# Show help
python main.py --help
```

### Command Options

- **`python main.py`**: Analyzes only new jobs, excludes cached results
- **`python main.py --include-cached`**: Analyzes new jobs + includes cached results
- **`python main.py --db-stats`**: Shows database statistics and cached SFS eligible positions
- **`python main.py --help`**: Displays available commands and options

## 📊 Output

The tool provides a clean, focused output showing only CyberCorps SFS eligible positions:

```
Analysis completed at: 2025-01-27 14:30:25

1. Cybersecurity Analyst [CACHED]
   Department: Strategic Military Space
   Location: North Logan, UT
   Cyber Score: 5 (Weighted: 15)
   Tech Score: 3 (Weighted: 3)
   Total Score: 18
   URL: https://spacedynamicslaboratory.applytojob.com/apply/...
   Keywords: Cached in database

2. Cyber Defense Engineer
   Department: Strategic Military Space
   Location: Colorado Springs, CO
   Cyber Score: 4 (Weighted: 12)
   Tech Score: 2 (Weighted: 2)
   Total Score: 14
   URL: https://spacedynamicslaboratory.applytojob.com/apply/...
   Cybersecurity keywords: cyber, cybersecurity, security
   Technical skills: python, linux, networking
```

## 🎨 Color Scheme

The output uses a consistent color scheme for easy reading:

- **🟢 Green**: Job titles and total scores
- **🔵 Blue**: Technical skills and tech scores
- **🟣 Magenta**: Headers and section titles
- **🟡 Yellow**: Cached indicators and warnings
- **⚪ White**: Labels and general information
- **🔵 Cyan**: Values and URLs

## 🗄️ Database Features

The SQLite database (`jobs.db`) provides:

- **Job Tracking**: All analyzed positions with scores and eligibility
- **Keyword Storage**: Found cybersecurity and technical keywords
- **Duplicate Prevention**: Avoids re-analyzing the same jobs
- **Cache System**: Instant access to previously analyzed results
- **Analysis History**: Tracks when jobs were analyzed and how many times

## ⚙️ Configuration

### Concurrency Settings

```python
# In main.py - adjust based on your system and rate limits
max_workers = 5  # 5 concurrent workers
rate_limit_delay = 0.2  # 200ms between requests (5 requests per second)
```

### Rate Limiting

The tool implements respectful crawling:
- **Maximum**: 5 requests per second per worker
- **Total**: Up to 25 requests per second across all workers
- **Configurable**: Adjust `rate_limit_delay` in the scanner

## 🔧 Technical Details

### Multithreading Implementation

- **ThreadPoolExecutor**: Manages concurrent job analysis
- **Thread-Local Sessions**: Each thread has its own `requests.Session`
- **Queue-Based Rate Limiting**: Ensures respectful crawling across threads
- **Progress Tracking**: Real-time progress updates during analysis

### Web Scraping Strategy

- **Targeted Extraction**: Focuses on `<div id="job-description">` elements
- **Fallback Patterns**: Multiple HTML patterns for job description extraction
- **HTML Cleaning**: Removes tags and normalizes whitespace
- **Error Handling**: Graceful fallbacks for various HTML structures

### Scoring Algorithm

```python
# Cybersecurity keywords are 3x more important for SFS eligibility
weighted_cyber_score = cyber_score * 3
weighted_tech_score = tech_score * 1
total_score = weighted_cyber_score + weighted_tech_score

# SFS eligibility: any cybersecurity keyword makes it eligible
is_sfs_eligible = cyber_score >= 1
```

## 🎯 CyberCorps SFS Keywords

### Primary Cybersecurity Keywords

The tool searches for comprehensive cybersecurity terms including:

- **Core Terms**: cyber, cybersecurity, information security, infosec
- **Functions**: penetration testing, threat hunting, incident response, SOC operations
- **Technologies**: SIEM, EDR, firewall, intrusion detection, VPN
- **Standards**: NIST frameworks, ISO 27001, MITRE ATT&CK, CIS controls
- **Military/Defense**: cyber warfare, signals intelligence, operational security
- **Advanced Skills**: malware analysis, reverse engineering, digital forensics

### Supporting Technical Skills

Technical skills that support cybersecurity work:

- **Programming**: Python, PowerShell, Bash, C/C++, Assembly
- **Platforms**: Linux, Windows, embedded systems
- **Networking**: TCP/IP, protocols, routing, switching
- **Cloud**: AWS, Azure, Docker, Kubernetes
- **Tools**: Metasploit, Nmap, Wireshark, Burp Suite

## 📈 Performance

### Speed Improvements

- **Sequential Processing**: ~1 job per second
- **Multithreaded (5 workers)**: ~5 jobs per second
- **Speed Improvement**: Approximately 5x faster than sequential processing
- **Database Caching**: Subsequent runs are nearly instant for cached jobs

### Resource Usage

- **Memory**: Minimal memory footprint per thread
- **CPU**: Efficient concurrent processing
- **Network**: Respectful rate limiting prevents server overload
- **Storage**: SQLite database with minimal disk usage

## 🚨 Ethical Considerations

- **Rate Limiting**: Respectful crawling with configurable delays
- **User-Agent**: Proper identification in HTTP headers
- **Error Handling**: Graceful handling of network issues
- **Resource Management**: Efficient use of system resources

## 📋 Requirements

- **Python**: 3.7 or higher
- **Dependencies**: See `requirements.txt`
- **Database**: SQLite3 (built into Python)
- **Network**: Internet connection for API access

## 📄 License

This project is provided as-is for educational and research purposes.

## ⚠️ Disclaimer

This tool is designed for legitimate job research and CyberCorps SFS eligibility assessment. Users are responsible for complying with website terms of service and applicable laws. The tool implements respectful crawling practices and should not be used for aggressive scraping or any malicious purposes.
