import sqlite3
import hashlib
from typing import List, Dict, Set

class JobDatabase:
    def __init__(self, db_path="jobs.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize the database with required tables"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Create jobs table to track analyzed positions
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    url TEXT UNIQUE NOT NULL,
                    department TEXT,
                    location TEXT,
                    cyber_score INTEGER DEFAULT 0,
                    tech_score INTEGER DEFAULT 0,
                    weighted_cyber_score INTEGER DEFAULT 0,
                    weighted_tech_score INTEGER DEFAULT 0,
                    total_score INTEGER DEFAULT 0,
                    is_sfs_eligible BOOLEAN DEFAULT FALSE,
                    description_hash TEXT,
                    last_analyzed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    analysis_count INTEGER DEFAULT 1
                )
            ''')
            
            # Create keywords table to track found keywords
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS job_keywords (
                    job_id TEXT,
                    keyword TEXT,
                    keyword_type TEXT,  -- 'cyber' or 'tech'
                    occurrences INTEGER DEFAULT 1,
                    first_found TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_found TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (job_id, keyword),
                    FOREIGN KEY (job_id) REFERENCES jobs (id)
                )
            ''')
            
            conn.commit()
    
    def get_job_hash(self, job_data: Dict) -> str:
        """Generate a hash based on job title and department to detect similar positions"""
        content = f"{job_data.get('title', '')}{job_data.get('department', '')}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def is_job_analyzed(self, job_id: str) -> bool:
        """Check if a job has been analyzed before"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM jobs WHERE id = ?', (job_id,))
            return cursor.fetchone() is not None
    
    def get_analyzed_job(self, job_id: str) -> Dict:
        """Get previously analyzed job data"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, title, url, department, location, cyber_score, tech_score,
                       weighted_cyber_score, weighted_tech_score, total_score, 
                       is_sfs_eligible, last_analyzed, analysis_count
                FROM jobs WHERE id = ?
            ''', (job_id,))
            
            row = cursor.fetchone()
            if row:
                return {
                    'job_id': row[0], 'title': row[1], 'url': row[2], 'department': row[3],
                    'location': row[4], 'cyber_score': row[5], 'tech_score': row[6],
                    'weighted_cyber_score': row[7], 'weighted_tech_score': row[8],
                    'total_score': row[9], 'is_sfs_eligible': row[10],
                    'last_analyzed': row[11], 'analysis_count': row[12]
                }
            return None
    
    def save_job_analysis(self, job_data: Dict, analysis_result: Dict, cyber_keywords: Set[str]):
        """Save job analysis results to database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Check if job exists
            cursor.execute('SELECT id FROM jobs WHERE id = ?', (job_data['id'],))
            existing_job = cursor.fetchone()
            
            if existing_job:
                # Update existing job
                cursor.execute('''
                    UPDATE jobs SET 
                        title = ?, url = ?, department = ?, location = ?,
                        cyber_score = ?, tech_score = ?, weighted_cyber_score = ?,
                        weighted_tech_score = ?, total_score = ?, is_sfs_eligible = ?,
                        last_analyzed = CURRENT_TIMESTAMP, analysis_count = analysis_count + 1
                    WHERE id = ?
                ''', (
                    job_data['title'], job_data['url'], job_data['department'], job_data['location'],
                    analysis_result['cyber_score'], analysis_result['tech_score'],
                    analysis_result['weighted_cyber_score'], analysis_result['weighted_tech_score'],
                    analysis_result['total_score'], analysis_result['is_sfs_eligible'],
                    job_data['id']
                ))
            else:
                # Insert new job
                cursor.execute('''
                    INSERT INTO jobs (
                        id, title, url, department, location, cyber_score, tech_score,
                        weighted_cyber_score, weighted_tech_score, total_score, is_sfs_eligible
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    job_data['id'], job_data['title'], job_data['url'], job_data['department'],
                    job_data['location'], analysis_result['cyber_score'], analysis_result['tech_score'],
                    analysis_result['weighted_cyber_score'], analysis_result['weighted_tech_score'],
                    analysis_result['total_score'], analysis_result['is_sfs_eligible']
                ))
            
            # Save keywords
            if analysis_result.get('found_keywords'):
                for keyword, contexts in analysis_result['found_keywords'].items():
                    keyword_type = 'cyber' if keyword.lower() in cyber_keywords else 'tech'
                    cursor.execute('''
                        INSERT OR REPLACE INTO job_keywords 
                        (job_id, keyword, keyword_type, occurrences, last_found)
                        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                    ''', (job_data['id'], keyword, keyword_type, len(contexts)))
            
            conn.commit()
    
    def get_all_analyzed_jobs(self) -> List[Dict]:
        """Get all previously analyzed jobs"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, title, url, department, location, cyber_score, tech_score,
                       weighted_cyber_score, weighted_tech_score, total_score, 
                       is_sfs_eligible, last_analyzed, analysis_count
                FROM jobs ORDER BY last_analyzed DESC
            ''')
            
            jobs = []
            for row in cursor.fetchall():
                jobs.append({
                    'job_id': row[0], 'title': row[1], 'url': row[2], 'department': row[3],
                    'location': row[4], 'cyber_score': row[5], 'tech_score': row[6],
                    'weighted_cyber_score': row[7], 'weighted_tech_score': row[8],
                    'total_score': row[9], 'is_sfs_eligible': row[10],
                    'last_analyzed': row[11], 'analysis_count': row[12]
                })
            return jobs
    
    def get_sfs_eligible_jobs(self) -> List[Dict]:
        """Get all SFS eligible jobs from database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, title, url, department, location, cyber_score, tech_score,
                       weighted_cyber_score, weighted_tech_score, total_score, 
                       last_analyzed, analysis_count
                FROM jobs WHERE is_sfs_eligible = TRUE ORDER BY total_score DESC
            ''')
            
            jobs = []
            for row in cursor.fetchall():
                jobs.append({
                    'job_id': row[0], 'title': row[1], 'url': row[2], 'department': row[3],
                    'location': row[4], 'cyber_score': row[5], 'tech_score': row[6],
                    'weighted_cyber_score': row[7], 'weighted_tech_score': row[8],
                    'total_score': row[9], 'last_analyzed': row[10], 'analysis_count': row[11]
                })
            return jobs
