from phishing_detector import PhishingDetector
from url_analyzer import URLAnalyzer
import re
from datetime import datetime

class EmailProcessor:
    def __init__(self):
        self.phishing_detector = PhishingDetector()
        self.url_analyzer = URLAnalyzer()
    
    def process_email(self, email_data):
        """Process an email through all detection mechanisms"""
        processed_email = {
            'id': email_data.get('id', ''),
            'subject': email_data.get('subject', ''),
            'sender': email_data.get('sender', ''),
            'date': email_data.get('date', ''),
            'content': email_data.get('content', ''),
            'snippet': email_data.get('snippet', ''),
            'labels': email_data.get('labels', [])
        }
        
        risk_score = self.phishing_detector.calculate_risk_score(email_data)
        processed_email['risk_score'] = risk_score
        processed_email['risk_level'] = self.phishing_detector.get_risk_level(risk_score)
        
        threats = self.phishing_detector.detect_threats(email_data)
        processed_email['threats'] = threats
        
        url_analysis = self.url_analyzer.analyze_email_urls(email_data.get('content', ''))
        processed_email['url_analysis'] = url_analysis
        processed_email['suspicious_urls'] = [url['url'] for url in url_analysis['suspicious_urls']]
        
        processed_email['sender_analysis'] = self._analyze_sender(email_data.get('sender', ''))
        processed_email['content_analysis'] = self._analyze_content(email_data.get('content', ''))
        processed_email['subject_analysis'] = self._analyze_subject(email_data.get('subject', ''))
        
        processed_email['summary'] = self._generate_summary(processed_email)
        
        return processed_email
    
    def _analyze_sender(self, sender):
        """Analyze the sender for suspicious characteristics"""
        analysis = {
            'is_suspicious': False,
            'indicators': [],
            'domain_reputation': 'unknown'
        }
        
        if not sender:
            return analysis
        
        sender_lower = sender.lower()
        
        if '<' in sender and '>' in sender:
            display_name = sender.split('<')[0].strip()
            email_address = sender.split('<')[1].split('>')[0].strip()
            
            legitimate_services = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook']
            for service in legitimate_services:
                if service in display_name.lower() and service not in email_address:
                    analysis['is_suspicious'] = True
                    analysis['indicators'].append(f"Display name suggests {service} but email domain doesn't match")
        
        if '@' in sender_lower:
            domain = sender_lower.split('@')[-1]
            
            suspicious_patterns = [
                r'.*-verify\..*',
                r'.*-security\..*',
                r'.*-support\..*',
                r'.*\.tk$',
                r'.*\.ml$',
                r'.*\.ga$'
            ]
            
            for pattern in suspicious_patterns:
                if re.match(pattern, domain):
                    analysis['is_suspicious'] = True
                    analysis['indicators'].append(f"Suspicious domain pattern: {domain}")
        
        if any(char in sender_lower for char in ['0', '1', '3', '4', '5', '7', '9']):
            analysis['indicators'].append("Contains numbers that might substitute letters")
        
        return analysis
    
    def _analyze_content(self, content):
        """Analyze email content for suspicious patterns"""
        analysis = {
            'word_count': 0,
            'suspicious_patterns': [],
            'urgency_indicators': 0,
            'social_engineering_score': 0.0
        }
        
        if not content:
            return analysis
        
        content_lower = content.lower()
        words = content_lower.split()
        analysis['word_count'] = len(words)
        
        urgency_words = ['urgent', 'immediate', 'asap', 'expire', 'deadline', 'final notice']
        analysis['urgency_indicators'] = sum(1 for word in urgency_words if word in content_lower)
        
        social_patterns = [
            r'click here',
            r'verify.*account',
            r'update.*information',
            r'confirm.*identity',
            r'suspended.*account',
            r'unusual.*activity',
            r'security.*alert'
        ]
        
        social_score = 0
        for pattern in social_patterns:
            if re.search(pattern, content_lower):
                social_score += 1
                analysis['suspicious_patterns'].append(f"Social engineering pattern: {pattern}")
        
        analysis['social_engineering_score'] = min(1.0, social_score / len(social_patterns))
        
        financial_patterns = [
            r'\$[\d,]+',
            r'refund',
            r'payment',
            r'invoice',
            r'billing',
            r'tax.*return',
            r'owe.*money'
        ]
        
        for pattern in financial_patterns:
            if re.search(pattern, content_lower):
                analysis['suspicious_patterns'].append(f"Financial indicator: {pattern}")
        
        return analysis
    
    def _analyze_subject(self, subject):
        """Analyze email subject for suspicious characteristics"""
        analysis = {
            'is_suspicious': False,
            'indicators': [],
            'caps_ratio': 0.0,
            'exclamation_count': 0
        }
        
        if not subject:
            return analysis
        
        if len(subject) > 0:
            caps_count = sum(1 for c in subject if c.isupper())
            analysis['caps_ratio'] = caps_count / len(subject)
        
        analysis['exclamation_count'] = subject.count('!')
        
        if analysis['caps_ratio'] > 0.5:
            analysis['is_suspicious'] = True
            analysis['indicators'].append("Excessive use of capital letters")
        
        if analysis['exclamation_count'] > 2:
            analysis['is_suspicious'] = True
            analysis['indicators'].append("Excessive use of exclamation marks")
        
        phishing_patterns = [
            r'urgent.*action',
            r'verify.*account',
            r'suspended.*account',
            r'security.*alert',
            r'congratulations.*won',
            r'final.*notice',
            r'act.*now'
        ]
        
        subject_lower = subject.lower()
        for pattern in phishing_patterns:
            if re.search(pattern, subject_lower):
                analysis['is_suspicious'] = True
                analysis['indicators'].append(f"Phishing subject pattern: {pattern}")
        
        return analysis
    
    def _generate_summary(self, processed_email):
        """Generate a human-readable summary of the email analysis"""
        risk_level = processed_email['risk_level']
        risk_score = processed_email['risk_score']
        threats = processed_email['threats']
        
        if risk_level == 'High':
            summary = f"🔴 HIGH RISK EMAIL (Score: {risk_score:.2f}) - This email shows multiple indicators of being a phishing attempt."
        elif risk_level == 'Medium':
            summary = f"🟡 MEDIUM RISK EMAIL (Score: {risk_score:.2f}) - This email has some suspicious characteristics that warrant caution."
        else:
            summary = f"🟢 LOW RISK EMAIL (Score: {risk_score:.2f}) - This email appears to be legitimate with minimal risk indicators."
        
        if threats:
            summary += f" Key concerns: {', '.join(threats[:3])}"
            if len(threats) > 3:
                summary += f" and {len(threats) - 3} more..."
        
        return summary
    
    def batch_process_emails(self, emails):
        """Process multiple emails in batch"""
        processed_emails = []
        
        for email in emails:
            try:
                processed_email = self.process_email(email)
                processed_emails.append(processed_email)
            except Exception as e:
                print(f"Error processing email {email.get('id', 'unknown')}: {str(e)}")
                continue
        
        return processed_emails
