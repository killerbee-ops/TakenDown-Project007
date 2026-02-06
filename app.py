from flask import Flask, request, jsonify, render_template
import re
import json
from datetime import datetime
import uuid
import sqlite3
import hashlib
import logging
import os
from functools import wraps
import secrets
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('honeypot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class AdvancedScamDetector:
    def __init__(self):
        self.scam_patterns = {
            'financial': [r'(?i)(lottery|winner|prize|jackpot)', r'(?i)(bank account|transfer money|send money)', r'(?i)(tax refund|government refund)', r'(?i)(inheritance|beneficiary)'],
            'urgency': [r'(?i)(urgent|immediate|act now|expires)', r'(?i)(limited time|hurry|quick)', r'(?i)(suspended|blocked|frozen)'],
            'verification': [r'(?i)(click here|verify account|update details)', r'(?i)(confirm identity|validate)', r'(?i)(otp|pin|password|cvv)'],
            'authority': [r'(?i)(government|official|authority)', r'(?i)(police|court|legal)', r'(?i)(irs|tax department)'],
            'crypto': [r'(?i)(bitcoin|cryptocurrency|crypto)', r'(?i)(investment|trading|profit)', r'(?i)(wallet|exchange)']
        }
        self.threat_levels = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
    
    def detect_scam(self, message):
        category_scores = {}
        total_score = 0
        
        for category, patterns in self.scam_patterns.items():
            score = sum(1 for pattern in patterns if re.search(pattern, message))
            category_scores[category] = score
            total_score += score
        
        threat_level = 'low'
        if total_score >= 4: threat_level = 'critical'
        elif total_score >= 3: threat_level = 'high' 
        elif total_score >= 2: threat_level = 'medium'
        
        return {
            'is_scam': total_score >= 2,
            'confidence': min(total_score * 25, 100),
            'threat_level': threat_level,
            'categories': category_scores,
            'total_score': total_score
        }

class AdvancedIntelligenceExtractor:
    def __init__(self):
        self.patterns = {
            'bank_accounts': r'\b\d{9,18}\b',
            'upi_ids': r'\b[\w\.-]+@[\w\.-]+\b',
            'phone_numbers': r'\b(?:\+91|91)?[6-9]\d{9}\b',
            'email_addresses': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'urls': r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
            'crypto_addresses': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\b0x[a-fA-F0-9]{40}\b',
            'ifsc_codes': r'\b[A-Z]{4}0[A-Z0-9]{6}\b',
            'pan_numbers': r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b',
            'aadhaar_numbers': r'\b\d{4}\s\d{4}\s\d{4}\b'
        }
    
    def extract(self, messages):
        text = ' '.join(messages)
        intelligence = {}
        
        for category, pattern in self.patterns.items():
            matches = list(set(re.findall(pattern, text)))
            intelligence[category] = matches
        
        # Risk assessment
        risk_score = sum(len(matches) * 10 for matches in intelligence.values())
        intelligence['risk_assessment'] = {
            'score': min(risk_score, 100),
            'level': 'critical' if risk_score > 50 else 'high' if risk_score > 25 else 'medium' if risk_score > 10 else 'low'
        }
        
        return intelligence

class AdvancedAIAgent:
    def __init__(self):
        self.personas = {
            'elderly': {
                'responses': {
                    'interest': "Oh my! This sounds wonderful. I'm not very good with technology, can you help me?",
                    'bank_query': "I use State Bank of India. Do you need my account number? I have it written down somewhere.",
                    'verification': "I'm not sure how to do this online. Can you guide me step by step?",
                    'concern': "My grandson usually helps me with these things. Should I call him?"
                }
            },
            'young_professional': {
                'responses': {
                    'interest': "Interesting! I'm always looking for good opportunities. Tell me more.",
                    'bank_query': "I have accounts with HDFC and ICICI. Which one would work better?",
                    'verification': "Sure, I can verify. What documents do you need?",
                    'concern': "Let me check this with my financial advisor first."
                }
            },
            'cautious': {
                'responses': {
                    'interest': "This seems too good to be true. How do I know this is legitimate?",
                    'bank_query': "I'm not comfortable sharing bank details. Is there another way?",
                    'verification': "Can you provide some official documentation first?",
                    'concern': "I need to verify this through official channels."
                }
            }
        }
        
        self.current_persona = 'elderly'  # Default persona
    
    def select_persona(self, scam_type):
        if 'financial' in scam_type or 'authority' in scam_type:
            self.current_persona = 'elderly'
        elif 'crypto' in scam_type:
            self.current_persona = 'young_professional'
        else:
            self.current_persona = 'cautious'
    
    def generate_response(self, message, turn_count, scam_analysis):
        message_lower = message.lower()
        persona = self.personas[self.current_persona]
        
        if turn_count == 1:
            return persona['responses']['interest']
        elif any(word in message_lower for word in ['bank', 'account', 'transfer']):
            return persona['responses']['bank_query']
        elif any(word in message_lower for word in ['verify', 'confirm', 'details']):
            return persona['responses']['verification']
        elif turn_count > 5:
            return persona['responses']['concern']
        else:
            return "I'm interested but need more information. What's the next step?"

# Database initialization
def init_db():
    conn = sqlite3.connect('honeypot.db')
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS conversations
                 (id TEXT PRIMARY KEY, start_time TEXT, end_time TEXT, 
                  scam_detected BOOLEAN, threat_level TEXT, total_turns INTEGER,
                  intelligence TEXT, ip_address TEXT, user_agent TEXT)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS messages
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, conversation_id TEXT,
                  message TEXT, response TEXT, timestamp TEXT, is_scammer BOOLEAN,
                  FOREIGN KEY (conversation_id) REFERENCES conversations (id))''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE,
                  password_hash TEXT, role TEXT, created_at TEXT)''')
    
    # Create default admin user
    admin_hash = generate_password_hash('admin123')
    c.execute('INSERT OR IGNORE INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)',
              ('admin', admin_hash, 'admin', datetime.now().isoformat()))
    
    conn.commit()
    conn.close()

# Authentication decorator
def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key or not verify_api_key(api_key):
            logger.warning(f"Unauthorized access attempt from {request.remote_addr}")
            return jsonify({'error': 'Invalid API key'}), 401
        return f(*args, **kwargs)
    return decorated_function

def verify_api_key(api_key):
    # In production, use proper API key management
    valid_keys = ['gov-api-key-2024', 'your-api-key-here']
    return api_key in valid_keys

# Global instances
detector = AdvancedScamDetector()
extractor = AdvancedIntelligenceExtractor()
agent = AdvancedAIAgent()

# Initialize database
init_db()

@app.route('/')
def home():
    return jsonify({'message': 'Government Agentic Honey-Pot System v2.0', 'status': 'running'})

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'version': '2.0.0',
        'timestamp': datetime.now().isoformat(),
        'system': 'Government Agentic Honey-Pot'
    })

@app.route('/api/message', methods=['POST'])
@require_auth
def handle_message():
    try:
        data = request.json
        message = data.get('message', '')
        conversation_id = data.get('conversation_id', str(uuid.uuid4()))
        
        # Get client info
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')
        
        # Database operations
        conn = sqlite3.connect('honeypot.db')
        c = conn.cursor()
        
        # Check if conversation exists
        c.execute('SELECT * FROM conversations WHERE id = ?', (conversation_id,))
        conv_data = c.fetchone()
        
        if not conv_data:
            # Create new conversation
            c.execute('''INSERT INTO conversations 
                        (id, start_time, scam_detected, threat_level, total_turns, ip_address, user_agent)
                        VALUES (?, ?, ?, ?, ?, ?, ?)''',
                     (conversation_id, datetime.now().isoformat(), False, 'low', 0, ip_address, user_agent))
            turn_count = 0
            scam_detected = False
        else:
            turn_count = conv_data[5] if conv_data[5] else 0
            scam_detected = bool(conv_data[2])
        
        turn_count += 1
        
        # Advanced scam detection
        scam_analysis = detector.detect_scam(message)
        if not scam_detected and scam_analysis['is_scam']:
            scam_detected = True
            agent.select_persona(max(scam_analysis['categories'], key=scam_analysis['categories'].get))
        
        # Generate AI response
        response_message = ""
        if scam_detected:
            response_message = agent.generate_response(message, turn_count, scam_analysis)
        
        # Store message
        c.execute('''INSERT INTO messages 
                    (conversation_id, message, response, timestamp, is_scammer)
                    VALUES (?, ?, ?, ?, ?)''',
                 (conversation_id, message, response_message, datetime.now().isoformat(), True))
        
        # Get all messages for intelligence extraction
        c.execute('SELECT message, response FROM messages WHERE conversation_id = ?', (conversation_id,))
        all_messages = []
        for msg_row in c.fetchall():
            all_messages.extend([msg_row[0], msg_row[1]])
        
        # Extract intelligence
        intelligence = extractor.extract(all_messages)
        
        # Update conversation
        c.execute('''UPDATE conversations SET 
                    scam_detected = ?, threat_level = ?, total_turns = ?, intelligence = ?
                    WHERE id = ?''',
                 (scam_detected, scam_analysis['threat_level'], turn_count, 
                  json.dumps(intelligence), conversation_id))
        
        conn.commit()
        conn.close()
        
        # Log the interaction
        logger.info(f"Message processed - Conv: {conversation_id}, Scam: {scam_detected}, Threat: {scam_analysis['threat_level']}")
        
        return jsonify({
            'conversation_id': conversation_id,
            'scam_detected': scam_detected,
            'scam_analysis': scam_analysis,
            'agent_response': response_message,
            'engagement_metrics': {
                'turn_count': turn_count,
                'agent_active': scam_detected,
                'threat_level': scam_analysis['threat_level'],
                'confidence': scam_analysis['confidence']
            },
            'extracted_intelligence': intelligence,
            'status': 'success'
        })
        
    except Exception as e:
        logger.error(f"Error processing message: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'version': '2.0.0',
        'timestamp': datetime.now().isoformat(),
        'system': 'Government Agentic Honey-Pot'
    })

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/stats', methods=['GET'])
@require_auth
def get_stats():
    conn = sqlite3.connect('honeypot.db')
    c = conn.cursor()
    
    # Get statistics
    c.execute('SELECT COUNT(*) FROM conversations')
    total_conversations = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM conversations WHERE scam_detected = 1')
    scam_conversations = c.fetchone()[0]
    
    c.execute('SELECT threat_level, COUNT(*) FROM conversations GROUP BY threat_level')
    threat_distribution = dict(c.fetchall())
    
    c.execute('SELECT COUNT(*) FROM messages')
    total_messages = c.fetchone()[0]
    
    conn.close()
    
    return jsonify({
        'total_conversations': total_conversations,
        'scam_conversations': scam_conversations,
        'detection_rate': (scam_conversations / max(total_conversations, 1)) * 100,
        'threat_distribution': threat_distribution,
        'total_messages': total_messages
    })

@app.route('/api/conversations', methods=['GET'])
@require_auth
def get_conversations():
    conn = sqlite3.connect('honeypot.db')
    c = conn.cursor()
    
    c.execute('''SELECT id, start_time, scam_detected, threat_level, total_turns, ip_address
                 FROM conversations ORDER BY start_time DESC LIMIT 100''')
    
    conversations = []
    for row in c.fetchall():
        conversations.append({
            'id': row[0],
            'start_time': row[1],
            'scam_detected': bool(row[2]),
            'threat_level': row[3],
            'total_turns': row[4],
            'ip_address': row[5]
        })
    
    conn.close()
    return jsonify(conversations)

if __name__ == '__main__':
    logger.info("Starting Government Agentic Honey-Pot System v2.0")
    app.run(host='0.0.0.0', port=5000, debug=False)