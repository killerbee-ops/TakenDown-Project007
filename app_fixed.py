from flask import Flask, request, jsonify, render_template
import re
import json
from datetime import datetime
import uuid
import sqlite3
import logging
from functools import wraps
import secrets
from werkzeug.security import generate_password_hash
import openai
import os

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# OpenAI API Configuration
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', 'your-openai-api-key-here')
openai.api_key = OPENAI_API_KEY

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AdvancedScamDetector:
    def __init__(self):
        self.scam_patterns = {
            'financial': [r'(?i)(lottery|winner|prize|jackpot|won|win)', r'(?i)(bank account|transfer money|send money|bank details)', r'(?i)(\$|dollar|money|cash|amount)'],
            'urgency': [r'(?i)(urgent|immediate|act now|expires)', r'(?i)(limited time|hurry|quick)', r'(?i)(now|today|immediately)'],
            'verification': [r'(?i)(click here|verify account|update details)', r'(?i)(otp|pin|password|cvv)', r'(?i)(send|provide|give us)'],
            'authority': [r'(?i)(government|official|authority)', r'(?i)(police|court|legal)'],
            'crypto': [r'(?i)(bitcoin|cryptocurrency|crypto)', r'(?i)(investment|trading|profit)']
        }
    
    def detect_scam(self, message):
        category_scores = {}
        total_score = 0
        
        for category, patterns in self.scam_patterns.items():
            score = sum(1 for pattern in patterns if re.search(pattern, message))
            category_scores[category] = score
            total_score += score
        
        threat_level = 'low'
        if total_score >= 3: threat_level = 'critical'
        elif total_score >= 2: threat_level = 'high' 
        elif total_score >= 1: threat_level = 'medium'
        
        return {
            'is_scam': total_score >= 1,
            'confidence': min(total_score * 30, 100),
            'threat_level': threat_level,
            'categories': category_scores,
            'total_score': total_score
        }

class AdvancedIntelligenceExtractor:
    def __init__(self):
        self.patterns = {
            'bank_accounts': r'\\b\\d{9,18}\\b',
            'upi_ids': r'\\b[\\w\\.-]+@[\\w\\.-]+\\b',
            'phone_numbers': r'\\b(?:\\+91|91)?[6-9]\\d{9}\\b',
            'email_addresses': r'\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b',
            'urls': r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\\\(\\\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        }
    
    def extract(self, messages):
        text = ' '.join(messages)
        intelligence = {}
        
        for category, pattern in self.patterns.items():
            matches = list(set(re.findall(pattern, text)))
            intelligence[category] = matches
        
        return intelligence

class AdvancedAIAgent:
    def __init__(self):
        self.personas = {
            'elderly': "You are an elderly person who is not tech-savvy and easily trusting. Respond naturally and ask for help with technology.",
            'young_professional': "You are a young professional interested in opportunities but somewhat cautious. Ask relevant questions.",
            'cautious': "You are very cautious and skeptical. Question everything and ask for verification."
        }
        self.current_persona = 'elderly'
    
    def select_persona(self, scam_type):
        if 'financial' in scam_type or 'authority' in scam_type:
            self.current_persona = 'elderly'
        elif 'crypto' in scam_type:
            self.current_persona = 'young_professional'
        else:
            self.current_persona = 'cautious'
    
    def generate_response(self, message, turn_count, scam_analysis):
        try:
            persona_prompt = self.personas[self.current_persona]
            
            prompt = f"""{persona_prompt}
            
Scammer message: "{message}"
Turn number: {turn_count}
Threat level: {scam_analysis['threat_level']}

Respond as this persona would, keeping the conversation going to extract more information. Be natural and believable. Keep response under 50 words."""
            
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are an AI agent in a government honey-pot system designed to engage scammers and extract intelligence. Stay in character."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=100,
                temperature=0.7
            )
            
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            logger.error(f"OpenAI API error: {str(e)}")
            # Fallback responses
            fallback_responses = {
                'elderly': "Oh my! This sounds interesting. Can you help me understand this better?",
                'young_professional': "Tell me more about this opportunity. What's the next step?",
                'cautious': "I need more information. Can you provide some verification?"
            }
            return fallback_responses.get(self.current_persona, "Can you tell me more about this?")

# Initialize database
def init_db():
    conn = sqlite3.connect('honeypot.db')
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS conversations
                 (id TEXT PRIMARY KEY, start_time TEXT, scam_detected BOOLEAN, 
                  threat_level TEXT, total_turns INTEGER, intelligence TEXT, ip_address TEXT)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS messages
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, conversation_id TEXT,
                  message TEXT, response TEXT, timestamp TEXT, is_scammer BOOLEAN)''')
    
    conn.commit()
    conn.close()

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key or api_key not in ['gov-api-key-2024', 'your-api-key-here']:
            return jsonify({'error': 'Invalid API key'}), 401
        return f(*args, **kwargs)
    return decorated_function

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

@app.route('/analytics')
def analytics():
    return render_template('analytics.html')

@app.route('/reports')
def reports():
    return render_template('reports.html')

@app.route('/settings')
def settings():
    return render_template('settings.html')

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
        
        # Database operations
        conn = sqlite3.connect('honeypot.db')
        c = conn.cursor()
        
        # Check if conversation exists
        c.execute('SELECT total_turns, scam_detected FROM conversations WHERE id = ?', (conversation_id,))
        conv_data = c.fetchone()
        
        if not conv_data:
            turn_count = 0
            scam_detected = False
            c.execute('''INSERT INTO conversations 
                        (id, start_time, scam_detected, threat_level, total_turns, ip_address)
                        VALUES (?, ?, ?, ?, ?, ?)''',
                     (conversation_id, datetime.now().isoformat(), False, 'low', 0, request.remote_addr))
        else:
            turn_count = conv_data[0] if conv_data[0] else 0
            scam_detected = bool(conv_data[1])
        
        turn_count += 1
        
        # Scam detection
        scam_analysis = detector.detect_scam(message)
        if not scam_detected and scam_analysis['is_scam']:
            scam_detected = True
        
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

@app.route('/api/stats')
@require_auth
def get_stats():
    conn = sqlite3.connect('honeypot.db')
    c = conn.cursor()
    
    c.execute('SELECT COUNT(*) FROM conversations')
    total_conversations = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM conversations WHERE scam_detected = 1')
    scam_conversations = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM messages')
    total_messages = c.fetchone()[0]
    
    conn.close()
    
    return jsonify({
        'total_conversations': total_conversations,
        'scam_conversations': scam_conversations,
        'detection_rate': (scam_conversations / max(total_conversations, 1)) * 100,
        'total_messages': total_messages
    })

@app.route('/api/conversations')
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

# Public API endpoints for threat intelligence sharing
@app.route('/api/public/threats', methods=['GET'])
def get_public_threats():
    """Public API for threat intelligence sharing with other organizations"""
    try:
        conn = sqlite3.connect('threat_intelligence.db')
        c = conn.cursor()
        
        # Get recent high-confidence threats
        c.execute('''SELECT indicator_type, value, threat_level, description, last_seen 
                     FROM threat_indicators 
                     WHERE confidence > 0.8 AND threat_level IN ('high', 'critical')
                     ORDER BY last_seen DESC LIMIT 100''')
        
        threats = []
        for row in c.fetchall():
            threats.append({
                'type': row[0],
                'indicator': row[1],
                'threat_level': row[2],
                'description': row[3],
                'last_seen': row[4]
            })
        
        conn.close()
        
        return jsonify({
            'status': 'success',
            'threats': threats,
            'total_count': len(threats),
            'last_updated': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/public/check-url', methods=['POST'])
def check_url_safety():
    """Public API for URL safety checking"""
    try:
        data = request.json
        url = data.get('url', '')
        
        if not url:
            return jsonify({'error': 'URL required'}), 400
        
        # Basic URL analysis
        threat_level = 'low'
        reason = 'No immediate threats detected'
        
        return jsonify({
            'url': url,
            'safe': threat_level == 'low',
            'threat_level': threat_level,
            'reason': reason,
            'recommendation': get_safety_recommendation(threat_level)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def get_safety_recommendation(threat_level):
    recommendations = {
        'low': 'URL appears safe to visit',
        'medium': 'Exercise caution - verify the website authenticity',
        'high': 'High risk - avoid visiting this URL',
        'critical': 'DANGER - This is a known malicious URL. Do not visit!',
        'unknown': 'Unable to determine safety - proceed with extreme caution'
    }
    return recommendations.get(threat_level, 'Unknown risk level')

if __name__ == '__main__':
    logger.info("Starting Government Agentic Honey-Pot System v2.0")
    app.run(host='0.0.0.0', port=5000, debug=False)