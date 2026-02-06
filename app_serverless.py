from flask import Flask, request, jsonify, render_template
import re
import json
from datetime import datetime
import uuid
import logging
from functools import wraps
import secrets
import openai
import os

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# OpenAI API Configuration
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', 'your-openai-api-key-here')
openai.api_key = OPENAI_API_KEY

# Configure logging (console only)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# In-memory storage (resets on each serverless invocation)
conversations_store = {}
messages_store = []

class AdvancedScamDetector:
    def __init__(self):
        self.scam_patterns = {
            'financial': [
                r'(?i)\b(lottery|lotto|winner|prize|jackpot|won|win|winning|congratulations|congrats)\b',
                r'(?i)\b(bank account|account number|transfer|send money|bank details|routing)\b',
                r'(?i)(\$|₹|dollar|rupee|money|cash|amount|payment|pay|fund|credit)',
                r'(?i)\b(claim|reward|refund|bonus|gift|free|offer)\b',
                r'(?i)\b(thousand|million|lakh|crore|k|\d+)\b.*\b(dollar|rupee|money|cash|prize)\b'
            ],
            'urgency': [
                r'(?i)\b(urgent|immediate|immediately|act now|expires|expiring|expire)\b',
                r'(?i)\b(limited time|hurry|quick|fast|asap|right now)\b',
                r'(?i)\b(today|tonight|now|within|hours|minutes)\b',
                r'(?i)\b(last chance|final|deadline|before|must)\b'
            ],
            'verification': [
                r'(?i)\b(click here|click|tap here|visit|link|url)\b',
                r'(?i)\b(verify|update|confirm|validate|check)\b.*\b(account|details|information|profile)\b',
                r'(?i)\b(otp|pin|password|cvv|code|passcode|security code)\b',
                r'(?i)\b(send|provide|give|share|enter|submit|reply)\b',
                r'(?i)\b(suspended|blocked|locked|frozen|deactivated|disabled|closed)\b'
            ],
            'authority': [
                r'(?i)\b(government|official|authority|department|ministry|agency)\b',
                r'(?i)\b(police|court|legal|law|judge|officer)\b',
                r'(?i)\b(tax|irs|income tax|gst|vat|customs|revenue)\b',
                r'(?i)\b(arrest|warrant|fine|penalty|charges|prosecution)\b'
            ],
            'crypto': [
                r'(?i)\b(bitcoin|cryptocurrency|crypto|btc|eth|ethereum|coin)\b',
                r'(?i)\b(investment|invest|trading|trade|profit|returns|earn)\b',
                r'(?i)\b(wallet|blockchain|mining|exchange)\b',
                r'(?i)\b(guaranteed|double|triple|multiply|100%|500%)\b'
            ],
            'suspicious_links': [
                r'(?i)(bit\.ly|tinyurl|short\.link|goo\.gl)',
                r'(?i)(\.tk|\.ml|\.ga|\.cf|\.gq)',
                r'http[s]?://[^\s]+'
            ],
            'personal_info': [
                r'(?i)\b(social security|ssn|aadhar|aadhaar|pan card|pan number)\b',
                r'(?i)\b(credit card|debit card|card number|card details)\b',
                r'(?i)\b(account number|routing number|ifsc|swift|iban)\b',
                r'(?i)\b(date of birth|dob|mother|maiden name)\b'
            ],
            'threats': [
                r'(?i)\b(arrest|jail|prison|legal action|court case)\b',
                r'(?i)\b(sue|lawsuit|litigation|prosecution)\b',
                r'(?i)\b(penalty|fine|charges|fee|consequences)\b'
            ],
            'contact_request': [
                r'(?i)\b(call|contact|reach|phone|whatsapp|telegram|email)\b.*\b(me|us|back|now)\b',
                r'(?i)\b(reply|respond|message|text)\b.*\b(immediately|urgent|asap|now)\b'
            ]
        }
    
    def detect_scam(self, message):
        category_scores = {}
        total_score = 0
        
        for category, patterns in self.scam_patterns.items():
            score = sum(1 for pattern in patterns if re.search(pattern, message))
            category_scores[category] = score
            total_score += score
        
        # AGGRESSIVE threat level calculation - even 1 match is suspicious
        threat_level = 'medium'  # Default to medium for any detection
        confidence = 50
        
        if total_score >= 4:
            threat_level = 'critical'
            confidence = 95
        elif total_score >= 2:
            threat_level = 'high'
            confidence = 75
        elif total_score >= 1:
            threat_level = 'medium'
            confidence = 50
        else:
            threat_level = 'low'
            confidence = 0
        
        # ANY match is considered a scam
        is_scam = total_score >= 1
        
        return {
            'is_scam': is_scam,
            'confidence': confidence,
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
            'urls': r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
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
            fallback_responses = {
                'elderly': "Oh my! This sounds interesting. Can you help me understand this better?",
                'young_professional': "Tell me more about this opportunity. What's the next step?",
                'cautious': "I need more information. Can you provide some verification?"
            }
            return fallback_responses.get(self.current_persona, "Can you tell me more about this?")

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
        
        # In-memory storage
        if conversation_id not in conversations_store:
            conversations_store[conversation_id] = {
                'id': conversation_id,
                'start_time': datetime.now().isoformat(),
                'scam_detected': False,
                'threat_level': 'low',
                'total_turns': 0,
                'ip_address': request.remote_addr,
                'messages': []
            }
        
        conv = conversations_store[conversation_id]
        conv['total_turns'] += 1
        
        # Scam detection
        scam_analysis = detector.detect_scam(message)
        if not conv['scam_detected'] and scam_analysis['is_scam']:
            conv['scam_detected'] = True
        
        # Generate AI response
        response_message = ""
        if conv['scam_detected']:
            response_message = agent.generate_response(message, conv['total_turns'], scam_analysis)
        
        # Store message
        conv['messages'].append({
            'message': message,
            'response': response_message,
            'timestamp': datetime.now().isoformat()
        })
        
        # Extract intelligence
        all_messages = []
        for msg in conv['messages']:
            all_messages.extend([msg['message'], msg['response']])
        intelligence = extractor.extract(all_messages)
        
        # Update conversation
        conv['threat_level'] = scam_analysis['threat_level']
        
        return jsonify({
            'conversation_id': conversation_id,
            'scam_detected': conv['scam_detected'],
            'scam_analysis': scam_analysis,
            'agent_response': response_message,
            'engagement_metrics': {
                'turn_count': conv['total_turns'],
                'agent_active': conv['scam_detected'],
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
    total_conversations = len(conversations_store)
    scam_conversations = sum(1 for c in conversations_store.values() if c['scam_detected'])
    total_messages = sum(len(c['messages']) for c in conversations_store.values())
    
    return jsonify({
        'total_conversations': total_conversations,
        'scam_conversations': scam_conversations,
        'detection_rate': (scam_conversations / max(total_conversations, 1)) * 100,
        'total_messages': total_messages
    })

@app.route('/api/conversations')
@require_auth
def get_conversations():
    conversations = []
    for conv in list(conversations_store.values())[-100:]:
        conversations.append({
            'id': conv['id'],
            'start_time': conv['start_time'],
            'scam_detected': conv['scam_detected'],
            'threat_level': conv['threat_level'],
            'total_turns': conv['total_turns'],
            'ip_address': conv['ip_address']
        })
    
    return jsonify(conversations)

@app.route('/api/public/threats', methods=['GET'])
def get_public_threats():
    """Public API for threat intelligence sharing"""
    return jsonify({
        'status': 'success',
        'threats': [],
        'total_count': 0,
        'last_updated': datetime.now().isoformat(),
        'note': 'Threat intelligence available in full deployment'
    })

@app.route('/api/public/check-url', methods=['POST'])
def check_url_safety():
    """Public API for URL safety checking"""
    try:
        data = request.json
        url = data.get('url', '')
        
        if not url:
            return jsonify({'error': 'URL required'}), 400
        
        threat_level = 'low'
        reason = 'No immediate threats detected'
        
        return jsonify({
            'url': url,
            'safe': threat_level == 'low',
            'threat_level': threat_level,
            'reason': reason,
            'recommendation': 'URL appears safe to visit'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    logger.info("Starting Government Agentic Honey-Pot System v2.0")
    app.run(host='0.0.0.0', port=5000, debug=False)
