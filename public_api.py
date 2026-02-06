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

@app.route('/api/public/warnings', methods=['GET'])
def get_public_warnings():
    """Public API for active scam warnings"""
    try:
        conn = sqlite3.connect('public_warnings.db')
        c = conn.cursor()
        
        # Get active warnings
        c.execute('''SELECT warning_type, title, description, severity, published_at 
                     FROM public_warnings 
                     WHERE status = 'active' AND expires_at > ?
                     ORDER BY published_at DESC''', (datetime.now().isoformat(),))
        
        warnings = []
        for row in c.fetchall():
            warnings.append({
                'type': row[0],
                'title': row[1],
                'description': row[2],
                'severity': row[3],
                'published_at': row[4]
            })
        
        conn.close()
        
        return jsonify({
            'status': 'success',
            'warnings': warnings,
            'total_count': len(warnings)
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
        
        # Analyze URL through threat intelligence
        analysis = protection_system.threat_intel.analyze_url(url)
        
        return jsonify({
            'url': url,
            'safe': analysis['threat_level'] == 'low',
            'threat_level': analysis['threat_level'],
            'reason': analysis['reason'],
            'recommendation': get_safety_recommendation(analysis['threat_level'])
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

@app.route('/api/report-scam', methods=['POST'])
def report_scam():
    """Public API for reporting scam attempts"""
    try:
        data = request.json
        
        # Store scam report
        conn = sqlite3.connect('public_warnings.db')
        c = conn.cursor()
        
        c.execute('''INSERT INTO scam_reports 
                     (report_source, scam_type, description, indicators, reported_at, verified)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                 ('public_api', data.get('scam_type', 'unknown'), 
                  data.get('description', ''), json.dumps(data.get('indicators', {})),
                  datetime.now().isoformat(), False))
        
        report_id = c.lastrowid
        conn.commit()
        conn.close()
        
        # Process through protection system if high confidence
        if data.get('confidence', 0) > 0.7:
            protection_system.process_scam_interaction({
                'scam_type': data.get('scam_type'),
                'source_ip': request.remote_addr,
                'description': data.get('description'),
                'urls': data.get('indicators', {}).get('urls', []),
                'phone_numbers': data.get('indicators', {}).get('phone_numbers', [])
            })
        
        return jsonify({
            'status': 'success',
            'report_id': report_id,
            'message': 'Scam report received and being processed'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500