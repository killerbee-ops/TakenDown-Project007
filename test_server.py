from flask import Flask, render_template, jsonify

app = Flask(__name__)

@app.route('/')
def home():
    return jsonify({'message': 'Government Honey-Pot System', 'status': 'running'})

@app.route('/health')
def health():
    return jsonify({'status': 'healthy'})

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

if __name__ == '__main__':
    print("Starting simple test server...")
    app.run(host='0.0.0.0', port=5001, debug=True)