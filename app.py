from flask import Flask, render_template, request, redirect, url_for
import sqlite3, json
from detector import analyze_url

app = Flask(__name__)
DB = 'history.db'
BRANDS = ['paypal.com','google.com','facebook.com','microsoft.com']

def init_db():
    with sqlite3.connect(DB) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY,
                url TEXT,
                result TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )   
        ''')

@app.route('/', methods=['GET','POST'])
def index():
    if request.method=='POST':
        url = request.form['url']
        res = analyze_url(url, BRANDS)
        with sqlite3.connect(DB) as conn:
            conn.execute('INSERT INTO history (url, result) VALUES (?, ?)', (url, json.dumps(res)))
        return redirect(url_for('results', url=url))
    return render_template('index.html')

@app.route('/results')
def results():
    url = request.args.get('url')
    with sqlite3.connect(DB) as conn:
        row = conn.execute('SELECT result FROM history WHERE url=? ORDER BY id DESC LIMIT 1', (url,)).fetchone()
    result = json.loads(row[0])
    return render_template('results.html', r=result)

@app.route('/history')
def history():
    with sqlite3.connect(DB) as conn:
        rows = conn.execute(
            'SELECT url, result, timestamp FROM history ORDER BY id DESC'
        ).fetchall()

    history_data = []
    for url, res_json, ts in rows:
        data = json.loads(res_json)    
        data['url']       = url       
        data['timestamp'] = ts
        history_data.append(data)

    clean  = sum(not d['is_phishing'] for d in history_data)
    phish  = sum(    d['is_phishing'] for d in history_data)
    graph  = { 'labels': ['Legítimas','Phishing'], 'values': [clean, phish] }

    return render_template(
        'history.html',
        history=history_data,
        graph=json.dumps(graph)
    )


if __name__=='__main__':
    init_db()
    app.run(debug=True)
