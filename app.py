import os
import threading
import asyncio
from flask import Flask, render_template, request, Response, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone, timedelta
from scanner_engine import recursive_crawler, scan_url
import io
import csv

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))

# --- DB Config ---
app.config['SECRET_KEY'] = 'your-super-secret-key-change-it-later'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'scanner.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- Global dictionary to store scan progress ---
scan_statuses = {}

# --- DB Models ---
class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(500), nullable=False)
    scan_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.String(50), nullable=False, default='Queued...')
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy=True)

class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    vuln_type = db.Column(db.String(100), nullable=False)
    payload = db.Column(db.Text, nullable=False)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)

# --- Background Scan Task ---
def run_full_scan_sync(app_context, target_url, scan_id):
    """This function runs in a background thread."""
    with app_context:
        # We need to run the async functions inside a new event loop for the thread
        asyncio.run(run_full_scan_async(target_url, scan_id))

async def run_full_scan_async(target_url, scan_id):
    import aiohttp
    global scan_statuses
    
    async with aiohttp.ClientSession() as session:
        scan_statuses[scan_id] = {'status': 'Crawling target...', 'progress': 10}
        links_to_scan = await recursive_crawler(session, target_url)
        
        scan_statuses[scan_id] = {'status': f'Found {len(links_to_scan)} links. Starting vulnerability scan...', 'progress': 30}
        
        scan_tasks = [scan_url(session, link) for link in links_to_scan]
        list_of_results = await asyncio.gather(*scan_tasks)
        
        all_vulnerabilities = [item for sublist in list_of_results for item in sublist]

        scan_statuses[scan_id] = {'status': 'Saving results to database...', 'progress': 90}
        
        with app.app_context():
            scan_to_update = Scan.query.get(scan_id)
            if all_vulnerabilities:
                for vuln in all_vulnerabilities:
                    db.session.add(Vulnerability(
                        url=vuln['url'], vuln_type=vuln['vuln_type'],
                        payload=vuln['payload'], scan_id=scan_id
                    ))
            
            scan_to_update.status = 'Completed'
            db.session.commit()
            print(f"[+] Scan {scan_id} Completed. Saved {len(all_vulnerabilities)} vulnerabilities.")

    # Remove the scan from the status tracker
    if scan_id in scan_statuses:
        del scan_statuses[scan_id]

# --- Flask Routes ---
@app.route('/', methods=['GET', 'POST'])
def dashboard():
    if request.method == 'POST':
        target_url = request.form['target_url'].strip()
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        
        new_scan = Scan(target_url=target_url)
        db.session.add(new_scan)
        db.session.commit()
        
        # Start the scan in a background thread
        scan_thread = threading.Thread(
            target=run_full_scan_sync,
            args=(app.app_context(), target_url, new_scan.id)
        )
        scan_thread.daemon = True
        scan_thread.start()
        
        # Immediately return the new scan_id to the browser
        return jsonify({'scan_id': new_scan.id})

    all_scans = Scan.query.order_by(Scan.scan_date.desc()).all()
    return render_template('dashboard.html', scans=all_scans)

@app.route('/scan_status/<int:scan_id>')
def scan_status(scan_id):
    """This route is called by the JavaScript to get progress updates."""
    global scan_statuses
    status = scan_statuses.get(scan_id, {'status': 'Waiting for scan to start...', 'progress': 0})
    
    # Check the database as a fallback if the job is done
    if scan_id not in scan_statuses:
        scan = Scan.query.get(scan_id)
        if scan and scan.status == 'Completed':
            status = {'status': 'Completed', 'progress': 100}
            
    return jsonify(status)

# --- Other Routes and Filters ---
@app.template_filter('to_ist')
def to_ist(utc_dt):
    if utc_dt is None: return ""
    ist_tz = timezone(timedelta(hours=5, minutes=30))
    ist_dt = utc_dt.replace(tzinfo=timezone.utc).astimezone(ist_tz)
    return ist_dt.strftime('%Y-%m-%d %I:%M %p')

@app.route('/scan/<int:scan_id>')
def scan_details(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    return render_template('scan_details.html', scan=scan)

@app.route('/export/<int:scan_id>')
def export_csv(scan_id):
    string_io = io.StringIO()
    csv_writer = csv.writer(string_io)
    scan = Scan.query.get_or_404(scan_id)
    csv_writer.writerow(['Vulnerability Type', 'Vulnerable URL', 'Payload'])
    for vuln in scan.vulnerabilities:
        csv_writer.writerow([vuln.vuln_type, vuln.url, vuln.payload])
    output = string_io.getvalue()
    return Response(output, mimetype="text/csv", headers={"Content-disposition": f"attachment; filename=scan_results_{scan_id}.csv"})

if __name__ == '__main__':
    if os.name == 'nt':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    app.run(debug=True)