import os
import asyncio
import aiohttp
from flask import Flask, render_template, request, Response
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

# --- DB Models ---
class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(500), nullable=False)
    scan_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False, default='Scanning...')
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy=True)

class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    vuln_type = db.Column(db.String(100), nullable=False)
    payload = db.Column(db.Text, nullable=False)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)

# --- Main Asynchronous Scan Task ---
async def run_full_scan(target_url, scan_id):
    print("="*50)
    print(f"[*] Starting Async Scan for {target_url} (ID: {scan_id})")
    
    async with aiohttp.ClientSession() as session:
        print(f"[*] Crawling target...")
        links_to_scan = await recursive_crawler(session, target_url)
        print(f"[+] Crawler found {len(links_to_scan)} links.")
        
        print(f"[*] Launching all vulnerability scans concurrently...")
        scan_tasks = [scan_url(session, link) for link in links_to_scan]
        list_of_results = await asyncio.gather(*scan_tasks)
        
        # Flatten the list of lists into a single list of vulnerabilities
        all_vulnerabilities = [item for sublist in list_of_results for item in sublist]

        # --- Database operations must be done in a sync context ---
        with app.app_context():
            if all_vulnerabilities:
                for vuln in all_vulnerabilities:
                    db.session.add(Vulnerability(
                        url=vuln['url'],
                        vuln_type=vuln['vuln_type'],
                        payload=vuln['payload'],
                        scan_id=scan_id
                    ))
                db.session.commit()
                print(f"[+] Saved {len(all_vulnerabilities)} vulnerabilities to the database.")
            else:
                print("[-] No vulnerabilities found.")
    
    print(f"[*] Async Scan finished.")
    print("="*50)

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
        
        # Run the entire async scan process
        asyncio.run(run_full_scan(target_url, new_scan.id))

    all_scans = Scan.query.order_by(Scan.scan_date.desc()).all()
    return render_template('dashboard.html', scans=all_scans)

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
    # On Windows, the default event loop policy needs to be changed for aiohttp
    # to work correctly with Flask's reloader in debug mode.
    if os.name == 'nt':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    app.run(debug=True)