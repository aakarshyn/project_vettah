import pandas as pd
import pdfplumber
import io
import re
import requests
import json
import os
import base64
import tempfile
from fpdf import FPDF
from textblob import TextBlob
from datetime import datetime

# --- DATABASES & KEYS ---
LOCAL_CCTNS_DB = {}  
LOCAL_CDR_DB = {}    
LOCAL_IPDR_DB = {}   

TELECOM_API_URL = "https://internal-telecom-gateway.keralapolice.gov.in/api/v1"
CCTNS_API_URL = "https://cctns-node.keralapolice.gov.in/api/v1/suspect/search"

TELECOM_API_KEY = "YOUR_TSP_KEY_HERE"
CCTNS_API_KEY = "YOUR_CCTNS_KEY_HERE"

TRON_API_KEY = "f39cdc52-3422-4b2e-8080-36ad7a8b8324"
ETHERSCAN_API_KEY = "C5A58IJ5UEYS5T3MEJ4NP51Z1CRHV9VFWP"

def verify_credentials(u, p):
    return u == "admin" and p == "cyberdome2026"

def safe_extract_date(val_str):
    match = re.search(r'\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{1,2}[/-][a-zA-Z]{3}[/-]\d{2,4}|\d{1,2}\.\d{1,2}\.\d{2,4}', str(val_str).strip())
    return match.group(0) if match else "N/A"

def safe_extract_amount(val_str):
    s = str(val_str).upper().replace(',', '').replace('₹', '').replace('INR', '').replace('DR', '').replace('CR', '').strip()
    matches = re.findall(r'\d+(?:\.\d+)?', s)
    if matches:
        valid = [m for m in matches if len(m.split('.')[0]) < 9]
        if valid: return valid[-1]
    return "0.00"

def explode_multiline_rows(df):
    return df

# ---------------------------------------------------------
# PERSISTENT EVIDENCE LOCKER
# ---------------------------------------------------------
LOCKER_FILE = "evidence_locker.json"

def load_locker():
    if os.path.exists(LOCKER_FILE):
        with open(LOCKER_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_locker(data):
    with open(LOCKER_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def add_to_locker(officer_id, item_type, title, content, **kwargs):
    locker = load_locker()
    if officer_id not in locker: locker[officer_id] = []
    
    for item in locker[officer_id]:
        if item['title'] == title and item['type'] == item_type:
            return False 
            
    new_item = {
        "id": str(datetime.now().timestamp()),
        "type": item_type,
        "title": title,
        "content": content,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    new_item.update(kwargs) 
    locker[officer_id].append(new_item)
    save_locker(locker)
    return True

def update_locker_item(officer_id, item_id, **kwargs):
    locker = load_locker()
    if officer_id in locker:
        for item in locker[officer_id]:
            if item['id'] == item_id:
                item.update(kwargs)
                save_locker(locker)
                return True
    return False

def delete_locker_item(officer_id, item_id):
    locker = load_locker()
    if officer_id in locker:
        original_len = len(locker[officer_id])
        locker[officer_id] = [item for item in locker[officer_id] if item['id'] != item_id]
        if len(locker[officer_id]) < original_len:
            save_locker(locker)
            return True
    return False

# ---------------------------------------------------------
# STATIC GRAPH SNAPSHOT ENGINE (STRICT FLOWCHART OVERRIDE)
# ---------------------------------------------------------
def get_static_network_b64(graph_links, hub_aliases, node_labels):
    import networkx as nx
    import plotly.graph_objects as go
    
    G = nx.DiGraph()
    for link in graph_links:
        s, t = link['source'], link['target']
        if s not in G: G.add_node(s, subset=1 if s in hub_aliases else 0)
        if t not in G: G.add_node(t, subset=1 if t in hub_aliases else 2)
        G.add_edge(s, t)
        
    try: pos = nx.multipartite_layout(G, scale=2, align='horizontal')
    except: pos = nx.spring_layout(G, seed=42)
    
    edge_x, edge_y = [], []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])
        
    # Straight lines for formal flowcharts
    edge_trace = go.Scatter(x=edge_x, y=edge_y, line=dict(width=2, color='#BDC3C7'), hoverinfo='none', mode='lines')
    
    node_x, node_y, texts, colors = [], [], [], []
    for node in G.nodes():
        node_x.append(pos[node][0])
        node_y.append(pos[node][1])
        texts.append(node_labels.get(node, str(node)))
        colors.append("#8E44AD" if node in hub_aliases else "#3498DB")
        
    node_trace = go.Scatter(
        x=node_x, y=node_y, mode='markers+text',
        text=texts, textposition="top center",
        marker=dict(symbol='square', size=35, color=colors, line=dict(width=2, color='#2C3E50')),
        textfont=dict(size=14, color="black", family="Arial")
    )
    
    fig = go.Figure(data=[edge_trace, node_trace], layout=go.Layout(showlegend=False, hovermode='closest', margin=dict(b=40,l=40,r=40,t=40), xaxis=dict(showgrid=False, zeroline=False, showticklabels=False), yaxis=dict(showgrid=False, zeroline=False, showticklabels=False), plot_bgcolor='white'))
    
    img_bytes = fig.to_image(format="png", engine="kaleido", width=1200, height=800, scale=2)
    return base64.b64encode(img_bytes).decode('utf-8')

# ---------------------------------------------------------
# LEGAL PDF GENERATOR
# ---------------------------------------------------------
def generate_legal_pdf(officer_id, action_type, division, provision, evidence_list):
    pdf = FPDF()
    pdf.add_page()
    
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 10, "KERALA POLICE - CRIME BRANCH", ln=True, align='C')
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, f"Division: {division}", ln=True, align='C')
    pdf.cell(0, 10, f"Date: {datetime.now().strftime('%Y-%m-%d')}", ln=True, align='C')
    pdf.ln(10)

    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 10, f"ACTION: {action_type.upper()}", ln=True)
    pdf.set_font("Arial", 'I', 12)
    pdf.cell(0, 10, f"Provision: {provision}", ln=True)
    pdf.cell(0, 10, f"Authorized By: Officer {officer_id}", ln=True)
    pdf.ln(10)

    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 10, "ATTACHED FORENSIC EVIDENCE:", ln=True)
    
    for ev in evidence_list:
        pdf.ln(5)
        pdf.set_font("Arial", 'B', 11)
        pdf.cell(0, 10, f"Exhibit: {ev['title']} ({ev['type']}) - {ev['timestamp']}", ln=True)
        
        pdf.set_font("Arial", '', 10)
        clean_content = str(ev['content']).replace('₹', 'INR ').encode('latin-1', 'replace').decode('latin-1')
        pdf.multi_cell(0, 6, clean_content)
        pdf.ln(5)
        
        if ev.get('graph_links'):
            try:
                img_b64 = get_static_network_b64(ev['graph_links'], ev.get('hub_aliases', []), ev.get('node_labels', {}))
                img_data = base64.b64decode(img_b64)
                with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp:
                    tmp.write(img_data)
                    tmp_path = tmp.name
                
                if pdf.get_y() > 180: pdf.add_page()
                pdf.image(tmp_path, w=180) 
                pdf.ln(5)
                os.remove(tmp_path)
            except Exception:
                pdf.cell(0, 10, "[Flowchart rendering failed: Missing Kaleido or NetworkX dependency]", ln=True)
                
        if ev.get('node_images'):
            pdf.ln(5)
            pdf.set_font("Arial", 'B', 12)
            pdf.cell(0, 10, "IDENTIFIED SUSPECT / NODE PROFILES:", ln=True)
            for node_name, img_b64 in ev['node_images'].items():
                try:
                    lbl = ev.get('node_labels', {}).get(node_name, node_name)
                    img_data = base64.b64decode(img_b64)
                    with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp_aux:
                        tmp_aux.write(img_data)
                        tmp_aux_path = tmp_aux.name
                    if pdf.get_y() > 240: pdf.add_page()
                    pdf.set_font("Arial", 'B', 10)
                    pdf.cell(0, 6, f"Entity Profile: {lbl}", ln=True)
                    pdf.image(tmp_aux_path, w=30)
                    pdf.ln(5)
                    os.remove(tmp_aux_path)
                except Exception: pass

        pdf.ln(10)

    pdf.ln(15)
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, "I.O. Signature: _______________________", ln=True)

    return pdf.output(dest='S').encode('latin-1')

# ---------------------------------------------------------
# THE FINITE EXTRACTION ENGINE 
# ---------------------------------------------------------
def extract_cdr_numbers(file_objs):
    all_numbers = set()
    for file_obj in file_objs:
        try:
            file_obj.seek(0)
            if file_obj.name.endswith('.csv'): df = pd.read_csv(file_obj, dtype=str)
            elif file_obj.name.endswith('.xlsx'): df = pd.read_excel(file_obj, dtype=str)
            else: continue
            text_data = " ".join(df.fillna("").astype(str).values.flatten())
            matches = re.findall(r'(?<!\d)(?:\+?91)?([6-9]\d{9})(?!\d)', text_data)
            all_numbers.update(matches)
        except Exception: pass
    return all_numbers

def extract_table_from_pdf(file_obj, bank_type="UNKNOWN"):
    try:
        transactions = []
        current_txn = None
        date_pattern = re.compile(r'^(\d{1,2}[/-]\w{3,4}[/-]\d{2,4}|\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{1,2}\.\d{1,2}\.\d{2,4})')
        
        with pdfplumber.open(file_obj) as pdf:
            for page in pdf.pages:
                text = page.extract_text()
                if not text: continue
                for line in text.split('\n'):
                    line = line.strip()
                    if not line: continue
                    match = date_pattern.match(line)
                    if match:
                        if current_txn: transactions.append(current_txn)
                        d_str = match.group(1)
                        rem = line[len(d_str):].strip()
                        current_txn = {"Date": d_str, "Raw_Block": rem}
                    else:
                        if current_txn: current_txn["Raw_Block"] += " " + line
        if current_txn: transactions.append(current_txn)

        formatted_data = []
        amount_pattern = re.compile(r'\b\d{1,3}(?:,\d{3})*\.\d{2}\b|\b\d+\.\d{2}\b') 
        
        for txn in transactions:
            raw = txn["Raw_Block"]
            amts = amount_pattern.findall(raw)
            amt_val = 0.0
            bal_val = None
            a_str = "0.00"
            desc = raw
            
            if amts:
                valids = [a.replace(',', '') for a in amts]
                non_zeros = [float(a) for a in valids if float(a) > 0]
                if non_zeros:
                    if len(non_zeros) >= 2:
                        amt_val = non_zeros[-2]
                        bal_val = non_zeros[-1]
                    else:
                        amt_val = non_zeros[0]
                    a_str = f"{amt_val:.2f}"
                    for a in amts: desc = desc.replace(a, '')
                    
            txn['amt_val'] = amt_val
            txn['bal_val'] = bal_val
            txn['a_str'] = a_str
            txn['desc'] = desc.strip()
            
        for i, txn in enumerate(transactions):
            direction = None
            upper_raw = txn["Raw_Block"].upper()
            
            if txn['bal_val'] is not None and txn['amt_val'] > 0:
                if i > 0 and transactions[i-1]['bal_val'] is not None:
                    delta = txn['bal_val'] - transactions[i-1]['bal_val']
                    if abs(abs(delta) - txn['amt_val']) < 1.0: 
                        direction = "Credit" if delta > 0 else "Debit"
                        
                if direction is None and i < len(transactions) - 1 and transactions[i+1]['bal_val'] is not None:
                    delta = txn['bal_val'] - transactions[i+1]['bal_val']
                    if abs(abs(delta) - txn['amt_val']) < 1.0:
                        direction = "Credit" if delta < 0 else "Debit" 
                        
            if direction is None:
                if re.search(r'\bCR\.?\b', upper_raw) or "CREDIT " in upper_raw or "RECEIVED" in upper_raw or "INWARD" in upper_raw or "FROM " in upper_raw or upper_raw.startswith("BY "):
                    direction = "Credit"
                else:
                    direction = "Debit"
                    
            formatted_data.append({
                "Date": txn["Date"],
                "Description": txn['desc'],
                "Amount": txn['a_str'],
                "Direction": direction
            })
            
        return pd.DataFrame(formatted_data) if formatted_data else None
    except Exception as e: return None

# ---------------------------------------------------------
# FORENSIC LOGIC ENGINES 
# ---------------------------------------------------------
def clean_entity_name(raw_string):
    s = re.sub(r'[./\-_]', ' ', str(raw_string).upper())
    s = re.sub(r'\d+', '', s)
    stopwords = {'UPI', 'IMPS', 'NEFT', 'RTGS', 'IB', 'MOB', 'MMID', 'TO', 'TRANSFER', 'FROM', 'FUNDS', 'DR', 'CR', 'INR', 'BIL', 'REV', 'ACH', 'BY', 'PAYMENT', 'UPIREF', 'QENT', 'BRANCH', 'ATM', 'CASH', 'DEPOSIT', 'WITHDRAWAL', 'INB', 'CMS', 'POS', 'SBI', 'HDFC', 'ICICI', 'YBL', 'AXIS', 'PAYTM', 'KOTAK', 'PNB', 'NA', 'UPIREF'}
    words = [w for w in s.split() if w not in stopwords]
    deduped = []
    for w in words:
        if not deduped or deduped[-1] != w: deduped.append(w)
    return " ".join(deduped) if deduped else "UNKNOWN ENTITY"

def extract_upi_nodes(df, risk_mode="Frequency", high_thresh=3.0, med_thresh=2.0):
    if df is None or df.empty: return pd.DataFrame()
    nodes = {}
    desc_col = "Description" if "Description" in df.columns else df.columns[1]
    amt_col = "Amount" if "Amount" in df.columns else df.columns[2]
    date_col = "Date" if "Date" in df.columns else df.columns[0]
    
    for i, row in df.iterrows():
        desc = str(row.get(desc_col, ""))
        if not desc.strip(): continue
        
        amt_str = str(row.get(amt_col, "0")).replace(',', '')
        try: amt = float(amt_str)
        except ValueError: amt = 0.0

        direction = str(row.get('Direction', 'Debit'))
        d_str = str(row.get(date_col, ""))
        dt = pd.to_datetime(d_str, errors='coerce', dayfirst=True)
        if pd.isna(dt): dt = pd.Timestamp.min

        upi = re.search(r'[a-zA-Z0-9.\-_]+@[a-zA-Z]+', desc)
        phone = re.search(r'(?<!\d)(?:\+?91)?([6-9]\d{9})(?!\d)', desc)
        
        tid = None
        if upi: tid = re.sub(r'^(?i)(UPI|IMPS|NEFT)[/\\-]', '', upi.group(0))
        elif phone: tid = phone.group(1)
        else:
            stopwords = {'UPI', 'IMPS', 'NEFT', 'RTGS', 'IB', 'MOB', 'MMID', 'TO', 'TRANSFER', 'FROM', 'FUNDS', 'DR', 'CR', 'INR', 'BIL', 'REV', 'ACH', 'BY', 'PAYMENT', 'UPIREF', 'QENT', 'BRANCH', 'ATM', 'CASH', 'DEPOSIT', 'WITHDRAWAL', 'INB', 'CMS', 'POS', 'SBI', 'HDFC', 'ICICI', 'YBL', 'AXIS', 'PAYTM', 'KOTAK', 'PNB', 'NA'}
            clean_desc = re.sub(r'[/\\-]', ' ', desc) 
            clean_words = re.sub(r'[^a-zA-Z0-9\s]', '', clean_desc).upper().split()
            filtered = [w for w in clean_words if w not in stopwords and not w.isdigit()]
            if len(filtered) >= 3: tid = f"{filtered[0]} {filtered[1]} {filtered[2]}"
            elif len(filtered) == 2: tid = f"{filtered[0]} {filtered[1]}"
            elif len(filtered) == 1: tid = filtered[0]
            else: tid = f"TXN_REF_{i}"
            
        if tid:
            key = (tid, direction)
            if key not in nodes:
                nodes[key] = {"count": 0, "volume": 0.0, "phone": phone.group(1) if phone else "N/A", "earliest": dt, "latest": dt}
            
            nodes[key]["count"] += 1
            nodes[key]["volume"] += amt
            
            if dt != pd.Timestamp.min:
                if nodes[key]["earliest"] == pd.Timestamp.min or dt < nodes[key]["earliest"]: nodes[key]["earliest"] = dt
                if dt > nodes[key]["latest"]: nodes[key]["latest"] = dt
            
    results = []
    for (tid, direction), data in nodes.items():
        val_to_check = data["count"] if risk_mode == "Frequency" else data["volume"]
        risk = f"HIGH ({risk_mode}: {val_to_check})" if val_to_check >= high_thresh else f"MEDIUM ({risk_mode}: {val_to_check})" if val_to_check >= med_thresh else f"LOW ({risk_mode}: {val_to_check})"
        
        results.append({
            "Target Node": tid, "Risk Score": risk, "Phone": data["phone"],
            "Volume": data["volume"], "Direction": direction,
            "Earliest Date": data["earliest"], "Latest Date": data["latest"]
        })
    return pd.DataFrame(results).sort_values(by="Risk Score").drop_duplicates(subset=["Target Node", "Direction"])

def auto_detect_bank(file_bytes):
    try:
        with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
            text = pdf.pages[0].extract_text().lower()
            if 'hdfc' in text: return 'HDFC'
            if 'icici' in text: return 'ICICI'
            if 'axis' in text: return 'Axis Bank'
    except: pass
    return 'Universal Extraction'

def fetch_wallet_data(wallet_address, chain="TRON"):
    if chain == "TRON":
        url = f"https://api.trongrid.io/v1/accounts/{wallet_address}/transactions/trc20"
        try:
            r = requests.get(url, headers={"TRON-PRO-API-KEY": TRON_API_KEY}, timeout=10)
            data = r.json()
            if 'data' not in data: return None
            return pd.DataFrame([{"Date (UTC)": pd.to_datetime(tx.get('block_timestamp', 0), unit='ms').strftime('%Y-%m-%d %H:%M:%S'), "From": tx.get('from', ''), "To": tx.get('to', ''), "Amount": float(tx.get('value', 0)) / (10 ** int(tx.get('token_info', {}).get('decimals', 6))), "Token": tx.get('token_info', {}).get('symbol', 'TRX'), "Transaction Hash": tx.get('transaction_id', '')} for tx in data['data'][:20]])
        except: return None
    elif chain == "ETHEREUM":
        url = f"https://api.etherscan.io/api?module=account&action=txlist&address={wallet_address}&startblock=0&endblock=99999999&page=1&offset=20&sort=desc&apikey={ETHERSCAN_API_KEY}"
        try:
            r = requests.get(url, timeout=10)
            data = r.json()
            if data['status'] != '1': return None
            return pd.DataFrame([{"Date (UTC)": pd.to_datetime(int(tx.get('timeStamp', 0)), unit='s').strftime('%Y-%m-%d %H:%M:%S'), "From": tx.get('from', ''), "To": tx.get('to', ''), "Amount": float(tx.get('value', 0)) / (10 ** 18), "Token": "ETH", "Transaction Hash": tx.get('hash', '')} for tx in data['result'][:20]])
        except: return None

def run_telecom_osint(phone_str):
    try:
        import phonenumbers
        from phonenumbers import geocoder, carrier
        parsed = phonenumbers.parse("+91" + str(phone_str), "IN")
        return {"Telecom Circle": geocoder.description_for_number(parsed, "en"), "Carrier": carrier.name_for_number(parsed, "en")}
    except Exception: return {"Telecom Circle": "Unknown", "Carrier": "Unknown"}

def run_advanced_threat_analysis(text_data):
    threat_keywords = ['usdt', 'binance', 'hawala', 'drop', 'mule', 'percentage', 'cut', 'angadia', 'cash out', 'p2p']
    blob = TextBlob(text_data)
    found_threats = [word for word in threat_keywords if word in text_data.lower()]
    score = min(len(found_threats) * 20, 100)
    if blob.sentiment.polarity < 0: score = min(score + 15, 100)
    return score, f"Layering Indicators Detected: {', '.join(found_threats)}" if score > 40 else "No structural laundering intent detected."

def get_criminal_history(identifier): return None
def fetch_cdr_location(phone_number): return "No Active Ping. Requires Sec 94 BNSS Subpoena."
def fetch_ipdr_phone(upi_id): return "Requires Telecom IPDR Query"

def resolve_upi_data(upi_id):
    if not upi_id or '@' not in upi_id: return None
    clean_id = re.sub(r'^(?i)(UPI|IMPS|NEFT)[/\\-]', '', upi_id)
    parts = clean_id.split('@')
    name_clean = clean_entity_name(parts[0])
    bank_handle = parts[1].lower()
    bank_map = {'ybl': 'Yes Bank', 'sbi': 'State Bank of India', 'icici': 'ICICI Bank', 'hdfcbank': 'HDFC Bank', 'okaxis': 'Axis Bank', 'okicici': 'ICICI Bank', 'oksbi': 'State Bank of India', 'okhdfcbank': 'HDFC Bank', 'paytm': 'Paytm Payments Bank', 'apl': 'Amazon Pay', 'axl': 'Axis Bank', 'ibl': 'ICICI Bank', 'sib': 'South Indian Bank'}
    bank_name = bank_map.get(bank_handle, f"Bank handle: {bank_handle.upper()}")
    phone_match = re.search(r'(?<!\d)[6-9]\d{9}(?!\d)', parts[0])
    phone = phone_match.group(0) if phone_match else fetch_ipdr_phone(clean_id)
    return {"Registered Name": name_clean, "Linked Bank": bank_name, "Phone Number": phone, "Last Active": fetch_cdr_location(phone)}

def query_intelligence_database(identifier, intel_type="bank", extracted_phone="N/A", extracted_upi="N/A"):
    if intel_type == "crypto": return {"Entity Match": "Unknown Wallet Address", "Risk Level": "Pending Investigator Triage", "Linked Bank Data": "Requires Centralized Exchange Subpoena"}
    else:
        extracted_name = clean_entity_name(extracted_upi.split('@')[0]) if extracted_upi != "N/A" and "@" in extracted_upi else "Unknown Entity"
        return {"Registered Name": extracted_name, "Active Phone": extracted_phone, "Last Active": fetch_cdr_location(extracted_phone)}

class SyndicateDatabase:
    def push_transaction(self, sender, receiver, amount, case_file): pass
syndicate_db = SyndicateDatabase()