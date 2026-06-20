import streamlit as st
from transformers import pipeline
from neo4j import GraphDatabase
from datetime import datetime

# PHASE 4: ZERO-SHOT THREAT AI
@st.cache_resource
def load_threat_ai():
    # Context-aware intent detection
    return pipeline("zero-shot-classification", model="facebook/bart-large-mnli")

def run_advanced_threat_analysis(text_data):
    classifier = load_threat_ai()
    candidate_labels = [
        "money laundering and financial layering", 
        "recruiting bank accounts or mules", 
        "cryptocurrency off-ramping or hawala",
        "normal casual conversation"
    ]
    # Truncate text to stay within model token limits
    safe_text = str(text_data)[:1000] 
    result = classifier(safe_text, candidate_labels)
    
    top_label = result['labels'][0]
    top_score = result['scores'][0] * 100
    
    if top_label == "normal casual conversation" or top_score < 50:
        return 0, "No structural layering intent detected."
    return int(top_score), f"High Probability Intent: {top_label.title()}"

# PHASE 3: GRAPH SYNDICATE ENGINE
class SyndicateDatabase:
    def __init__(self, uri="bolt://localhost:7687", user="neo4j", password="password"):
        try:
            self.driver = GraphDatabase.driver(uri, auth=(user, password))
            self.connected = True
        except: self.connected = False

    def push_transaction(self, sender, receiver, amount, case_file):
        if not self.connected: return False, "GraphDB Offline."
        query = "MERGE (s:Entity {id: $sender}) MERGE (r:Entity {id: $receiver}) MERGE (s)-[t:TRANSFERRED {amount: $amount, case: $case_file}]->(r)"
        try:
            with self.driver.session() as session:
                session.run(query, sender=sender, receiver=receiver, amount=amount, case_file=case_file)
            return True, "Synced."
        except: return False, "Connection Error."

syndicate_db = SyndicateDatabase()

# PHASE 3: DYNAMIC FIR GENERATOR
def generate_fir_draft(target_entity, case_file, total_volume, linked_upi, crime_type, division):
    date_str = datetime.now().strftime("%Y-%m-%d")
    sections = {
        "Cyber Fraud / Cheating": "Section 318 BNS & Sec 105 BNSS",
        "Extortion": "Section 308 BNS & Sec 105 BNSS",
        "Money Laundering (PMLA)": "PMLA 2002 & Sec 105 BNSS"
    }
    applied = sections.get(crime_type, "Sec 105 BNSS")
    
    return f"""KERALA POLICE - CRIME BRANCH
Division: {division}
Date: {date_str}

FIRST INFORMATION REPORT - AUTOMATED DRAFT
------------------------------------------
Target: {target_entity}
Associated UPI/Identifiers: {linked_upi}
Evidence Reference: {case_file}

LEGAL PROVISIONS: {applied}

SUMMARY:
Automated forensic analysis of the seized ledger indicates illicit financial 
layering detected by Vettah Intelligence Grid. Total volume: ₹ {total_volume}

I.O. Signature: _______________________
"""