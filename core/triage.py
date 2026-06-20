import pandas as pd
import re
import os

def load_threat_database(filepath="threat_intel.csv"):
    """Pulls known bad-actor identifiers from the external CSV."""
    if os.path.exists(filepath):
        try:
            df = pd.read_csv(filepath)
            if 'identifier' in df.columns:
                return df['identifier'].dropna().astype(str).str.lower().tolist()
        except Exception:
            pass
    return []

def clean_amount(val):
    """Safely extracts numeric values from messy bank amount strings."""
    try:
        # Strip everything except digits and decimals
        clean_str = re.sub(r'[^\d.]', '', str(val))
        return float(clean_str) if clean_str else 0.0
    except Exception:
        return 0.0

def extract_upi_nodes(df):
    """
    Real-World Triage Engine:
    Tracks Volume, Velocity, and Structuring (Smurfing) signatures to calculate Risk Scores.
    """
    THREAT_INTEL = load_threat_database()
    
    cols = df.columns.tolist()
    if len(cols) < 2:
        return pd.DataFrame()

    # 1. Smart Column Hunting
    desc_col = next((c for c in cols if any(k in str(c).lower() for k in ['desc', 'narration', 'particular', 'remark'])), cols[1])
    debit_col = next((c for c in cols if any(k in str(c).lower() for k in ['debit', 'withdrawal', 'dr', 'amount', 'amt'])), cols[2] if len(cols) > 2 else cols[-1])

    upi_pattern = re.compile(r'[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}')
    
    # Dictionary to track real behavioral metrics
    # Format: { 'upi_id': {'count': 0, 'total_val': 0.0, 'max_val': 0.0} }
    entity_stats = {}

    # 2. Ingest and Aggregate the Math
    for _, row in df.iterrows():
        text = str(row[desc_col])
        amt = clean_amount(row[debit_col])
        
        # Extract entities
        found_entities = upi_pattern.findall(text)
        if 'XXXXX' in text:
            found_entities.extend(re.findall(r'X{4,5}\d{4}', text))
            
        for entity in found_entities:
            clean_entity = entity.lower()
            if clean_entity not in entity_stats:
                entity_stats[clean_entity] = {'count': 0, 'total_val': 0.0, 'max_val': 0.0, 'original': entity}
                
            entity_stats[clean_entity]['count'] += 1
            entity_stats[clean_entity]['total_val'] += amt
            if amt > entity_stats[clean_entity]['max_val']:
                entity_stats[clean_entity]['max_val'] = amt

    # 3. Apply Heuristic Rule Engine
    suspects_data = []
    
    for entity, stats in entity_stats.items():
        flags = []
        risk_score = 0
        
        # Rule 1: Threat Database Match (Instant 100% Risk)
        if any(threat in entity for threat in THREAT_INTEL):
            flags.append("Database Match")
            risk_score += 100
            
        # Rule 2: Velocity Anomaly / Mule Pattern
        if stats['count'] >= 4:
            flags.append("High Velocity (Mule Risk)")
            risk_score += 40
            
        # Rule 3: High-Value Flight
        if stats['max_val'] >= 50000:
            flags.append("High-Value Transfer")
            risk_score += 30
            
        # Rule 4: Structuring / Smurfing (Transfers designed to avoid 50k reporting limits)
        if stats['count'] >= 2 and (40000 <= stats['max_val'] < 50000):
            flags.append("Structuring (Smurfing Signature)")
            risk_score += 60

        # If any suspicious behavior was flagged, add them to the docket
        if risk_score > 0:
            suspects_data.append({
                "Target Node": stats['original'],
                "Txn Count": stats['count'],
                "Total Volume (₹)": f"₹ {stats['total_val']:,.2f}",
                "Risk Score": f"{min(risk_score, 100)} / 100",
                "Detection Flags": " | ".join(flags)
            })

    # 4. Output sorted by highest risk first
    if not suspects_data:
        return pd.DataFrame()
        
    suspect_df = pd.DataFrame(suspects_data).sort_values(by="Risk Score", ascending=False)
    return suspect_df