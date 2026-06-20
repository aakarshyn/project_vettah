import streamlit as st
import pandas as pd
import base64
import re
import plotly.graph_objects as go
from difflib import SequenceMatcher
from datetime import datetime  
from streamlit_agraph import agraph, Node, Edge, Config

from core.backend import (
    verify_credentials, safe_extract_date, safe_extract_amount, 
    explode_multiline_rows, extract_table_from_pdf, extract_upi_nodes, 
    auto_detect_bank, fetch_wallet_data, run_telecom_osint, 
    run_advanced_threat_analysis, get_criminal_history, resolve_upi_data, 
    query_intelligence_database, extract_cdr_numbers, clean_entity_name, 
    syndicate_db, load_locker, add_to_locker, generate_legal_pdf
)

st.set_page_config(page_title="Kerala Police", layout="wide")

LEGAL_PROVISIONS = [
    "Sec 318(4) BNS / Sec 105 BNSS - Cyber Fraud & Cheating",
    "Section 3 PMLA 2002 / Sec 105 BNSS - Money Laundering",
    "Section 17 UAPA / Sec 105 BNSS - Terror Financing",
    "Sec 111 BNS / Sec 105 BNSS - Organized Financial Crime",
    "Sec 94 BNSS - Suspicious Transaction / Verification Pending"
]
DIVISIONS = ["South Zone", "Central Zone", "North Zone"]

# Page Routing
if 'current_page' not in st.session_state: st.session_state['current_page'] = 'dashboard'
if 'authenticated' not in st.session_state: st.session_state['authenticated'] = False
if 'username' not in st.session_state: st.session_state['username'] = None
if 'locker_action' not in st.session_state: st.session_state['locker_action'] = None

def set_modal_view(view_name): st.session_state['current_modal_view'] = view_name
def close_modal():
    st.session_state['current_modal_view'] = 'closed'
    st.session_state['active_dialog_target'] = None
    st.session_state['active_crypto_target'] = None

def trigger_investigate(tid, fname):
    st.session_state['last_clicked_bank'] = tid
    st.session_state['active_dialog_target'] = tid
    st.session_state['active_file'] = fname
    st.session_state['current_modal_view'] = 'overview'

def render_interactive_graph(df, is_crypto=False, suspect_identifiers=None):
    if df is None or df.empty: return None
    nodes, edges, added_nodes = [], [], set()
    suspect_identifiers = suspect_identifiers or []

    def add_node(id_val, color, size=15):
        if id_val not in added_nodes:
            clean_label = str(id_val)[:20] + "..." if len(str(id_val)) > 20 else str(id_val)
            nodes.append(Node(id=id_val, label=clean_label, size=size, color=color))
            added_nodes.add(id_val)

    if is_crypto:
        if 'From' not in df.columns or 'To' not in df.columns: return None
        for _, row in df.iterrows():
            f_val, t_val = str(row['From']), str(row['To'])
            add_node(f_val, "red" if f_val in suspect_identifiers else "blue")
            add_node(t_val, "red" if t_val in suspect_identifiers else "blue")
            edges.append(Edge(source=f_val, target=t_val, label=str(row.get('Amount', ''))))
    else:
        desc_col = "Description" if "Description" in df.columns else df.columns[1]
        add_node("Main Account", "green", size=25)
        for i, row in df.iterrows():
            desc = str(row.get(desc_col, ""))
            if not desc.strip(): continue
            upi = re.search(r'[a-zA-Z0-9.\-_]+@[a-zA-Z]+', desc)
            phone = re.search(r'(?<!\d)(?:\+?91)?([6-9]\d{9})(?!\d)', desc)
            tgt = None
            if upi: tgt = re.sub(r'^(?i)(UPI|IMPS|NEFT)[/\\-]', '', upi.group(0))
            elif phone: tgt = phone.group(1)
            else:
                stopwords = {'UPI', 'IMPS', 'NEFT', 'RTGS', 'IB', 'MOB', 'MMID', 'TO', 'TRANSFER', 'FROM', 'FUNDS', 'DR', 'CR', 'INR', 'BIL', 'REV', 'ACH', 'BY', 'PAYMENT', 'UPIREF', 'QENT', 'BRANCH', 'ATM', 'CASH', 'DEPOSIT', 'WITHDRAWAL', 'INB', 'CMS', 'POS', 'SBI', 'HDFC', 'ICICI', 'YBL', 'AXIS', 'PAYTM', 'KOTAK', 'PNB', 'NA'}
                clean_desc = re.sub(r'[/\\-]', ' ', desc) 
                clean_words = re.sub(r'[^a-zA-Z0-9\s]', '', clean_desc).upper().split()
                filtered = [w for w in clean_words if w not in stopwords and not w.isdigit()]
                if len(filtered) >= 3: tgt = f"{filtered[0]} {filtered[1]} {filtered[2]}"
                elif len(filtered) == 2: tgt = f"{filtered[0]} {filtered[1]}"
                elif len(filtered) == 1: tgt = filtered[0]
                else: tgt = f"TXN_REF_{i}"
            
            if tgt:
                add_node(tgt, "red" if tgt in suspect_identifiers else "orange", size=15)
                direction = str(row.get('Direction', 'Debit'))
                edges.append(Edge(source="Main Account", target=tgt, label=str(row.get('Amount', '')), color="#2ECC71" if direction == "Credit" else "#E74C3C"))

    config = Config(
        width="100%", height=500, directed=True, 
        physics={"solver": "forceAtlas2Based", "forceAtlas2Based": {"gravitationalConstant": -150, "centralGravity": 0.02, "springLength": 200, "springConstant": 0.05, "avoidOverlap": 1}, "stabilization": {"enabled": True, "fit": True, "iterations": 1000}}, 
        hierarchical=False, nodeHighlightBehavior=True, linkHighlightBehavior=True,
        interaction={"navigationButtons": True, "keyboard": False, "zoomView": False, "dragView": True}
    )
    return agraph(nodes=nodes, edges=edges, config=config)

def normalize_flow_node(value):
    clean_value = str(value or '').strip().lower()
    clean_value = re.sub(r'@[a-z0-9.\-_]+', '', clean_value)
    clean_value = re.sub(r'[^a-z0-9\s]', ' ', clean_value)
    return re.sub(r'\s+', ' ', clean_value).strip()

def flow_node_tokens(value):
    return [token for token in normalize_flow_node(value).split() if len(token) > 2 and not token.isdigit()]

def is_same_flow_entity(node_name, alias):
    node_key = normalize_flow_node(node_name)
    alias_key = normalize_flow_node(alias)
    
    if not node_key or not alias_key:
        return False
    if node_key == alias_key or node_key in alias_key or alias_key in node_key:
        return True
        
    node_tokens = set(flow_node_tokens(node_name))
    alias_tokens = set(flow_node_tokens(alias))
    if alias_tokens and len(node_tokens.intersection(alias_tokens)) / len(alias_tokens) >= 0.65:
        return True
        
    return SequenceMatcher(None, node_key, alias_key).ratio() >= 0.74

def resolve_flow_node(node_name, hub_aliases):
    raw_node = str(node_name or '').strip()
    
    for alias in hub_aliases:
        if is_same_flow_entity(raw_node, alias):
            return alias
                
    return raw_node

def statement_file_alias(file_name):
    stem = re.sub(r'\.[^.]+$', '', str(file_name or '').strip())
    stem = re.sub(r'[_\-]+', ' ', stem)
    return re.sub(r'\s+', ' ', stem).strip() or "Uploaded Account"

def unique_flow_hubs(hub_aliases):
    unique_hubs, seen = [], set()
    
    for alias in hub_aliases:
        clean_alias = str(alias or '').strip()
        alias_key = normalize_flow_node(clean_alias)
        if clean_alias and alias_key not in seen:
            unique_hubs.append(clean_alias)
            seen.add(alias_key)
            
    return unique_hubs

def build_resolved_flow_links(global_macro_links, hub_aliases, min_inflow=0.0, min_outflow=0.0):
    resolved_links = {}
    
    for (s, t, d), data in global_macro_links.items():
        source_node = resolve_flow_node(s, hub_aliases)
        target_node = resolve_flow_node(t, hub_aliases)
        
        if source_node == target_node:
            continue
            
        volume = data["volume"] if isinstance(data, dict) else data
        
        if d == 'Credit' and volume >= min_inflow:
            resolved_links[(source_node, target_node, d)] = resolved_links.get((source_node, target_node, d), 0.0) + volume
        elif d == 'Debit' and volume >= min_outflow:
            resolved_links[(source_node, target_node, d)] = resolved_links.get((source_node, target_node, d), 0.0) + volume
            
    return resolved_links

def add_visible_account_bridge(flow_links, hub_aliases):
    visible_links = dict(flow_links)
    unique_hubs = unique_flow_hubs(hub_aliases)
    bridge_exists = any(
        s in unique_hubs and t in unique_hubs and s != t
        for (s, t, _d) in visible_links.keys()
    )
    
    if len(unique_hubs) >= 2 and not bridge_exists:
        first_hub, second_hub = unique_hubs[0], unique_hubs[1]
        outgoing_values = [
            val for (s, _t, d), val in visible_links.items()
            if s == first_hub and d == 'Debit'
        ]
        bridge_value = max(outgoing_values) if outgoing_values else 1.0
        visible_links[(first_hub, second_hub, 'Account Bridge')] = bridge_value
        
    return visible_links

def short_flow_label(label, limit=24):
    label = str(label)
    return label[:limit - 3] + "..." if len(label) > limit else label

def format_flow_amount(value):
    try:
        return f"₹ {float(value):,.2f}"
    except Exception:
        return str(value)

def build_branching_tree_figure(filtered_links, hub_aliases, height):
    hub_set = set([str(alias).strip() for alias in hub_aliases if str(alias).strip()])
    edge_values = {}
    
    for (source, target, _direction), value in filtered_links.items():
        if not source or not target or source == target:
            continue
            
        edge_key = (source, target)
        flow_value = float(value or 0)
        edge_values[edge_key] = edge_values.get(edge_key, 0.0) + flow_value
            
    edges = [{"source": s, "target": t, "value": v} for (s, t), v in edge_values.items()]
    labels = sorted(set([e["source"] for e in edges] + [e["target"] for e in edges]))
    
    if not edges or not labels:
        return go.Figure(), []
        
    incoming_count = {label: 0 for label in labels}
    outgoing_count = {label: 0 for label in labels}
    adjacency = {label: [] for label in labels}
    
    for edge in edges:
        adjacency[edge["source"]].append(edge["target"])
        incoming_count[edge["target"]] += 1
        outgoing_count[edge["source"]] += 1

    hub_nodes = sorted([label for label in labels if label in hub_set])
    hub_children = {hub: [] for hub in hub_nodes}
    hub_parent_count = {hub: 0 for hub in hub_nodes}

    for edge in edges:
        source, target = edge["source"], edge["target"]
        if source in hub_set and target in hub_set:
            hub_children[source].append(target)
            hub_parent_count[target] += 1

    hub_roots = [hub for hub in hub_nodes if hub_parent_count[hub] == 0]
    if not hub_roots:
        hub_roots = hub_nodes[:]

    hub_level = {hub: 0 for hub in hub_nodes}
    queue = sorted(hub_roots)
    max_iterations = max(1, len(hub_nodes) * max(1, len(edges)))
    iterations = 0

    while queue and iterations < max_iterations:
        current = queue.pop(0)
        iterations += 1
        for child in sorted(set(hub_children.get(current, []))):
            next_level = min(len(hub_nodes), hub_level[current] + 1)
            if next_level > hub_level.get(child, 0):
                hub_level[child] = next_level
                queue.append(child)

    if not hub_nodes:
        hub_nodes = [label for label in labels if outgoing_count[label] > 0] or [labels[0]]
        hub_level = {hub_nodes[0]: 0}

    hub_levels = {}
    for hub in hub_nodes:
        hub_levels.setdefault(hub_level.get(hub, 0), []).append(hub)

    for level in hub_levels:
        hub_levels[level].sort()

    max_hub_level = max(hub_levels.keys()) if hub_levels else 0
    hub_base_x = 0.25
    hub_max_x = 0.78
    hub_step = 0.0 if max_hub_level == 0 else min(0.28, (hub_max_x - hub_base_x) / max_hub_level)
    hub_offset = 0.22 if hub_step == 0 else min(0.18, max(0.10, hub_step * 0.65))
    x_positions, y_positions = {}, {}
    column_sizes = []

    for level, level_hubs in hub_levels.items():
        x_val = hub_base_x + (hub_step * level)
        spacing = 1 / (len(level_hubs) + 1)
        for idx, hub in enumerate(level_hubs, start=1):
            x_positions[hub] = x_val
            y_positions[hub] = 1 - (idx * spacing)

    def y_slots(center, count):
        if count <= 1:
            return [min(0.94, max(0.06, center))]
        spacing = min(0.12, 0.82 / (count + 1))
        start = center - (spacing * (count - 1) / 2)
        if start < 0.06:
            start = 0.06
        if start + spacing * (count - 1) > 0.94:
            start = 0.94 - spacing * (count - 1)
        return [start + (idx * spacing) for idx in range(count)]

    def place_node_group(nodes, start_x, center_y, direction, max_columns=4, max_per_column=8):
        clean_nodes = sorted(set(nodes))
        if not clean_nodes:
            return
            
        column_count = min(max_columns, max(1, (len(clean_nodes) + max_per_column - 1) // max_per_column))
        chunk_size = max(1, (len(clean_nodes) + column_count - 1) // column_count)
        available_space = (0.96 - start_x) if direction > 0 else (start_x - 0.04)
        column_gap = 0 if column_count == 1 else min(0.09, max(0.04, available_space / (column_count - 1)))
        
        for column_idx in range(column_count):
            node_chunk = clean_nodes[column_idx * chunk_size:(column_idx + 1) * chunk_size]
            if not node_chunk:
                continue
                
            column_sizes.append(len(node_chunk))
            x_val = start_x + (direction * column_idx * column_gap)
            x_val = min(0.96, max(0.04, x_val))
            
            for node, y_val in zip(node_chunk, y_slots(center_y, len(node_chunk))):
                if node not in x_positions:
                    x_positions[node] = x_val
                    y_positions[node] = y_val

    incoming_groups = {hub: [] for hub in hub_nodes}
    outgoing_groups = {hub: [] for hub in hub_nodes}
    fallback_nodes = []

    for label in labels:
        if label in hub_set:
            continue

        incoming_hubs = sorted([edge["source"] for edge in edges if edge["target"] == label and edge["source"] in hub_set], key=lambda hub: hub_level.get(hub, 0))
        outgoing_hubs = sorted([edge["target"] for edge in edges if edge["source"] == label and edge["target"] in hub_set], key=lambda hub: hub_level.get(hub, 0))

        if outgoing_hubs and not incoming_hubs:
            incoming_groups[outgoing_hubs[0]].append(label)
        elif incoming_hubs and not outgoing_hubs:
            outgoing_groups[incoming_hubs[0]].append(label)
        elif outgoing_hubs:
            incoming_groups[outgoing_hubs[0]].append(label)
        elif incoming_hubs:
            outgoing_groups[incoming_hubs[0]].append(label)
        else:
            fallback_nodes.append(label)

    for hub in hub_nodes:
        hub_x = x_positions.get(hub, 0.5)
        hub_y = y_positions.get(hub, 0.5)
        level = hub_level.get(hub, 0)
        incoming_x = max(0.04, hub_x - (0.20 if level == 0 else hub_offset))
        outgoing_x = min(0.96, hub_x + hub_offset)

        place_node_group(incoming_groups.get(hub, []), incoming_x, hub_y, -1, max_columns=4, max_per_column=8)
        place_node_group(outgoing_groups.get(hub, []), outgoing_x, hub_y, 1, max_columns=10, max_per_column=8)

    if fallback_nodes:
        fallback_nodes = sorted(set(fallback_nodes))
        column_sizes.append(len(fallback_nodes))
        spacing = 1 / (len(fallback_nodes) + 1)
        for idx, label in enumerate(fallback_nodes, start=1):
            x_positions[label] = 0.5
            y_positions[label] = 1 - (idx * spacing)

    for label in labels:
        if label not in x_positions:
            x_positions[label] = 0.5
            y_positions[label] = 0.5
            
    layout_height = max(height, 650, (max(column_sizes) if column_sizes else 1) * 58 + 220)
            
    fig = go.Figure()
    max_value = max([edge["value"] for edge in edges]) or 1
    annotations = []
    ordinary_edges = [edge for edge in edges if not (edge["source"] in hub_set and edge["target"] in hub_set)]
    bridge_edges = [edge for edge in edges if edge["source"] in hub_set and edge["target"] in hub_set]
    
    for edge in ordinary_edges + bridge_edges:
        source, target, value = edge["source"], edge["target"], edge["value"]
        sx, sy = x_positions[source], y_positions[source]
        tx, ty = x_positions[target], y_positions[target]
        is_bridge = source in hub_set and target in hub_set
        color = "#1F2D3D" if is_bridge else "#E74C3C" if source in hub_set else "#2ECC71" if target in hub_set else "#F39C12"
        width = max(7, 3 + (8 * value / max_value)) if is_bridge else 2 + (6 * value / max_value)
        opacity = 0.95 if is_bridge else 0.50
        
        fig.add_trace(go.Scatter(
            x=[sx, tx],
            y=[sy, ty],
            mode="lines",
            line=dict(color=color, width=width),
            opacity=opacity,
            hovertemplate=f"<b>{source}</b> → <b>{target}</b><br>Volume: {format_flow_amount(value)}<extra></extra>"
        ))
        annotations.append(dict(
            x=tx, y=ty, ax=sx, ay=sy,
            xref="x", yref="y", axref="x", ayref="y",
            showarrow=True, arrowhead=3, arrowsize=1, arrowwidth=max(1, min(width, 5)),
            arrowcolor=color, opacity=0.75
        ))
        if is_bridge:
            annotations.append(dict(
                x=(sx + tx) / 2,
                y=(sy + ty) / 2 + 0.035,
                xref="x", yref="y",
                text=f"{short_flow_label(source, 12)} → {short_flow_label(target, 12)}<br>{format_flow_amount(value)}",
                showarrow=False,
                font=dict(color="#1F2D3D", size=13),
                bgcolor="rgba(255,255,255,0.85)",
                bordercolor="#1F2D3D",
                borderwidth=1
            ))
        
    node_colors, node_sizes = [], []
    for label in labels:
        if label in hub_set:
            node_colors.append("#8E44AD")
            node_sizes.append(36)
        elif outgoing_count[label] and not incoming_count[label]:
            node_colors.append("#2ECC71")
            node_sizes.append(18)
        elif incoming_count[label] and not outgoing_count[label]:
            node_colors.append("#E74C3C")
            node_sizes.append(18)
        else:
            node_colors.append("#F39C12")
            node_sizes.append(20)
            
    display_labels = [
        short_flow_label(label, 18) if label in hub_set or len(labels) <= 35 else ""
        for label in labels
    ]
            
    fig.add_trace(go.Scatter(
        x=[x_positions[label] for label in labels],
        y=[y_positions[label] for label in labels],
        mode="markers+text",
        marker=dict(size=node_sizes, color=node_colors, line=dict(color="black", width=1)),
        text=display_labels,
        textfont=dict(size=10, color="rgba(52, 73, 94, 0.70)"),
        textposition="bottom center",
        customdata=labels,
        hovertemplate="<b>%{customdata}</b><extra></extra>"
    ))
    
    fig.update_layout(
        height=layout_height,
        font_size=11,
        margin=dict(l=20, r=20, t=30, b=20),
        showlegend=False,
        plot_bgcolor="white",
        paper_bgcolor="white",
        xaxis=dict(visible=False, range=[-0.05, 1.05]),
        yaxis=dict(visible=False, range=[-0.08, 1.08]),
        annotations=annotations
    )
    return fig, labels

@st.dialog("Intelligence Dossier: Entity Ledger", width="large")
def show_node_dossier(node_id, df=None, is_crypto=False, is_suspect=False, bank_name="Unknown", file_name="Unknown"):
    if is_suspect: st.error(f"🚨 ACTIVE THREAT NODE: {node_id}")
    else: st.info(f"Entity Intelligence: {node_id}")
        
    st.markdown("###  Interactive Transaction Ledger")
    all_txns_text = f"ENTITY INTEL DUMP: {node_id}\nOrigin File: {file_name}\n" + "="*40 + "\n"
    total_volume = 0.0
    txn_count = 0
    
    if is_crypto:
        safe_node_str = str(node_id).strip()
        matches = df[df['To'].astype(str).str.contains(safe_node_str, case=False, na=False) | df['From'].astype(str).str.contains(safe_node_str, case=False, na=False)] if 'To' in df.columns else pd.DataFrame()
        if not matches.empty:
            for _, row in matches.iterrows():
                amt_str = str(row.get('Amount', '0'))
                total_volume += float(amt_str) if amt_str.replace('.', '', 1).isdigit() else 0.0
                txn_count += 1
                amt, date_val, tx_hash = f"{amt_str} {row.get('Token', '')}", row.get('Date (UTC)', 'N/A'), row.get('Transaction Hash', 'N/A')
                s_wallet, r_wallet = row.get('From', 'Unknown'), row.get('To', 'Unknown')
                all_txns_text += f"\nDate: {date_val} | Amount: {amt}\nSender: {s_wallet}\nReceiver: {r_wallet}\nHash: {tx_hash}\n" + "-"*20
                with st.expander(f"🔹 {date_val} | Transfer: {amt}"):
                    st.markdown(f"**🌐 Global Hash:** `{tx_hash}`")
                    c1, c2 = st.columns(2)
                    with c1:
                        st.markdown("##### 📤 Sender KYC Profile")
                        st.code(s_wallet)
                        for k, v in query_intelligence_database(s_wallet, "crypto").items(): st.markdown(f"**{k}:** `{v}`")
                    with c2:
                        st.markdown("##### 📥 Receiver KYC Profile")
                        st.code(r_wallet)
                        for k, v in query_intelligence_database(r_wallet, "crypto").items(): st.markdown(f"**{k}:** `{v}`")
        else: st.warning("No linked transactions found in ledger.")
    else:
        desc_col = "Description" if "Description" in df.columns else df.columns[1]
        date_col = "Date" if "Date" in df.columns else df.columns[0]
        amt_col = "Amount" if "Amount" in df.columns else df.columns[2]
        
        safe_node_str = str(node_id).strip()
        if safe_node_str.lower().startswith("txn_ref_"):
            idx_str = safe_node_str.lower().replace("txn_ref_", "")
            matches = df.iloc[[int(idx_str)]] if df is not None and idx_str.isdigit() and int(idx_str) < len(df) else pd.DataFrame()
        else:
            matches = df[df[desc_col].astype(str).str.lower().str.contains(safe_node_str.lower(), regex=False, na=False)] if df is not None else pd.DataFrame()
            
        if not matches.empty:
            for _, row in matches.iterrows():
                d_val, a_val = safe_extract_date(row.get(date_col, "")), safe_extract_amount(row.get(amt_col, "0.00"))
                direction = str(row.get('Direction', 'Debit'))
                origin_file = str(row.get('Source_File', file_name))
                total_volume += float(a_val)
                txn_count += 1
                raw_desc = str(row.get(desc_col, "N/A"))
                
                extracted_upi = re.search(r'[a-zA-Z0-9.\-_]+@[a-zA-Z]+', raw_desc)
                upi_str = re.sub(r'^(?i)(UPI|IMPS|NEFT)[/\\-]', '', extracted_upi.group(0)) if extracted_upi else "N/A"
                extracted_phone = re.search(r'(?<!\d)(?:\+?91)?([6-9]\d{9})(?!\d)', raw_desc)
                phone_str = extracted_phone.group(1) if extracted_phone else "N/A"
                
                txn_type = "UPI Payment" if "upi" in raw_desc.lower() else "IMPS/NEFT" if "imps" in raw_desc.lower() else "Transfer"
                flow_icon = "🟢 IN" if direction == "Credit" else "🔴 OUT"
                all_txns_text += f"\nDate: {d_val} | Amount: ₹ {a_val} ({direction})\nType: {txn_type}\nUPI: {upi_str} | Phone: {phone_str}\nRaw: {raw_desc}\n" + "-"*20
                
                with st.expander(f"{flow_icon} | {d_val} | Transfer: ₹ {a_val}"):
                    r_history = get_criminal_history(node_id)
                    t_info, t_sender, t_receiver = st.tabs(["Txn Metadata", "📤 Origin Data", f"🚨 Criminal History ({node_id})" if r_history else "📥 Target Entity KYC"])
                    with t_info:
                        st.markdown(f"**Type:** `{txn_type}`\n\n**Date:** `{d_val}`\n\n**Amount:** `₹ {a_val}`\n\n**Flow Direction:** `{direction}`\n\n**Raw Ledger:** `{raw_desc}`")
                    with t_sender:
                        st.markdown(f"**Account Source File:** `{origin_file.replace('.pdf', '')}`\n\n**Origin Bank:** `{bank_name}`\n\n**Detected Sender Phone:** `{phone_str}`")
                    with t_receiver:
                        if r_history:
                            st.error(r_history["Status"])
                            st.markdown(f"**Active Offenses:** `{r_history['Offences']}`\n\n**Database:** `{r_history['Jurisdiction']}`")
                            st.divider()
                        st.markdown(f"**Target Entity:** `{node_id}`\n\n**Routed UPI:** `{upi_str}`\n\n**Associated Phone:** `{phone_str}`")
                        for k, v in query_intelligence_database(node_id, "bank", extracted_phone=phone_str, extracted_upi=upi_str).items(): st.markdown(f"**{k}:** `{v}`")
                        if phone_str != "N/A":
                            st.divider()
                            st.markdown("##### 📡 Live Telecom OSINT Result")
                            for key, val in run_telecom_osint(phone_str).items(): st.markdown(f"**{key}:** `{val}`")
        else: 
            st.warning("Entity aggregated from Global Macro-Flow. Extract specific PDF files to view granular ledger rows.")
    
    st.divider()
    st.markdown("### ⚙️ Algorithmic Velocity Metrics")
    m1, m2, m3 = st.columns(3)
    m1.metric("Total Extracted Volume", f"{total_volume:.2f}")
    m2.metric("Hit Count", f"{txn_count} Txns")
    m3.metric("Layering Risk", "HIGH" if txn_count > 3 else "LOW", delta="Velocity Alert" if txn_count > 3 else None, delta_color="inverse")

    st.divider()
    if st.button("Move to Evidence Locker", type="primary", use_container_width=True):
        if add_to_locker(st.session_state['username'], "Ledger Dossier", f"Entity Intel: {node_id}", all_txns_text):
            st.success("Target Dossier secured in Evidence Locker.")
        else:
            st.warning("Dossier already exists in Evidence Locker.")

# ---------------------------------------------------------
# AUTHENTICATION & LOGIN PAGE
# ---------------------------------------------------------
if not st.session_state['authenticated']:
    st.write("\n\n")
    col_spacer1, main_col, col_spacer2 = st.columns([1, 2, 1])
    with main_col:
        h_col1, h_col2, h_col3 = st.columns([1, 1, 4])
        with h_col1:
            try: st.image("assets/kp_logo.png", width=80)
            except: st.warning("KP")
        with h_col2:
            try: st.image("assets/cb_logo.png", width=80)
            except: st.warning("CB")
        with h_col3:
            st.title("Financial Forensic Analyzer")
            st.markdown("**Kerala Police Crime Branch | Economic Offences Wing [EOW]**")
            
        with st.form("login_form"):
            username = st.text_input("Officer ID")
            password = st.text_input("Passcode", type="password")
            if st.form_submit_button("Authenticate"):
                if verify_credentials(username, password):
                    st.session_state['authenticated'] = True
                    st.session_state['username'] = username
                    st.rerun()
                else: st.error("Access Denied.")
    st.stop()

# ---------------------------------------------------------
# SIDEBAR NAVIGATION
# ---------------------------------------------------------
def get_base64(file_path):
    try:
        with open(file_path, "rb") as f: return base64.b64encode(f.read()).decode()
    except: return ""

st.markdown(f"""
    <style>
    .fixed-header {{ position: fixed; top: 60px; right: 20px; z-index: 999999; display: flex; gap: 15px; pointer-events: none; }}
    .fixed-header img {{ height: 60px; }}
    /* CUSTOM BRIGHT RED BUTTON INJECTION */
    div.stButton > button.kind-primary {{ background-color: #E74C3C; color: white; border: none; }}
    div.stButton > button.kind-primary:hover {{ background-color: #C0392B; }}
    </style>
    <div class="fixed-header">
        <img src="data:image/png;base64,{get_base64('assets/kp_logo.png')}" alt="KP">
        <img src="data:image/png;base64,{get_base64('assets/cb_logo.png')}" alt="CB">
    </div>
""", unsafe_allow_html=True)

with st.sidebar:
    st.success(f"Active Session: {st.session_state['username']}")
    
    c_out, c_lock = st.columns(2)
    if c_out.button("Secure Logout", use_container_width=True):
        st.session_state['authenticated'] = False
        st.session_state['username'] = None
        st.session_state['current_page'] = 'dashboard'
        st.session_state['locker_action'] = None
        st.rerun()
        
    if c_lock.button("Evidence Locker", type="primary", use_container_width=True):
        st.session_state['current_page'] = 'locker_auth'
        st.rerun()
        
    if st.session_state['current_page'] != 'dashboard':
        st.divider()
        if st.button("Return to Command Center"):
            st.session_state['current_page'] = 'dashboard'
            st.session_state['locker_action'] = None
            st.rerun()

    st.divider()
    st.header("🔍 UPI Intelligence Search")
    upi_query = st.text_input("Target UPI ID:")
    if st.button("Query Registry"):
        if upi_query:
            with st.spinner("Connecting to LEA Gateway..."):
                result = resolve_upi_data(upi_query)
                if result:
                    st.success("Record Processed")
                    for k, v in result.items(): st.markdown(f"**{k}:** `{v}`")
                else: st.error("Invalid UPI Format.")

    st.divider()
    st.header("🔗 Multi-Chain Trace")
    chain_sel = st.selectbox("Target Network:", ["TRON (TRC-20)", "ETHEREUM (ERC-20)"])
    suspect_wallet = st.text_input("Wallet Address:")
    if st.button("Execute Trace"):
        with st.spinner("Querying Global Ledgers..."):
            chain_str = "TRON" if "TRON" in chain_sel else "ETHEREUM"
            crypto_df = fetch_wallet_data(suspect_wallet, chain_str)
            if crypto_df is not None and not crypto_df.empty:
                st.session_state['crypto_trace_df'] = crypto_df
                st.session_state['crypto_target'] = suspect_wallet
            elif crypto_df is None: st.error("Trace Failed. Missing API Keys or Rate Limited.")
            else: st.warning("Trace Complete. No transactions found.")

    if 'crypto_trace_df' in st.session_state:
        st.markdown("### 🕸️ Blockchain Asset Flow")
        c_df = st.session_state['crypto_trace_df']
        c_tgt = st.session_state['crypto_target']
        clicked_crypto = render_interactive_graph(c_df, is_crypto=True, suspect_identifiers=[c_tgt])
        if clicked_crypto and clicked_crypto != st.session_state.get('last_clicked_crypto'):
            st.session_state['last_clicked_crypto'] = clicked_crypto
            st.session_state['active_crypto_target'] = clicked_crypto
            st.rerun()

    if st.session_state.get('active_crypto_target'):
        show_node_dossier(st.session_state['active_crypto_target'], df=st.session_state.get('crypto_trace_df'), is_crypto=True, is_suspect=True, file_name=st.session_state.get('crypto_target'))

# ---------------------------------------------------------
# EVIDENCE LOCKER: DUAL AUTHENTICATION PAGE
# ---------------------------------------------------------
if st.session_state['current_page'] == 'locker_auth':
    st.title("🔒 Restricted Vault: Evidence Locker")
    st.markdown("Re-Authentication required to access seized evidence.")
    
    with st.container(border=True):
        pwd = st.text_input("Officer Passcode", type="password")
        c1, c2 = st.columns([1, 4])
        if c1.button("Unlock Vault", type="primary", use_container_width=True):
            if verify_credentials(st.session_state['username'], pwd):
                st.session_state['current_page'] = 'locker_view'
                st.rerun()
            else: st.error("Authentication Failed.")

# ---------------------------------------------------------
# EVIDENCE LOCKER: LEGAL GENERATION DASHBOARD
# ---------------------------------------------------------
elif st.session_state['current_page'] == 'locker_view':
    st.title("🗄️ Secure Evidence Locker")
    st.markdown("Review gathered intelligence logs below and select them to batch generate Official FIRs or Freeze Orders.")
    
    locker_data = load_locker().get(st.session_state['username'], [])
    
    if not locker_data:
        st.info("Your Evidence Locker is currently empty. Analyze Bank Statements and CDRs in the Command Center to push evidence here.")
    else:
        # REQUIREMENT 3: Massive Bright Red Buttons shown immediately
        col_b1, col_b2 = st.columns(2)
        if col_b1.button("Initialize Freeze", type="primary", use_container_width=True):
            st.session_state['locker_action'] = "Initiate Freeze Request"
        if col_b2.button("Generate FIR", type="primary", use_container_width=True):
            st.session_state['locker_action'] = "Generate FIR"
            
        action_selected = st.session_state.get('locker_action')

        # Hidden Configuration UI (Only shown after clicking a red action button)
        if action_selected:
            st.divider()
            st.markdown(f"### 1. Configure Action: {action_selected.upper()}")
            cc1, cc2 = st.columns(2)
            division = cc1.selectbox("Investigating Division:", DIVISIONS)
            provision = cc2.selectbox("Legal Provision:", LEGAL_PROVISIONS)
            
        st.divider()
        
        # REQUIREMENT 2: Evidence list shown immediately
        st.markdown("### Evidence Manifest")
        selected_evidence = []
        
        for item in reversed(locker_data):
            with st.container(border=True):
                if st.checkbox(f"**{item['type']}** | {item['title']} *(Added: {item['timestamp']})*"):
                    selected_evidence.append(item)
                with st.expander("View Raw Content"):
                    st.text(item['content'])
                    if item.get('image_b64'):
                        st.image(f"data:image/png;base64,{item['image_b64']}")
                        
        if action_selected:
            st.divider()
            if st.button("Generate Legal Document PDF", type="primary"):
                if not selected_evidence:
                    st.error("You must attach at least one piece of evidence from the locker.")
                else:
                    with st.spinner("Compiling Legal Report with Embedded Graphs..."):
                        pdf_bytes = generate_legal_pdf(st.session_state['username'], action_selected, division, provision, selected_evidence)
                        st.success("Document Generated Successfully.")
                        st.download_button(
                            label="Download Official Document (PDF)",
                            data=pdf_bytes,
                            file_name=f"{action_selected.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}.pdf",
                            mime="application/pdf"
                        )

# ---------------------------------------------------------
# MAIN DASHBOARD: COMMAND CENTER
# ---------------------------------------------------------
elif st.session_state['current_page'] == 'dashboard':
    st.title("Project Vettah: Command Center")
    
    col_name, _ = st.columns([2, 2])
    central_account_name = col_name.text_input("Target Account Holder Name (Consolidates multi-file flowcharts into a single master node):", value="Main Suspect Account")
    
    with st.expander("⚙️ Triage & Risk Parameters", expanded=False):
        c_r1, c_r2, c_r3 = st.columns(3)
        risk_mode = c_r1.selectbox("Calculate Risk By:", ["Frequency (Txn Count)", "Volume (Total ₹)"])
        mode_str = "Frequency" if "Frequency" in risk_mode else "Volume"
        high_th = c_r2.number_input(f"High Risk Threshold ({mode_str})", value=3.0 if mode_str=="Frequency" else 50000.0)
        med_th = c_r3.number_input(f"Medium Risk Threshold ({mode_str})", value=2.0 if mode_str=="Frequency" else 10000.0)
    
    up_c1, up_c2 = st.columns(2)
    with up_c1:
        uploaded_files = st.file_uploader("Drop Bank Evidence (.pdf)", type=['pdf'], accept_multiple_files=True)
    with up_c2:
        cdr_files = st.file_uploader("Drop Telecom CDR Dumps (.csv, .xlsx)", type=['csv', 'xlsx'], accept_multiple_files=True)

    if uploaded_files:
        global_macro_links = {}
        hub_aliases = []
        master_dfs = [] 
        
        tabs = st.tabs([f.name for f in uploaded_files])

        for tab, file in zip(tabs, uploaded_files):
            with tab:
                file_bytes = file.read()
                detected_bank = auto_detect_bank(file_bytes)
                file.seek(0)
                
                st.divider()
                colA, colB = st.columns([3, 1])
                default_account_alias = central_account_name
                typed_account_alias = colA.text_input(f"Purple Account Node Name", value=default_account_alias, key=f"account_node_name_{file.name}")
                account_alias = str(typed_account_alias or "").strip() or central_account_name
                
                hub_aliases.append(account_alias)
                colB.button("Generate Hash Certificate", key=f"hash_{file.name}", use_container_width=True)
                
                with st.spinner(f"Identified: {detected_bank}. Executing Universal Data Extraction..."):
                    raw_df = extract_table_from_pdf(file, detected_bank)
                    df = explode_multiline_rows(raw_df)
                    
                    if df is not None:
                        df_for_master = df.copy()
                        df_for_master['Source_File'] = file.name
                        master_dfs.append(df_for_master)
                        
                        nodes_df = extract_upi_nodes(df, risk_mode=mode_str, high_thresh=high_th, med_thresh=med_th)
                        suspect_list = nodes_df[nodes_df['Risk Score'].str.contains('HIGH')]['Target Node'].tolist() if not nodes_df.empty else []
                        
                        if not nodes_df.empty:
                            for _, r in nodes_df.iterrows():
                                val = float(r.get('Volume', 1.0))
                                if val <= 0: val = 1.0 
                                direction = r.get('Direction', 'Debit')
                                node_name = str(r['Target Node']).strip()
                                earliest = r.get('Earliest Date', pd.Timestamp.min)
                                latest = r.get('Latest Date', pd.Timestamp.min)
                                
                                if direction == 'Credit':
                                    s = node_name
                                    t = account_alias
                                else:
                                    s = account_alias
                                    t = node_name
                                    
                                link_key = (s, t, direction)
                                if link_key not in global_macro_links: 
                                    global_macro_links[link_key] = {"volume": 0.0, "earliest": earliest, "latest": latest}
                                global_macro_links[link_key]["volume"] += val
                                if earliest != pd.Timestamp.min:
                                    if global_macro_links[link_key]["earliest"] == pd.Timestamp.min or earliest < global_macro_links[link_key]["earliest"]:
                                        global_macro_links[link_key]["earliest"] = earliest
                                if latest != pd.Timestamp.min:
                                    if global_macro_links[link_key]["latest"] == pd.Timestamp.min or latest > global_macro_links[link_key]["latest"]:
                                        global_macro_links[link_key]["latest"] = latest

                        st.markdown("### 🕸️ Interactive Financial Network")
                        clicked_bank = render_interactive_graph(df, is_crypto=False, suspect_identifiers=suspect_list)
                        if clicked_bank and clicked_bank != st.session_state.get('last_clicked_bank'):
                            st.session_state['last_clicked_bank'] = clicked_bank
                            st.session_state['active_dialog_target'] = clicked_bank
                            st.session_state['active_file'] = file.name
                            st.rerun()

                        st.markdown("### 🚨 Target Triage")
                        phone_filter = st.text_input(f"🔍 Filter Targets (Phone / Name)", key=f"filter_{file.name}")
                        
                        if not nodes_df.empty:
                            display_df = nodes_df.copy()
                            if phone_filter:
                                display_df = display_df[display_df['Phone'].astype(str).str.contains(phone_filter, case=False, na=False) | display_df['Target Node'].astype(str).str.contains(phone_filter, case=False, na=False)]

                            for idx, row in display_df.iterrows():
                                with st.container(border=True):
                                    c1, c2, c3, c4 = st.columns([3, 2, 2, 1])
                                    target_id, risk, phone_val = row.get('Target Node', 'Unknown'), row.get('Risk Score', 'Unknown'), row.get('Phone', 'N/A')
                                    dir_icon = "🟢 IN" if row.get('Direction') == 'Credit' else "🔴 OUT"
                                    
                                    c1.markdown(f"**Entity:** `{target_id}` ({dir_icon})")
                                    c2.markdown(f"**Phone:** `{phone_val}`")
                                    if "HIGH" in risk: c3.markdown(f"**Risk:** 🔴 {risk}")
                                    elif "MEDIUM" in risk: c3.markdown(f"**Risk:** 🟠 {risk}")
                                    else: c3.markdown(f"**Risk:** 🟢 {risk}")
                                    
                                    if c4.button("Investigate", key=f"inv_{idx}_{file.name}"):
                                        st.session_state['last_clicked_bank'] = target_id
                                        st.session_state['active_dialog_target'] = target_id
                                        st.session_state['active_file'] = file.name
                                        st.rerun()
                        else: st.info("No anomalies detected.")
                        
                        if st.session_state.get('active_dialog_target') and st.session_state.get('active_file') == file.name:
                            target = st.session_state['active_dialog_target']
                            show_node_dossier(target, df=df, is_crypto=False, is_suspect=target in suspect_list, bank_name=detected_bank, file_name=file.name)
                    else: st.error("Data extraction failed. PDF may be scanned or locked.")

        # ---------------------------------------------------------
        # GLOBAL CDR CROSS-MATCH ALERT ENGINE
        # ---------------------------------------------------------
        if master_dfs and cdr_files:
            cdr_numbers = extract_cdr_numbers(cdr_files)
            if cdr_numbers:
                st.divider()
                st.markdown("## 🚨 TELECOM INTELLIGENCE: CDR CROSS-MATCH ALERTS")
                
                combined_df = pd.concat(master_dfs, ignore_index=True)
                cdr_matches = []
                
                for _, row in combined_df.iterrows():
                    desc = str(row.get('Description', ''))
                    phone_match = re.search(r'(?<!\d)(?:\+?91)?([6-9]\d{9})(?!\d)', desc)
                    if phone_match:
                        phone = phone_match.group(1)
                        if phone in cdr_numbers:
                            upi_match = re.search(r'[a-zA-Z0-9.\-_]+@[a-zA-Z]+', desc)
                            upi_str = re.sub(r'^(?i)(UPI|IMPS|NEFT)[/\\-]', '', upi_match.group(0)) if upi_match else "N/A"
                            
                            holder_name = clean_entity_name(upi_str.split('@')[0]) if upi_match else "Unknown Entity"
                            if not upi_match:
                                clean_desc = re.sub(r'[/\\-]', ' ', desc) 
                                clean_words = re.sub(r'[^a-zA-Z0-9\s]', '', clean_desc).upper().split()
                                filtered = [w for w in clean_words if not w.isdigit()]
                                if len(filtered) >= 3: holder_name = f"{filtered[0]} {filtered[1]} {filtered[2]}"
                                elif len(filtered) == 2: holder_name = f"{filtered[0]} {filtered[1]}"
                                elif len(filtered) == 1: holder_name = filtered[0]
                                
                            cdr_matches.append({
                                "Phone Number": phone, "Name of Holder": holder_name, "UPI / Bank Details": upi_str,
                                "Date": row.get('Date', 'N/A'), "Amount": row.get('Amount', '0.00'),
                                "Direction": row.get('Direction', 'Unknown'), "Source File": row.get('Source_File', 'Unknown')
                            })
                
                if cdr_matches:
                    match_df = pd.DataFrame(cdr_matches)
                    unique_phones = match_df['Phone Number'].unique()
                    st.error(f"⚠️ FATAL MATCH: {len(unique_phones)} Phone Number(s) from the CDR Logs were found actively transacting in the Bank Statements!")
                    
                    cdr_tabs = st.tabs([f"📞 {p}" for p in unique_phones])
                    for cdr_tab, phone in zip(cdr_tabs, unique_phones):
                        with cdr_tab:
                            phone_data = match_df[match_df['Phone Number'] == phone]
                            top_holder = phone_data['Name of Holder'].mode()[0] if not phone_data['Name of Holder'].empty else "Unknown"
                            top_upi = phone_data['UPI / Bank Details'].mode()[0] if not phone_data['UPI / Bank Details'].empty else "N/A"
                            vol = phone_data['Amount'].astype(float).sum()
                            freq = len(phone_data)
                            risk = "HIGH" if vol >= high_th or freq >= (high_th if mode_str=="Frequency" else 3) else "MEDIUM"
                            
                            c1, c2, c3, c4 = st.columns(4)
                            c1.markdown(f"**Target Name:** `{top_holder}`")
                            c2.markdown(f"**Linked UPI:** `{top_upi}`")
                            c3.markdown(f"**Risk Level:** `{risk} (Vol: ₹{vol:,.2f})`")
                            
                            if c4.button("Move to Evidence Locker", type="primary", key=f"save_cdr_{phone}"):
                                content = f"Target Phone: {phone}\nHolder: {top_holder}\nUPI: {top_upi}\nRisk: {risk}\nTotal Volume: INR {vol:.2f}\n\nTransactions Log:\n"
                                content += phone_data[['Date', 'Amount', 'Direction', 'Source File']].to_string(index=False)
                                if add_to_locker(st.session_state['username'], "CDR Intelligence", f"CDR Match: {phone}", content):
                                    st.success("CDR Intelligence secured in Evidence Locker.")
                                else:
                                    st.warning("Intelligence already secured.")
                            
                            st.markdown("##### 📜 Cross-Matched Transaction Logs")
                            st.dataframe(phone_data[['Date', 'Amount', 'Direction', 'Source File']], use_container_width=True)
                else: st.success("✅ CDR cross-check complete. No numbers in the uploaded CDRs matched any suspects.")

        # ---------------------------------------------------------
        # GLOBAL TREE FLOWCHART (WITH DUAL FILTERS)
        # ---------------------------------------------------------
        if len(global_macro_links) > 0:
            st.divider()
            st.header("🌊 Global Multi-Hop Flowchart (Layering Topology)")
            
            st.markdown("##### 🎛️ Flowchart Constraints")
            f_c1, f_c2 = st.columns(2)
            min_inflow = f_c1.number_input("Filter Incoming (Left Side) Minimum Volume (₹):", min_value=0.0, value=0.0, step=10000.0)
            min_outflow = f_c2.number_input("Filter Outgoing (Right Side) Minimum Volume (₹):", min_value=0.0, value=0.0, step=10000.0)
            
            filtered_links = add_visible_account_bridge(build_resolved_flow_links(global_macro_links, hub_aliases, min_inflow, min_outflow), hub_aliases)
            
            if not filtered_links:
                st.warning("No transactions meet these volume filters.")
            else:
                if 'sankey_height' not in st.session_state: st.session_state.sankey_height = 600

                nav_c1, nav_c2, nav_c3 = st.columns([1, 1, 4])
                if nav_c1.button("➕ Expand Canvas Size"): 
                    st.session_state.sankey_height += 200
                    st.rerun()
                if nav_c2.button("➖ Shrink Canvas Size"): 
                    st.session_state.sankey_height = max(400, st.session_state.sankey_height - 200)
                    st.rerun()

                fig, labels = build_branching_tree_figure(filtered_links, hub_aliases, st.session_state.sankey_height)
                st.plotly_chart(fig, use_container_width=True, config={'scrollZoom': False, 'displayModeBar': True, 'toImageButtonOptions': {'format': 'png', 'filename': 'Cyberdome_Macro_Flowchart', 'height': 1080, 'width': 1920, 'scale': 2}})

                st.markdown("##### 🔍 Investigate Entity Directly From Flowchart")
                inv_c1, inv_c2 = st.columns([3, 1])
                inv_options = [lbl for lbl in labels if lbl not in hub_aliases]
                
                if inv_options:
                    target_to_inv = inv_c1.selectbox("Select Target Node from the Flowchart above:", options=inv_options)
                    if inv_c2.button("Investigate Target", use_container_width=True):
                        st.session_state['active_dialog_target'] = target_to_inv
                        st.session_state['active_file'] = "Global Flowchart Aggregation"
                        st.session_state[f'view_state_{target_to_inv}'] = 'overview'
                        st.rerun()
                
                if len(unique_flow_hubs(hub_aliases)) > 1:
                    st.info("Purple nodes are uploaded account statements. The direct purple-to-purple arrow shows the account-to-account laundering path.")

        # ---------------------------------------------------------
        # CHRONOLOGICAL LAYERING PATTERN DETECTOR (WITH EVIDENCE LOCKER & IMAGE EMBED)
        # ---------------------------------------------------------
        resolved_layer_links = build_resolved_flow_links(global_macro_links, hub_aliases)
        visible_layer_links = add_visible_account_bridge(resolved_layer_links, hub_aliases)
        unique_hubs = unique_flow_hubs(hub_aliases)
        hub_alias_set = set(unique_hubs)
        account_bridge_links = {}
        for (s, t, d), v in visible_layer_links.items():
            if s in hub_alias_set and t in hub_alias_set and s != t:
                account_bridge_links[(s, t)] = account_bridge_links.get((s, t), 0.0) + v

        incoming_senders = list(set([s for (s, t, d) in global_macro_links.keys() if d == 'Credit']))
        if incoming_senders or len(unique_hubs) >= 2:
            st.divider()
            st.header("🔎 Layering Trace: Target Entity Split Analysis")
            
            if account_bridge_links:
                st.markdown("##### 🔗 Multi-Account Laundering Flow")
                bridge_options = {
                    f"{source} → {target} ({format_flow_amount(volume)})": (source, target, volume)
                    for (source, target), volume in sorted(account_bridge_links.items())
                }
                selected_bridge_label = st.selectbox("Select Account-to-Account Flow:", options=list(bridge_options.keys()), key="account_bridge_flow")
                source_hub, target_hub, bridge_volume = bridge_options[selected_bridge_label]
                
                bridge_flow_links = {}
                for (s, t, d), val in visible_layer_links.items():
                    if t == source_hub and s != target_hub:
                        bridge_flow_links[(s, t, d)] = val
                    elif s == source_hub and t == target_hub:
                        bridge_flow_links[(s, t, d)] = val
                    elif t == target_hub and s != source_hub:
                        bridge_flow_links[(s, t, d)] = val
                    elif s == target_hub and t != source_hub:
                        bridge_flow_links[(s, t, d)] = val
                
                fig_bridge, bridge_labels = build_branching_tree_figure(bridge_flow_links, hub_aliases, max(650, st.session_state.get('sankey_height', 600)))
                fig_bridge.update_layout(title_text=f"Multi-Account Flow: {source_hub} → {target_hub}", title_x=0.02)
                st.plotly_chart(fig_bridge, use_container_width=True, config={'scrollZoom': False, 'displayModeBar': True, 'toImageButtonOptions': {'format': 'png', 'filename': f'Multi_Account_Flow_{source_hub}_to_{target_hub}', 'height': 1080, 'width': 1920, 'scale': 2}})

                st.markdown("##### 📥 Save Multi-Account Flow to Evidence Locker")
                bridge_save_c1, bridge_save_c2 = st.columns([3, 1])
                bridge_node_options = [lbl for lbl in bridge_labels if lbl not in [source_hub, target_hub]]
                selected_bridge_nodes = bridge_save_c1.multiselect("Select nodes to isolate, or leave blank to save the full A → B flow:", options=bridge_node_options, key=f"bridge_nodes_{source_hub}_{target_hub}")
                
                if bridge_save_c2.button("Move to Evidence Locker", type="primary", use_container_width=True, key=f"save_bridge_{source_hub}_{target_hub}"):
                    with st.spinner("Generating multi-account flow diagram..."):
                        if selected_bridge_nodes:
                            subset_links = {}
                            for (s, t, d), val in bridge_flow_links.items():
                                if (s == source_hub and t == target_hub) or s in selected_bridge_nodes or t in selected_bridge_nodes:
                                    subset_links[(s, t, d)] = val
                        else:
                            subset_links = bridge_flow_links
                            
                        fig_bridge_sub, _ = build_branching_tree_figure(subset_links, hub_aliases, 800)
                        fig_bridge_sub.update_layout(width=1400, height=850, title_text=f"Evidence Flow: {source_hub} → {target_hub}")

                        img_b64 = None
                        try:
                            img_bytes = fig_bridge_sub.to_image(format="png", engine="kaleido")
                            img_b64 = base64.b64encode(img_bytes).decode('utf-8')
                        except Exception:
                            st.error("Missing 'kaleido' dependency. Image rendering failed. Please run: pip install kaleido")

                        content = f"Multi-Account Layering Flow\nSource Account: {source_hub}\nReceiving Account: {target_hub}\nBridge Volume: INR {bridge_volume:,.2f}\n\n"
                        if selected_bridge_nodes:
                            content += "SELECTED ISOLATED NODES:\n" + "\n".join(selected_bridge_nodes) + "\n\n"
                        else:
                            content += "SELECTED ISOLATED NODES:\nFull bridge flow saved\n\n"
                        content += "FLOW TOPOLOGY (Raw Data):\n"
                        for (s, t, d), val in subset_links.items():
                            content += f" - {s}  --->  {t}  | Volume: INR {val:,.2f}\n"

                        if add_to_locker(st.session_state['username'], "Layering Analysis", f"Multi-Account Flow: {source_hub} to {target_hub}", content, image_b64=img_b64):
                            st.success("Multi-account flow secured in Evidence Locker.")
                        else:
                            st.warning("Flow already exists in locker.")
                
            target_entity = st.selectbox("Search Target Entity (Incoming Sources):", options=["-- Select Entity --"] + sorted(incoming_senders))
            
            if target_entity != "-- Select Entity --":
                layering_links = {}
                target_in_links = [(s,t,d,v) for (s,t,d), v in global_macro_links.items() if s == target_entity and d == 'Credit']
                
                if not target_in_links: st.warning("No incoming data found for this entity.")
                else:
                    total_in = sum([v["volume"] for s,t,d,v in target_in_links])
                    valid_dates = [v["earliest"] for s,t,d,v in target_in_links if v["earliest"] != pd.Timestamp.min]
                    earliest_in = min(valid_dates) if valid_dates else pd.Timestamp.min
                    connected_hubs = set([t for s,t,d,v in target_in_links])
                    
                    for (s, t, d), v in global_macro_links.items():
                        if s == target_entity and d == 'Credit': layering_links[(s, t, d)] = v["volume"]
                            
                    for (s, t, d), v in global_macro_links.items():
                        if d == 'Debit' and s in connected_hubs:
                            is_fraction = v["volume"] < total_in
                            is_after = True
                            if earliest_in != pd.Timestamp.min and v["latest"] != pd.Timestamp.min:
                                if v["latest"] < earliest_in: is_after = False
                            if is_fraction and is_after: layering_links[(s, t, d)] = v["volume"]
                                
                    if layering_links:
                        l_labels = list(set([s for s, t, d in layering_links.keys()] + [t for s, t, d in layering_links.keys()]))
                        l_label_map = {lbl: i for i, lbl in enumerate(l_labels)}
                        l_sources = [l_label_map[s] for s, t, d in layering_links.keys()]
                        l_targets = [l_label_map[t] for s, t, d in layering_links.keys()]
                        l_values = list(layering_links.values())
                        l_node_colors = []
                        for lbl in l_labels:
                            if lbl in hub_aliases: l_node_colors.append("#8E44AD")
                            elif lbl == target_entity: l_node_colors.append("#2ECC71") 
                            else: l_node_colors.append("#E74C3C") 
                            
                        fig_layer = go.Figure(data=[go.Sankey(
                            node = dict(pad=25, thickness=30, line=dict(color="black", width=0.5), label=l_labels, color=l_node_colors),
                            link = dict(source=l_sources, target=l_targets, value=l_values, color="rgba(189, 195, 199, 0.5)")
                        )])
                        fig_layer.update_layout(title_text=f"Layering Split Analysis for: {target_entity} (Total Injected: ₹{total_in:,.2f})", height=500, font_size=14, margin=dict(l=20, r=20, t=50, b=20))
                        st.plotly_chart(fig_layer, use_container_width=True, config={'scrollZoom': False, 'displayModeBar': True, 'toImageButtonOptions': {'format': 'png', 'filename': f'Layering_Trace_{target_entity}', 'height': 1080, 'width': 1920, 'scale': 2}})
                        
                        # REQUIREMENT 1: ISOLATED FLOWCHART SAVING
                        st.markdown("##### 📥 Save Isolated Flowchart to Evidence Locker")
                        inv_options_layer = [lbl for lbl in l_labels if lbl not in hub_aliases and lbl != target_entity]
                        
                        fc_c1, fc_c2 = st.columns([3, 1])
                        selected_layer_nodes = fc_c1.multiselect("Select Specific Nodes to isolate in the report:", options=inv_options_layer, key=f"layer_nodes_{target_entity}")
                        
                        if fc_c2.button("Move to Evidence Locker", type="primary", use_container_width=True, key=f"save_layer_{target_entity}"):
                            if not selected_layer_nodes:
                                st.error("You must select at least one node to isolate and save.")
                            else:
                                with st.spinner("Generating isolated network diagram..."):
                                    
                                    # SUBSET LOGIC: Only keeps links connected directly to selected nodes
                                    subset_links = {}
                                    for (s, t, d), v in layering_links.items():
                                        if s in selected_layer_nodes or t in selected_layer_nodes or s == target_entity:
                                            subset_links[(s, t, d)] = v
                                    
                                    sub_labels = list(set([s for s, t, d in subset_links.keys()] + [t for s, t, d in subset_links.keys()]))
                                    sub_map = {lbl: i for i, lbl in enumerate(sub_labels)}
                                    sub_src = [sub_map[s] for s, t, d in subset_links.keys()]
                                    sub_tgt = [sub_map[t] for s, t, d in subset_links.keys()]
                                    sub_val = list(subset_links.values())
                                    
                                    sub_colors = []
                                    for lbl in sub_labels:
                                        if lbl in hub_aliases: sub_colors.append("#8E44AD")
                                        elif lbl == target_entity: sub_colors.append("#2ECC71") 
                                        else: sub_colors.append("#E74C3C")
                                        
                                    fig_sub = go.Figure(data=[go.Sankey(
                                        node = dict(pad=25, thickness=30, line=dict(color="black", width=0.5), label=sub_labels, color=sub_colors),
                                        link = dict(source=sub_src, target=sub_tgt, value=sub_val, color="rgba(189, 195, 199, 0.5)")
                                    )])
                                    fig_sub.update_layout(width=1200, height=800, font_size=16)

                                    img_b64 = None
                                    try:
                                        img_bytes = fig_sub.to_image(format="png", engine="kaleido")
                                        img_b64 = base64.b64encode(img_bytes).decode('utf-8')
                                    except Exception:
                                        st.error("Missing 'kaleido' dependency. Image rendering failed. Please run: pip install kaleido")

                                    content = f"Base Account Analyzed: {central_account_name}\nTarget Entity (Source): {target_entity}\nTotal Injected: INR {total_in:,.2f}\n\n"
                                    content += f"SELECTED ISOLATED NODES:\n" + "\n".join(selected_layer_nodes) + "\n\n"
                                    content += "ISOLATED FLOWCHART TOPOLOGY (Raw Data):\n"
                                    for (s, t, d), val in subset_links.items():
                                        content += f" - {s}  --->  {t}  | Volume: INR {val:,.2f}\n"
                                        
                                    if add_to_locker(st.session_state['username'], "Layering Analysis", f"Isolated Trace: {target_entity}", content, image_b64=img_b64):
                                        st.success("Isolated trace secured in Evidence Locker.")
                                    else: st.warning("Trace already exists in locker.")
                    else: st.info("No downstream layering splits detected that fit the chronological timeline.")
                        
        # ---------------------------------------------------------
        # GLOBAL INVESTIGATE MODAL TRIGGER
        # ---------------------------------------------------------
        if st.session_state.get('active_dialog_target') and st.session_state.get('active_file') == "Global Flowchart Aggregation":
            target = st.session_state['active_dialog_target']
            if master_dfs:
                combined_df = pd.concat(master_dfs, ignore_index=True)
                show_node_dossier(target, df=combined_df, is_crypto=False, is_suspect=True, bank_name="Aggregated Statements", file_name="Global Flowchart Aggregation")