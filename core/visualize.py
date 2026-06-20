from streamlit_agraph import agraph, Node, Edge, Config
import pandas as pd
import re

def render_interactive_graph(df, is_crypto=False, suspect_identifiers=[]):
    nodes = []
    edges = []
    added_nodes = set()

    origin_id = "Target Wallet" if is_crypto else "Origin Account"
    nodes.append(Node(id=origin_id, label=origin_id, size=30, color="#2563eb", symbolType="diamond", font={'color': 'white'}))
    added_nodes.add(origin_id)

    if df is None or df.empty: return None

    if is_crypto:
        for _, row in df.iterrows(): 
            tgt = str(row.get('To', 'Unknown'))[:12] + "..."
            is_suspect = str(row.get('To', '')) in suspect_identifiers
            node_color = "#dc2626" if is_suspect else "#334155" 
            
            if tgt not in added_nodes:
                nodes.append(Node(id=tgt, label=tgt, size=20, color=node_color, font={'color': 'white'}))
                added_nodes.add(tgt)
            
            # FIX: length=350 forces the nodes far apart so they don't cluster!
            edges.append(Edge(source=origin_id, target=tgt, color="#64748b", length=350))
            
    else:
        cols = df.columns.tolist()
        desc_col = next((c for c in cols if any(k in str(c).lower() for k in ['desc', 'narration', 'particular'])), cols[1] if len(cols) > 1 else None)
        debit_col = next((c for c in cols if any(k in str(c).lower() for k in ['debit', 'withdrawal', 'dr', 'amount'])), cols[2] if len(cols) > 2 else None)

        if desc_col and debit_col:
            for _, row in df.iterrows():
                raw_amt = str(row[debit_col]).strip()
                if not any(c.isdigit() for c in raw_amt): continue

                raw_desc = str(row[desc_col]).strip()
                desc_parts = [p.strip() for p in re.split(r'[/|\-]', raw_desc) if len(p.strip()) > 3 and not p.strip().replace('.', '').isnumeric()]
                tgt = desc_parts[0][:25] if desc_parts else raw_desc[:25]
                
                is_suspect = any(str(sus) in raw_desc for sus in suspect_identifiers)
                node_color = "#dc2626" if is_suspect else "#334155" 
                
                if tgt not in added_nodes:
                    nodes.append(Node(id=tgt, label=tgt, size=20, color=node_color, font={'color': 'white'}))
                    added_nodes.add(tgt)
                
                # FIX: length=350 to declutter the bank nodes
                edges.append(Edge(source=origin_id, target=tgt, color="#64748b", length=350))

    config = Config(
        width="100%", height=600, 
        directed=True, physics=True, hierarchical=False,
        nodeHighlightBehavior=True, highlightColor="#f59e0b",
        collapsible=False,
        interaction={"zoomView": False, "dragView": True, "dragNodes": True, "navigationButtons": True} 
    )
    
    return agraph(nodes=nodes, edges=edges, config=config)