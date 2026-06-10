import streamlit as st
from core.export import generate_pdf_dossier
from core.auth import verify_credentials
from core.evidence import generate_sha256_hash
from core.ingestion import extract_table_from_pdf
from core.triage import extract_upi_nodes
from core.crypto_api import fetch_tron_wallet_data

st.set_page_config(page_title=" Kerala Police Crime Branch | Economic Offenses Wing [EOW]", layout="wide")

# Session State Gatekeeper
if 'authenticated' not in st.session_state:
    st.session_state['authenticated'] = False

if not st.session_state['authenticated']:
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.title("Financial Forensic Analyzer and Triage System")
        st.markdown("**Kerala Police | Restricted Access**")
        with st.form("login_form"):
            username = st.text_input("Officer ID")
            password = st.text_input("Passcode", type="password")
            submit = st.form_submit_button("Authenticate")
            if submit:
                if verify_credentials(username, password):
                    st.session_state['authenticated'] = True
                    st.rerun()
                else:
                    st.error("Access Denied.")
else:
    st.title("Project Vettah: Financial Forensic Analyzer")
    
    with st.sidebar:
        st.success("Active Investigator Session")
        if st.button("Secure Logout"):
            st.session_state['authenticated'] = False
            st.rerun()
        
        st.divider()
        bank_selection = st.selectbox("Target Format", ["SBI", "HDFC", "ICICI", "Axis Bank"])
        
        st.divider()
        st.header("Crypto Trace")
        suspect_wallet = st.text_input("USDT Address (TRC-20):", placeholder="e.g., TXYZ...")
        if st.button("Trace Asset"):
            with st.spinner("Querying TronGrid API..."):
                crypto_df = fetch_tron_wallet_data(suspect_wallet)
                if crypto_df is not None:
                    st.dataframe(crypto_df, use_container_width=True)
                else:
                    st.error("No data found or invalid wallet address.")

    st.header("Evidence Locker & Data Extraction")
    uploaded_files = st.file_uploader("Upload Bank Statements", type=['pdf'], accept_multiple_files=True)

    if uploaded_files:
        for file in uploaded_files:
            st.divider()
            st.subheader(f"Dossier: {file.name}")
            
            # Chain of Custody Hash
            file_bytes = file.read()
            st.caption(f"**SHA-256 Hash:** `{generate_sha256_hash(file_bytes)}`")
            file.seek(0)
            
            with st.spinner(f'Applying {bank_selection} schema...'):
                df = extract_table_from_pdf(file, bank_selection)
                if df is not None:
                    st.dataframe(df.head(10), use_container_width=True)
                    
                    st.markdown("### 🚨 Suspect Nodes Detected")
                    nodes_df = extract_upi_nodes(df)
                    if not nodes_df.empty:
                        if not nodes_df.empty:
                        st.dataframe(nodes_df, use_container_width=True)
                        
                        # Layout the download buttons side-by-side
                        col_csv, col_pdf = st.columns(2)
                        
                        with col_csv:
                            st.download_button(
                                "📥 Download Nodes (CSV)", 
                                data=nodes_df.to_csv(index=False).encode('utf-8'), 
                                file_name=f"nodes_{file.name}.csv", 
                                mime="text/csv"
                            )
                            
                        with col_pdf:
                            # Generate the official PDF Dossier
                            pdf_bytes = generate_pdf_dossier(file.name, file_hash, bank_selection, nodes_df, df)
                            st.download_button(
                                "📄 Export Court Dossier (PDF)", 
                                data=bytes(pdf_bytes), 
                                file_name=f"VETTAH_DOSSIER_{file.name}.pdf", 
                                mime="application/pdf"
                            )
                    else:
                        st.info("No suspect nodes detected.")
                else:
                    st.error("Extraction failed.")
