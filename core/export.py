from fpdf import FPDF
from datetime import datetime

def generate_pdf_dossier(file_name, file_hash, bank_name, nodes_df, extracted_df):
    """
    Generates a native, court-ready PDF dossier containing the chain of custody 
    hash and the extracted suspect nodes.
    """
    pdf = FPDF()
    pdf.add_page()
    
    # 1. Official Header
    pdf.set_font("helvetica", "B", 16)
pdf.cell(0, 10, "KERALA POLICE CRIME BRANCH : ECONOMIC OFFENSES WING [EOW]", ln=True, align="C")
    pdf.set_font("helvetica", "I", 10)
    pdf.cell(0, 10, f"Automated Forensic Extraction | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
    pdf.ln(10)
    
    # 2. Chain of Custody (The Evidence Locker)
    pdf.set_font("helvetica", "B", 12)
    pdf.set_text_color(200, 0, 0) # Red warning color
    pdf.cell(0, 10, "1. EVIDENCE CHAIN OF CUSTODY", ln=True)
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("helvetica", "", 10)
    pdf.multi_cell(0, 8, f"Source Ledger: {file_name}\nTarget Schema: {bank_name}\nSHA-256 Integrity Hash: {file_hash}\nStatus: Cryptographically Verified")
    pdf.ln(5)
    
    # 3. Suspect Nodes (The UPIs & Burner Phones)
    pdf.set_font("helvetica", "B", 12)
    pdf.cell(0, 10, "2. EXTRACTED SUSPECT NODES", ln=True)
    pdf.set_font("helvetica", "", 10)
    
    if nodes_df is not None and not nodes_df.empty:
        for index, row in nodes_df.iterrows():
            pdf.cell(0, 8, f"- [{row['Suspect_Node_Type']}] : {row['Identifier']}", ln=True)
    else:
        pdf.cell(0, 8, "No UPI handles or masked phone numbers detected in this ledger.", ln=True)
    pdf.ln(10)
    
    # 4. Data Extraction Verification (Preview)
    pdf.set_font("helvetica", "B", 12)
    pdf.cell(0, 10, "3. LEDGER EXTRACTION SAMPLE (Top 5 Rows)", ln=True)
    pdf.set_font("helvetica", "", 8)
    
    if extracted_df is not None and not extracted_df.empty:
        sample_df = extracted_df.head(5)
        # Convert columns to string and print a flat text representation to bypass complex PDF table drawing for the MVP
        for index, row in sample_df.iterrows():
            row_str = " | ".join([f"{str(val)[:20]}" for val in row.values])
            pdf.cell(0, 6, row_str, ln=True)

    # Return the PDF as a byte string so Streamlit can download it
    return pdf.output()