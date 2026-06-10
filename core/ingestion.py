import pdfplumber
import pandas as pd
from templates.bank_schemas import BANK_SCHEMAS

def extract_table_from_pdf(uploaded_file, bank_name):
    """
    Scrapes tabular data from a PDF file dynamically using the selected bank's schema.
    """
    # Pull the exact bounding box rules for the selected bank
    template = BANK_SCHEMAS.get(bank_name, BANK_SCHEMAS["SBI"])
    all_data = []
    
    with pdfplumber.open(uploaded_file) as pdf:
        for page in pdf.pages:
            table = page.extract_table(table_settings=template["table_settings"])
            
            if table and len(table) > 1:
                df_page = pd.DataFrame(table[1:], columns=table[0])
                all_data.append(df_page)
                
    if not all_data:
        return None

    # Combine and clean
    final_df = pd.concat(all_data, ignore_index=True)
    final_df = final_df.dropna(subset=[final_df.columns[0]])
    
    return final_df