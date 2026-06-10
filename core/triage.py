import pandas as pd
import re

def extract_upi_nodes(df):
    """
    Scans the DataFrame's Description column for UPI handles and masked phone numbers.
    """
    upi_pattern = r'[\w\.-]+@[\w\.-]+'
    masked_phone_pattern = r'[X]{3,}\d{3,}'
    
    # Fallback to 2nd column if 'Description' isn't explicitly named
    desc_col = 'Description' if 'Description' in df.columns else df.columns[1]
    
    upi_ids = df[desc_col].astype(str).str.findall(upi_pattern)
    masked_phones = df[desc_col].astype(str).str.findall(masked_phone_pattern)
    
    unique_upis = pd.Series([item for sublist in upi_ids for item in sublist]).unique()
    unique_phones = pd.Series([item for sublist in masked_phones for item in sublist]).unique()
    
    return pd.DataFrame({
        "Suspect_Node_Type": ["UPI"] * len(unique_upis) + ["Masked Phone"] * len(unique_phones),
        "Identifier": list(unique_upis) + list(unique_phones)
    })