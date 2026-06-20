import pandas as pd
import pdfplumber
import re

def extract_table_from_pdf(file_obj, bank_type="SBI"):
    """
    Hunts for raw text lines that look like transactions instead of relying on fragile table borders.
    """
    try:
        all_transactions = []
        
        # Regex to find standard Indian date formats at the start of a string
        date_pattern = re.compile(r'^(\d{1,2}[/-]\w{3,4}[/-]\d{2,4}|\d{1,2}[/-]\d{1,2}[/-]\d{2,4})')
        
        with pdfplumber.open(file_obj) as pdf:
            for page in pdf.pages:
                raw_text = page.extract_text()
                if not raw_text:
                    continue
                    
                lines = raw_text.split('\n')
                for line in lines:
                    line = line.strip()
                    # Check if the line starts with a date
                    match = date_pattern.match(line)
                    if match:
                        date_str = match.group(1)
                        # Remove the date from the string
                        remaining_line = line[len(date_str):].strip()
                        
                        # Look for currency figures (e.g., 1,500.00 or 500)
                        # We search from the back of the string
                        amount_matches = re.findall(r'\b\d{1,3}(?:,\d{3})*(?:\.\d{2})?\b', remaining_line)
                        
                        amount = "0.00"
                        if amount_matches:
                            # Take the last currency-looking figure as the amount
                            # and ensure it's not a 12 digit transaction ID
                            valid_amounts = [amt for amt in amount_matches if len(amt.replace(',', '').split('.')[0]) < 9]
                            if valid_amounts:
                                amount = valid_amounts[-1]
                                
                        all_transactions.append({
                            "Date": date_str,
                            "Description": remaining_line,
                            "Debit": amount
                        })

        if not all_transactions:
            return None

        return pd.DataFrame(all_transactions)
    except Exception as e:
        print(f"Extraction Error: {e}")
        return None