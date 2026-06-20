def verify_credentials(username, password):
    """
    Validates investigator access.
    In a real Cyberdome production environment, this would hook into 
    an LDAP or Active Directory secure database.
    """
    # Hardcoded test credentials for the MVP presentation
    valid_username = "admin"
    valid_password = "cyberdome2026"
    
    if username == valid_username and password == valid_password:
        return True
    return False