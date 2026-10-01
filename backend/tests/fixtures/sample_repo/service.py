def handle_payment(payload):
    try:
        process_token(payload)
    except Exception:
        pass

def fetch_user(user_id):
    try:
        return db_query(user_id)
    except:
        print("User query failed")
