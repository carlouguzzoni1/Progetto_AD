def send_activity_heartbeat(conn, token):
    """
    Sends an heartbeat to the name server to indicate that the entity is still
    active.
    Args:
        conn (rpyc.Connection): The connection to the name server.
        token (str):            The entity's JWT token.
    """
    
    try:
        conn.root.receive_activity_heartbeat(token)
        
    except Exception as e:
        print("Error sending heartbeat:", e)
