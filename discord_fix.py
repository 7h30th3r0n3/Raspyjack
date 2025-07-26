# Discord Webhook Character Limit Fix
# Replace the send_to_discord function in raspyjack.py

def send_to_discord(scan_label: str, scan_results: str, target_network: str, interface: str):
    """Send Nmap scan results to Discord webhook."""
    webhook_url = get_discord_webhook()
    if not webhook_url:
        print("Discord webhook not configured - skipping webhook notification")
        return
    
    try:
        # Discord limits: embed field value = 1024 chars, total embed = 6000 chars
        # Use 1800 chars for results to show more meaningful content
        MAX_RESULTS_LENGTH = 1800
        
        # Truncate results intelligently - try to keep complete lines
        if len(scan_results) > MAX_RESULTS_LENGTH:
            # Find the last complete line within the limit
            truncated = scan_results[:MAX_RESULTS_LENGTH]
            last_newline = truncated.rfind('\n')
            if last_newline > MAX_RESULTS_LENGTH * 0.8:  # If we can find a good break point
                truncated = truncated[:last_newline]
            truncated += f"\n\n... (truncated - full results saved locally)"
        else:
            truncated = scan_results
        
        # Create Discord embed
        embed = {
            "title": f"🔍 Nmap Scan Complete: {scan_label}",
            "description": f"**Target Network:** `{target_network}`\n**Interface:** `{interface}`\n**Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "color": 0x00ff00,  # Green color
            "fields": [
                {
                    "name": "📊 Scan Results",
                    "value": f"```\n{truncated}\n```",
                    "inline": False
                }
            ],
            "footer": {
                "text": "RaspyJack Nmap Scanner"
            },
            "timestamp": datetime.now().isoformat()
        }
        
        # Prepare the payload
        payload = {
            "embeds": [embed]
        }
        
        # Send to Discord
        response = requests.post(webhook_url, json=payload, timeout=10)
        if response.status_code == 204:
            print("✅ Discord webhook sent successfully")
        else:
            print(f"❌ Discord webhook failed: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Error sending Discord webhook: {e}")

# Instructions:
# 1. Open raspyjack.py
# 2. Find the send_to_discord function (around line 957)
# 3. Replace the entire function with this updated version
# 4. Save the file
# 5. Restart RaspyJack

# The main changes:
# - Increased limit from 1000 to 1800 characters
# - Smart truncation at line boundaries
# - Better truncation message
# - More meaningful content in Discord notifications 