#!/usr/bin/env python3
"""
Discord Webhook Character Limit Fix
==================================
This script automatically applies the fix to increase Discord webhook character limit
from 1000 to 1800 characters in raspyjack.py
"""

import re
import os
import shutil
from datetime import datetime

def apply_discord_fix():
    """Apply the Discord webhook character limit fix to raspyjack.py"""
    
    raspyjack_file = "raspyjack.py"
    
    # Check if raspyjack.py exists
    if not os.path.exists(raspyjack_file):
        print(f"❌ Error: {raspyjack_file} not found!")
        return False
    
    # Create backup
    backup_file = f"raspyjack_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.py"
    shutil.copy2(raspyjack_file, backup_file)
    print(f"✅ Created backup: {backup_file}")
    
    # Read the current file
    with open(raspyjack_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Define the old and new patterns
    old_pattern = r'def send_to_discord\(scan_label: str, scan_results: str, target_network: str, interface: str\):\s*"""[^"]*""".*?except Exception as e:\s*print\(f"❌ Error sending Discord webhook: \{e\}"\)'
    
    new_function = '''def send_to_discord(scan_label: str, scan_results: str, target_network: str, interface: str):
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
            last_newline = truncated.rfind('\\n')
            if last_newline > MAX_RESULTS_LENGTH * 0.8:  # If we can find a good break point
                truncated = truncated[:last_newline]
            truncated += f"\\n\\n... (truncated - full results saved locally)"
        else:
            truncated = scan_results
        
        # Create Discord embed
        embed = {
            "title": f"🔍 Nmap Scan Complete: {scan_label}",
            "description": f"**Target Network:** `{target_network}`\\n**Interface:** `{interface}`\\n**Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "color": 0x00ff00,  # Green color
            "fields": [
                {
                    "name": "📊 Scan Results",
                    "value": f"```\\n{truncated}\\n```",
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
        print(f"❌ Error sending Discord webhook: {e}")'''
    
    # Try to replace using regex
    if re.search(old_pattern, content, re.DOTALL):
        new_content = re.sub(old_pattern, new_function, content, flags=re.DOTALL)
        
        # Write the updated content
        with open(raspyjack_file, 'w', encoding='utf-8') as f:
            f.write(new_content)
        
        print("✅ Discord webhook fix applied successfully!")
        print("📝 Changes made:")
        print("   - Increased character limit from 1000 to 1800")
        print("   - Added smart truncation at line boundaries")
        print("   - Improved truncation message")
        print("   - More meaningful content in Discord notifications")
        print("\n🔄 Please restart RaspyJack to apply the changes!")
        return True
    
    else:
        # Fallback: simple string replacement
        old_line = '                    "value": f"```\\n{scan_results[:1000]}{\'...\' if len(scan_results) > 1000 else \'\'}\\n```",'
        new_line = '''                    "value": f"```\\n{truncated}\\n```",'''
        
        if old_line in content:
            # First, add the truncation logic before the embed creation
            content = content.replace(
                '        # Create Discord embed',
                '''        # Discord limits: embed field value = 1024 chars, total embed = 6000 chars
        # Use 1800 chars for results to show more meaningful content
        MAX_RESULTS_LENGTH = 1800
        
        # Truncate results intelligently - try to keep complete lines
        if len(scan_results) > MAX_RESULTS_LENGTH:
            # Find the last complete line within the limit
            truncated = scan_results[:MAX_RESULTS_LENGTH]
            last_newline = truncated.rfind('\\n')
            if last_newline > MAX_RESULTS_LENGTH * 0.8:  # If we can find a good break point
                truncated = truncated[:last_newline]
            truncated += f"\\n\\n... (truncated - full results saved locally)"
        else:
            truncated = scan_results
        
        # Create Discord embed'''
            )
            
            # Then replace the value line
            content = content.replace(old_line, new_line)
            
            # Write the updated content
            with open(raspyjack_file, 'w', encoding='utf-8') as f:
                f.write(content)
            
            print("✅ Discord webhook fix applied successfully!")
            print("📝 Changes made:")
            print("   - Increased character limit from 1000 to 1800")
            print("   - Added smart truncation at line boundaries")
            print("   - Improved truncation message")
            print("   - More meaningful content in Discord notifications")
            print("\n🔄 Please restart RaspyJack to apply the changes!")
            return True
        else:
            print("❌ Could not find the target line to replace!")
            print("   Please apply the fix manually using the discord_fix.py file")
            return False

if __name__ == "__main__":
    print("🔧 Discord Webhook Character Limit Fix")
    print("=" * 40)
    apply_discord_fix() 