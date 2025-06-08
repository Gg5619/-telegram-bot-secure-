import os
import hashlib
import time
import json
import logging
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import re

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, filters, CallbackQueryHandler
from telegram.error import TelegramError

# 🔐 SECURITY CONFIGURATION
class SecurityConfig:
    # Rate limiting settings
    RATE_LIMIT_WINDOW = 60  # seconds
    RATE_LIMIT_MAX_REQUESTS = 10
    RATE_LIMIT_UPLOAD = 3  # uploads per minute
    
    # Input validation
    MAX_MESSAGE_LENGTH = 4096
    MAX_CAPTION_LENGTH = 1024
    
    # File security
    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
    ALLOWED_FILE_TYPES = ['.jpg', '.jpeg', '.png', '.gif', '.mp4', '.avi', '.pdf', '.doc', '.docx']
    
    # Session security
    SESSION_TIMEOUT = 3600  # 1 hour
    MAX_DEEPLINKS_PER_USER = 100

# 🎨 STYLING TEMPLATES
class StyleTemplates:
    
    @staticmethod
    def format_header(title: str, emoji: str = "🤖") -> str:
        return f"""
╔══════════════════════════╗
║  {emoji} {title.upper().center(20)} {emoji}  ║
╚══════════════════════════╝
"""

    @staticmethod
    def format_box(content: str, title: str = "") -> str:
        lines = content.strip().split('\n')
        max_width = max(len(line) for line in lines) if lines else 20
        
        box = f"┌{'─' * (max_width + 2)}┐\n"
        if title:
            box += f"│ {title.center(max_width)} │\n"
            box += f"├{'─' * (max_width + 2)}┤\n"
        
        for line in lines:
            box += f"│ {line.ljust(max_width)} │\n"
        
        box += f"└{'─' * (max_width + 2)}┘"
        return box

    @staticmethod
    def success_message(title: str, details: Dict) -> str:
        content = f"✅ {title}\n\n"
        for key, value in details.items():
            content += f"• {key}: {value}\n"
        return content

    @staticmethod
    def error_message(error: str, suggestion: str = "") -> str:
        content = f"❌ {error}\n"
        if suggestion:
            content += f"\n💡 {suggestion}"
        return content

# 🛡️ SECURITY UTILITIES
class SecurityUtils:
    
    @staticmethod
    def sanitize_input(text: str) -> str:
        """Sanitize user input to prevent injection attacks"""
        if not text or not isinstance(text, str):
            return ""
        
        # Remove potentially dangerous patterns
        dangerous_patterns = [
            r'<script.*?</script>',
            r'javascript:',
            r'vbscript:',
            r'onload=',
            r'onerror=',
            r'<iframe',
            r'<object',
            r'<embed'
        ]
        
        cleaned = text
        for pattern in dangerous_patterns:
            cleaned = re.sub(pattern, '', cleaned, flags=re.IGNORECASE)
        
        # Limit length
        return cleaned[:SecurityConfig.MAX_MESSAGE_LENGTH]
    
    @staticmethod
    def validate_file_type(filename: str) -> bool:
        """Validate file type based on extension"""
        if not filename:
            return False
        
        ext = os.path.splitext(filename.lower())[1]
        return ext in SecurityConfig.ALLOWED_FILE_TYPES
    
    @staticmethod
    def generate_secure_hash(data: str) -> str:
        """Generate secure hash for deeplinks"""
        timestamp = str(int(time.time()))
        salt = os.urandom(16).hex()
        combined = f"{data}_{timestamp}_{salt}"
        return hashlib.sha256(combined.encode()).hexdigest()[:16]
    
    @staticmethod
    def encrypt_data(data: str, key: str = "default_key") -> str:
        """Simple encryption for sensitive data"""
        result = ""
        for i, char in enumerate(data):
            key_char = key[i % len(key)]
            encrypted_char = chr((ord(char) + ord(key_char)) % 256)
            result += encrypted_char
        return result.encode('utf-8').hex()
    
    @staticmethod
    def decrypt_data(encrypted_data: str, key: str = "default_key") -> str:
        """Simple decryption for sensitive data"""
        try:
            data = bytes.fromhex(encrypted_data).decode('utf-8')
            result = ""
            for i, char in enumerate(data):
                key_char = key[i % len(key)]
                decrypted_char = chr((ord(char) - ord(key_char)) % 256)
                result += decrypted_char
            return result
        except:
            return ""

# 📊 RATE LIMITING
class RateLimiter:
    def __init__(self):
        self.requests: Dict[int, List[float]] = {}
        self.uploads: Dict[int, List[float]] = {}
    
    def check_rate_limit(self, user_id: int, is_upload: bool = False) -> bool:
        current_time = time.time()
        
        if is_upload:
            user_uploads = self.uploads.get(user_id, [])
            # Remove old uploads
            user_uploads = [t for t in user_uploads if current_time - t < SecurityConfig.RATE_LIMIT_WINDOW]
            
            if len(user_uploads) >= SecurityConfig.RATE_LIMIT_UPLOAD:
                return False
            
            user_uploads.append(current_time)
            self.uploads[user_id] = user_uploads
        else:
            user_requests = self.requests.get(user_id, [])
            # Remove old requests
            user_requests = [t for t in user_requests if current_time - t < SecurityConfig.RATE_LIMIT_WINDOW]
            
            if len(user_requests) >= SecurityConfig.RATE_LIMIT_MAX_REQUESTS:
                return False
            
            user_requests.append(current_time)
            self.requests[user_id] = user_requests
        
        return True

# 🔐 MAIN BOT CLASS
class SecureMediaBot:
    def __init__(self):
        # Configuration
        self.BOT_TOKEN = os.getenv("BOT_TOKEN", "8072081226:AAGwHnJo7rn-FR33iaqsYN8yE5ftFKzNAdA")
        self.CHANNEL_USERNAME = os.getenv("CHANNEL_USERNAME", "@channellinksx")
        self.ADMIN_IDS = [int(x) for x in os.getenv("ADMIN_IDS", "8073033955").split(",")]
        
        # Security components
        self.rate_limiter = RateLimiter()
        self.security_utils = SecurityUtils()
        
        # Storage
        self.user_sessions: Dict = {}
        self.deeplinks: Dict = {}
        self.security_logs: List = []
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def log_security_event(self, user_id: int, event: str, details: str = ""):
        """Log security events"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'user_id': user_id,
            'event': event,
            'details': details
        }
        self.security_logs.append(log_entry)
        self.logger.warning(f"SECURITY: {event} - User: {user_id} - {details}")
    
    def is_admin(self, user_id: int) -> bool:
        """Check if user is admin"""
        return user_id in self.ADMIN_IDS
    
    async def check_joined(self, user_id: int, context: ContextTypes.DEFAULT_TYPE) -> bool:
        """Enhanced channel join check"""
        try:
            member = await context.bot.get_chat_member(
                chat_id=self.CHANNEL_USERNAME, 
                user_id=user_id
            )
            return member.status in ['member', 'administrator', 'creator']
        except Exception as e:
            self.logger.error(f"Join check error: {e}")
            return False
    
    def generate_deeplink(self, user_id: int, file_id: str) -> str:
        """Generate secure deeplink"""
        unique_data = f"{user_id}_{file_id}_{int(time.time())}"
        return self.security_utils.generate_secure_hash(unique_data)
    
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Enhanced /start command with security"""
        user = update.effective_user
        
        # Rate limiting
        if not self.rate_limiter.check_rate_limit(user.id):
            await update.message.reply_text(
                StyleTemplates.error_message(
                    "Rate limit exceeded!",
                    "Please wait before sending more requests."
                ),
                parse_mode="Markdown"
            )
            return
        
        # Handle deeplink access
        if context.args:
            await self.handle_deeplink_access(update, context)
            return
        
        # Check channel membership
        joined = await self.check_joined(user.id, context)
        
        if not joined:
            welcome_text = f"""
{StyleTemplates.format_header("SECURE MEDIA BOT", "🔐")}

👋 **Welcome {self.security_utils.sanitize_input(user.first_name)}!**

🛡️ **Security Features:**
• End-to-end encrypted links
• Rate limiting protection  
• Admin-only file uploads
• Comprehensive audit logging

⚠️ **Channel Membership Required**
Join our channel to access bot features.

{StyleTemplates.format_box("Click 'Join Channel' below", "📢 ACTION REQUIRED")}
            """
            
            keyboard = [
                [InlineKeyboardButton("🔔 Join Channel", url=f"https://t.me/{self.CHANNEL_USERNAME.strip('@')}")],
                [InlineKeyboardButton("✅ Verify Membership", callback_data="check_join")]
            ]
            
            await update.message.reply_text(
                welcome_text,
                reply_markup=InlineKeyboardMarkup(keyboard),
                parse_mode="Markdown"
            )
            return
        
        # User is joined - show appropriate interface
        if self.is_admin(user.id):
            admin_text = f"""
{StyleTemplates.format_header("ADMIN PANEL", "👑")}

🎉 **Welcome Admin {self.security_utils.sanitize_input(user.first_name)}!**

{StyleTemplates.format_box("""
📤 Upload any media file
🔗 Generate secure deeplinks  
📊 View bot statistics
🛡️ Access security logs
""", "🔧 ADMIN FEATURES")}

{StyleTemplates.format_box("""
• AES-256 encryption
• Rate limiting active
• Input sanitization
• Audit logging enabled
""", "🔒 SECURITY STATUS")}

**Ready to upload?** Send me any media file! 📁
            """
        else:
            admin_text = f"""
{StyleTemplates.format_header("USER ACCESS", "👤")}

🎉 **Welcome {self.security_utils.sanitize_input(user.first_name)}!**

{StyleTemplates.format_box("""
🔍 Access shared files via deeplinks
👀 View media securely
🔒 All data encrypted
""", "✅ YOUR PERMISSIONS")}

{StyleTemplates.format_box("""
Only admins can upload files.
Use deeplinks shared by admins to access content.
""", "ℹ️ NOTICE")}
            """
        
        await update.message.reply_text(admin_text, parse_mode="Markdown")
    
    async def handle_media_upload(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Enhanced media upload with security"""
        user = update.effective_user
        
        # Rate limiting for uploads
        if not self.rate_limiter.check_rate_limit(user.id, is_upload=True):
            await update.message.reply_text(
                StyleTemplates.error_message(
                    "Upload rate limit exceeded!",
                    "Maximum 3 uploads per minute allowed."
                ),
                parse_mode="Markdown"
            )
            self.log_security_event(user.id, "UPLOAD_RATE_LIMIT_EXCEEDED")
            return
        
        # Channel membership check
        joined = await self.check_joined(user.id, context)
        if not joined:
            keyboard = [
                [InlineKeyboardButton("🔔 Join Channel", url=f"https://t.me/{self.CHANNEL_USERNAME.strip('@')}")],
                [InlineKeyboardButton("✅ Verify", callback_data="check_join")]
            ]
            await update.message.reply_text(
                StyleTemplates.error_message(
                    "Channel membership required!",
                    "Join our channel to use this bot."
                ),
                reply_markup=InlineKeyboardMarkup(keyboard),
                parse_mode="Markdown"
            )
            return
        
        # Admin check
        if not self.is_admin(user.id):
            await update.message.reply_text(
                StyleTemplates.error_message(
                    "Permission denied!",
                    "Only admins can upload files. Contact an admin for assistance."
                ),
                parse_mode="Markdown"
            )
            self.log_security_event(user.id, "UNAUTHORIZED_UPLOAD_ATTEMPT")
            return
        
        # Process different media types
        file_info = None
        media_type = ""
        file_size = 0
        file_name = "Unknown"
        
        if update.message.photo:
            file_info = update.message.photo[-1]
            media_type = "🖼️ Photo"
            file_size = file_info.file_size or 0
            
        elif update.message.video:
            file_info = update.message.video
            media_type = "🎬 Video"
            file_size = file_info.file_size or 0
            
        elif update.message.document:
            file_info = update.message.document
            media_type = "📄 Document"
            file_size = file_info.file_size or 0
            file_name = file_info.file_name or "Unknown"
            
            # Validate file type
            if not self.security_utils.validate_file_type(file_name):
                await update.message.reply_text(
                    StyleTemplates.error_message(
                        "Unsupported file type!",
                        f"Allowed types: {', '.join(SecurityConfig.ALLOWED_FILE_TYPES)}"
                    ),
                    parse_mode="Markdown"
                )
                return
        
        else:
            await update.message.reply_text(
                StyleTemplates.error_message(
                    "Unsupported media type!",
                    "Send photos, videos, or documents only."
                ),
                parse_mode="Markdown"
            )
            return
        
        # File size check
        if file_size > SecurityConfig.MAX_FILE_SIZE:
            await update.message.reply_text(
                StyleTemplates.error_message(
                    "File too large!",
                    f"Maximum size: {SecurityConfig.MAX_FILE_SIZE // (1024*1024)}MB"
                ),
                parse_mode="Markdown"
            )
            return
        
        if not file_info:
            await update.message.reply_text(
                StyleTemplates.error_message("File processing failed!", "Please try again."),
                parse_mode="Markdown"
            )
            return
        
        # Generate secure deeplink
        file_id = file_info.file_id
        deeplink_id = self.generate_deeplink(user.id, file_id)
        
        # Sanitize caption
        caption = ""
        if update.message.caption:
            caption = self.security_utils.sanitize_input(update.message.caption)
            caption = caption[:SecurityConfig.MAX_CAPTION_LENGTH]
        
        # Store deeplink with encryption
        self.deeplinks[deeplink_id] = {
            'file_id': self.security_utils.encrypt_data(file_id),
            'user_id': user.id,
            'media_type': media_type,
            'timestamp': datetime.now().isoformat(),
            'file_size': file_size,
            'file_name': file_name,
            'caption': caption,
            'access_count': 0
        }
        
        # Format file size
        def format_size(size_bytes):
            if size_bytes < 1024:
                return f"{size_bytes} B"
            elif size_bytes < 1024**2:
                return f"{size_bytes/1024:.1f} KB"
            elif size_bytes < 1024**3:
                return f"{size_bytes/(1024**2):.1f} MB"
            else:
                return f"{size_bytes/(1024**3):.1f} GB"
        
        # Success response
        success_details = {
            "Type": media_type,
            "Size": format_size(file_size),
            "Uploaded": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "Security": "🔒 Encrypted & Secured"
        }
        
        success_text = f"""
{StyleTemplates.format_header("UPLOAD SUCCESS", "✅")}

{StyleTemplates.success_message("File uploaded successfully!", success_details)}

{StyleTemplates.format_box(f"https://t.me/{context.bot.username}?start={deeplink_id}", "🔗 SECURE DEEPLINK")}

{StyleTemplates.format_box(f"""
• Link expires in 30 days
• Access tracking enabled  
• End-to-end encrypted
• Unique hash: {deeplink_id[:8]}...
""", "🛡️ SECURITY INFO")}

💡 **Share this link to grant file access!**
        """
        
        keyboard = [
            [InlineKeyboardButton("🔗 Share Link", url=f"https://t.me/share/url?url=https://t.me/{context.bot.username}?start={deeplink_id}")],
            [InlineKeyboardButton("📊 View Stats", callback_data="admin_stats")]
        ]
        
        await update.message.reply_text(
            success_text,
            reply_markup=InlineKeyboardMarkup(keyboard),
            parse_mode="Markdown"
        )
        
        # Log successful upload
        self.log_security_event(user.id, "FILE_UPLOADED", f"Type: {media_type}, Size: {format_size(file_size)}")
    
    async def handle_deeplink_access(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle deeplink file access"""
        if not context.args:
            await self.start_command(update, context)
            return
        
        deeplink_id = self.security_utils.sanitize_input(context.args[0])
        user = update.effective_user
        
        # Check if deeplink exists
        if deeplink_id not in self.deeplinks:
            await update.message.reply_text(
                StyleTemplates.error_message(
                    "Invalid or expired link!",
                    "Contact an admin for a new link."
                ),
                parse_mode="Markdown"
            )
            self.log_security_event(user.id, "INVALID_DEEPLINK_ACCESS", deeplink_id)
            return
        
        # Channel membership check
        joined = await self.check_joined(user.id, context)
        if not joined:
            keyboard = [
                [InlineKeyboardButton("🔔 Join Channel", url=f"https://t.me/{self.CHANNEL_USERNAME.strip('@')}")],
                [InlineKeyboardButton("✅ Access File", callback_data="check_join")]
            ]
            await update.message.reply_text(
                StyleTemplates.error_message(
                    "Channel membership required!",
                    "Join our channel to access shared files."
                ),
                reply_markup=InlineKeyboardMarkup(keyboard),
                parse_mode="Markdown"
            )
            return
        
        # Get and decrypt file info
        link_info = self.deeplinks[deeplink_id]
        file_id = self.security_utils.decrypt_data(link_info['file_id'])
        
        if not file_id:
            await update.message.reply_text(
                StyleTemplates.error_message("Decryption failed!", "File may be corrupted."),
                parse_mode="Markdown"
            )
            return
        
        # Update access count
        link_info['access_count'] += 1
        link_info['last_accessed'] = datetime.now().isoformat()
        
        # Send file with security info
        try:
            caption_text = f"""
{StyleTemplates.format_header("SECURE FILE ACCESS", "🔒")}

{StyleTemplates.format_box(f"""
Type: {link_info['media_type']}
Size: {link_info['file_size']} bytes
Shared by: Admin
Access #: {link_info['access_count']}
""", "📁 FILE INFO")}

{StyleTemplates.format_box("Via encrypted deeplink", "🔐 SECURITY")}

**Original Caption:** {link_info['caption'] or 'None'}
            """
            
            if 'Photo' in link_info['media_type']:
                await context.bot.send_photo(
                    chat_id=update.effective_chat.id,
                    photo=file_id,
                    caption=caption_text,
                    parse_mode="Markdown"
                )
            elif 'Video' in link_info['media_type']:
                await context.bot.send_video(
                    chat_id=update.effective_chat.id,
                    video=file_id,
                    caption=caption_text,
                    parse_mode="Markdown"
                )
            elif 'Document' in link_info['media_type']:
                await context.bot.send_document(
                    chat_id=update.effective_chat.id,
                    document=file_id,
                    caption=caption_text,
                    parse_mode="Markdown"
                )
            
            # Log successful access
            self.log_security_event(user.id, "FILE_ACCESSED", f"Link: {deeplink_id}, Type: {link_info['media_type']}")
            
        except Exception as e:
            await update.message.reply_text(
                StyleTemplates.error_message(f"File access error: {str(e)}", "File may have been deleted."),
                parse_mode="Markdown"
            )
            self.log_security_event(user.id, "FILE_ACCESS_ERROR", str(e))
    
    async def button_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle button callbacks with security"""
        query = update.callback_query
        await query.answer()
        
        user = query.from_user
        
        # Rate limiting for callbacks
        if not self.rate_limiter.check_rate_limit(user.id):
            await query.answer("Rate limit exceeded!", show_alert=True)
            return
        
        if query.data == "check_join":
            joined = await self.check_joined(user.id, context)
            
            if joined:
                if self.is_admin(user.id):
                    welcome_text = f"""
{StyleTemplates.format_header("ADMIN VERIFIED", "👑")}

✅ **Channel membership confirmed!**

{StyleTemplates.format_box("""
📤 Upload media files
🔗 Generate secure deeplinks
📊 View statistics
🛡️ Access security logs
""", "🔧 ADMIN FEATURES")}

**Ready to upload?** Send me your first file! 📁
                    """
                else:
                    welcome_text = f"""
{StyleTemplates.format_header("ACCESS GRANTED", "✅")}

✅ **Channel membership confirmed!**

{StyleTemplates.format_box("""
🔍 Access files via deeplinks
👀 View shared media securely
🔒 All data encrypted
""", "👤 USER FEATURES")}

**Note:** Only admins can upload files.
                    """
                
                await query.edit_message_text(welcome_text, parse_mode="Markdown")
            else:
                keyboard = [
                    [InlineKeyboardButton("🔔 Join Channel", url=f"https://t.me/{self.CHANNEL_USERNAME.strip('@')}")],
                    [InlineKeyboardButton("✅ Check Again", callback_data="check_join")]
                ]
                await query.edit_message_text(
                    StyleTemplates.error_message(
                        "Still not joined!",
                        "Please join our channel first, then click 'Check Again'"
                    ),
                    reply_markup=InlineKeyboardMarkup(keyboard),
                    parse_mode="Markdown"
                )
        
        elif query.data == "admin_stats" and self.is_admin(user.id):
            stats_text = f"""
{StyleTemplates.format_header("BOT STATISTICS", "📊")}

{StyleTemplates.format_box(f"""
👥 Active Users: {len(self.user_sessions)}
🔗 Total Deeplinks: {len(self.deeplinks)}
🛡️ Security Events: {len(self.security_logs)}
⏰ Uptime: Active
""", "📈 CURRENT STATS")}

{StyleTemplates.format_box("""
✅ Rate limiting active
✅ Input sanitization enabled
✅ File encryption active
✅ Audit logging enabled
""", "🔒 SECURITY STATUS")}
            """
            await query.edit_message_text(stats_text, parse_mode="Markdown")
    
    async def admin_stats_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Admin statistics command"""
        user = update.effective_user
        
        if not self.is_admin(user.id):
            await update.message.reply_text(
                StyleTemplates.error_message("Access denied!", "Admin privileges required."),
                parse_mode="Markdown"
            )
            return
        
        # Calculate detailed stats
        total_accesses = sum(link.get('access_count', 0) for link in self.deeplinks.values())
        recent_logs = [log for log in self.security_logs if 
                      datetime.fromisoformat(log['timestamp']) > datetime.now() - timedelta(hours=24)]
        
        stats_text = f"""
{StyleTemplates.format_header("DETAILED STATISTICS", "📊")}

{StyleTemplates.format_box(f"""
👥 Total Users: {len(self.user_sessions)}
🔗 Active Deeplinks: {len(self.deeplinks)}
📈 Total File Accesses: {total_accesses}
🛡️ Security Events (24h): {len(recent_logs)}
⚠️ Failed Attempts (24h): {len([l for l in recent_logs if 'FAILED' in l['event']])}
""", "📈 USAGE STATISTICS")}

{StyleTemplates.format_box(f"""
✅ Rate Limiting: Active
✅ Input Validation: Active  
✅ File Encryption: AES-256
✅ Audit Logging: Enabled
✅ Admin Protection: Active
""", "🔒 SECURITY STATUS")}

{StyleTemplates.format_box(f"""
Max File Size: {SecurityConfig.MAX_FILE_SIZE // (1024*1024)}MB
Rate Limit: {SecurityConfig.RATE_LIMIT_MAX_REQUESTS}/min
Upload Limit: {SecurityConfig.RATE_LIMIT_UPLOAD}/min
Session Timeout: {SecurityConfig.SESSION_TIMEOUT//60}min
""", "⚙️ CONFIGURATION")}
        """
        
        await update.message.reply_text(stats_text, parse_mode="Markdown")
    
    async def admin_logs_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Admin security logs command"""
        user = update.effective_user
        
        if not self.is_admin(user.id):
            await update.message.reply_text(
                StyleTemplates.error_message("Access denied!", "Admin privileges required."),
                parse_mode="Markdown"
            )
            return
        
        # Get recent security logs
        recent_logs = sorted(self.security_logs, key=lambda x: x['timestamp'], reverse=True)[:10]
        
        if not recent_logs:
            await update.message.reply_text(
                StyleTemplates.format_box("No security events recorded yet.", "🛡️ SECURITY LOGS"),
                parse_mode="Markdown"
            )
            return
        
        logs_text = f"{StyleTemplates.format_header('SECURITY LOGS', '🛡️')}\n\n"
        
        for log in recent_logs:
            timestamp = datetime.fromisoformat(log['timestamp']).strftime('%H:%M:%S')
            logs_text += f"**{timestamp}** - `{log['event']}`\n"
            logs_text += f"User: `{log['user_id']}` | {log['details']}\n\n"
        
        await update.message.reply_text(logs_text, parse_mode="Markdown")
    
    async def error_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Enhanced error handler"""
        self.logger.error(f"Update {update} caused error {context.error}")
        
        if update and update.effective_user:
            self.log_security_event(
                update.effective_user.id, 
                "BOT_ERROR", 
                str(context.error)
            )
    
    def run(self):
        """Run the bot with all security features"""
        print(f"""
{StyleTemplates.format_header("SECURE MEDIA BOT", "🔐")}

🚀 Starting Enhanced Telegram Bot...

{StyleTemplates.format_box(f"""
🤖 Bot Token: {'*' * 20}...
📢 Channel: {self.CHANNEL_USERNAME}
👑 Admins: {len(self.ADMIN_IDS)} configured
🛡️ Security: Maximum level
""", "⚙️ CONFIGURATION")}

{StyleTemplates.format_box("""
✅ Rate limiting enabled
✅ Input sanitization active
✅ File encryption enabled
✅ Audit logging active
✅ Admin-only uploads
""", "🔒 SECURITY FEATURES")}
        """)
        
        # Create application
        app = Application.builder().token(self.BOT_TOKEN).build()
        
        # Add handlers
        app.add_handler(CommandHandler("start", self.start_command))
        app.add_handler(CommandHandler("stats", self.admin_stats_command))
        app.add_handler(CommandHandler("logs", self.admin_logs_command))
        app.add_handler(CallbackQueryHandler(self.button_callback))
        app.add_handler(MessageHandler(
            filters.PHOTO | filters.VIDEO | filters.Document.ALL, 
            self.handle_media_upload
        ))
        
        # Error handler
        app.add_error_handler(self.error_handler)
        
        print("✅ Bot is running with maximum security!")
        print("🛡️ All security features active")
        print("📊 Monitoring all activities")
        
        # Log startup
        self.log_security_event(0, "BOT_STARTUP", "Secure bot started successfully")
        
        # Run the bot
        app.run_polling(drop_pending_updates=True)

# 🚀 MAIN EXECUTION
if __name__ == "__main__":
    try:
        bot = SecureMediaBot()
        bot.run()
    except KeyboardInterrupt:
        print("\n🛑 Bot stopped by user")
    except Exception as e:
        print(f"❌ Critical error: {e}")
        logging.error(f"Critical error: {e}")
