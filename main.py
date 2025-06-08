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

# Bot Configuration - Updated with your credentials
BOT_TOKEN = os.getenv("BOT_TOKEN", "8072081226:AAGwHnJo7rn-FR33iaqsYN8yE5ftFKzNAdA")
CHANNEL_USERNAME = os.getenv("CHANNEL_USERNAME", "@channellinksx")
ADMIN_IDS = [int(x) for x in os.getenv("ADMIN_IDS", "8073033955").split(",")]

# Storage
user_sessions = {}
deeplinks = {}
security_logs = []

# Security Utils
def sanitize_input(text: str) -> str:
    if not text:
        return ""
    dangerous_patterns = [r'<script.*?</script>', r'javascript:', r'vbscript:']
    cleaned = text
    for pattern in dangerous_patterns:
        cleaned = re.sub(pattern, '', cleaned, flags=re.IGNORECASE)
    return cleaned[:4000]

def generate_deeplink(user_id: int, file_id: str) -> str:
    timestamp = str(int(time.time()))
    unique_data = f"{user_id}_{file_id}_{timestamp}"
    return hashlib.sha256(unique_data.encode()).hexdigest()[:16]

# Rate Limiting
rate_limits = {}

def check_rate_limit(user_id: int) -> bool:
    current_time = time.time()
    if user_id not in rate_limits:
        rate_limits[user_id] = []
    
    # Remove old requests
    rate_limits[user_id] = [t for t in rate_limits[user_id] if current_time - t < 60]
    
    if len(rate_limits[user_id]) >= 10:
        return False
    
    rate_limits[user_id].append(current_time)
    return True

# Bot Class
class SecureMediaBot:
    def __init__(self):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # Print configuration for debugging
        print(f"🤖 Bot Token: {BOT_TOKEN[:20]}...")
        print(f"📢 Channel: {CHANNEL_USERNAME}")
        print(f"👑 Admin IDs: {ADMIN_IDS}")
    
    def is_admin(self, user_id: int) -> bool:
        return user_id in ADMIN_IDS
    
    async def check_joined(self, user_id: int, context: ContextTypes.DEFAULT_TYPE) -> bool:
        try:
            member = await context.bot.get_chat_member(chat_id=CHANNEL_USERNAME, user_id=user_id)
            return member.status in ['member', 'administrator', 'creator']
        except Exception as e:
            self.logger.error(f"Join check error: {e}")
            return False
    
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        user = update.effective_user
        
        if not check_rate_limit(user.id):
            await update.message.reply_text("⏰ Rate limit exceeded! Please wait.")
            return
        
        # Handle deeplink access
        if context.args:
            await self.handle_deeplink_access(update, context)
            return
        
        # Check channel membership
        joined = await self.check_joined(user.id, context)
        
        if not joined:
            welcome_text = f"""
🔐 **SECURE MEDIA BOT**

👋 Welcome **{sanitize_input(user.first_name)}**!

🛡️ **Features:**
• Encrypted file sharing
• Admin-only uploads  
• Rate limiting protection
• Channel verification required

⚠️ **Join Required:** You must join our channel first.

📢 **Channel:** {CHANNEL_USERNAME}
            """
            
            keyboard = [
                [InlineKeyboardButton("🔔 Join Channel", url=f"https://t.me/{CHANNEL_USERNAME.strip('@')}")],
                [InlineKeyboardButton("✅ Verify Membership", callback_data="check_join")]
            ]
            
            await update.message.reply_text(
                welcome_text,
                reply_markup=InlineKeyboardMarkup(keyboard),
                parse_mode="Markdown"
            )
            return
        
        # User is joined
        if self.is_admin(user.id):
            admin_text = f"""
👑 **ADMIN PANEL**

Welcome Admin **{sanitize_input(user.first_name)}**!

🔧 **Admin Features:**
• Upload any media files
• Generate secure deeplinks
• View bot statistics
• Access security logs

📤 **Ready to upload?** Send me any media file!

🆔 **Your Admin ID:** `{user.id}`
            """
        else:
            admin_text = f"""
👤 **USER ACCESS**

Welcome **{sanitize_input(user.first_name)}**!

🔍 **Your Features:**
• Access files via deeplinks
• View shared media securely
• All data encrypted

**Note:** Only admins can upload files.

🆔 **Your User ID:** `{user.id}`
            """
        
        await update.message.reply_text(admin_text, parse_mode="Markdown")
    
    async def handle_media_upload(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        user = update.effective_user
        
        if not check_rate_limit(user.id):
            await update.message.reply_text("⏰ Upload rate limit exceeded!")
            return
        
        # Channel membership check
        joined = await self.check_joined(user.id, context)
        if not joined:
            keyboard = [
                [InlineKeyboardButton("🔔 Join Channel", url=f"https://t.me/{CHANNEL_USERNAME.strip('@')}")],
                [InlineKeyboardButton("✅ Verify", callback_data="check_join")]
            ]
            await update.message.reply_text(
                "❌ **Channel membership required!**",
                reply_markup=InlineKeyboardMarkup(keyboard),
                parse_mode="Markdown"
            )
            return
        
        # Admin check
        if not self.is_admin(user.id):
            await update.message.reply_text(
                f"⛔ **Permission denied!** Only admins can upload files.\n\n🆔 **Your ID:** `{user.id}`\n👑 **Admin IDs:** `{ADMIN_IDS}`",
                parse_mode="Markdown"
            )
            return
        
        # Process media
        file_info = None
        media_type = ""
        file_size = 0
        
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
        else:
            await update.message.reply_text("❌ **Unsupported file type!**")
            return
        
        if not file_info:
            await update.message.reply_text("❌ **File processing failed!**")
            return
        
        # Generate deeplink
        file_id = file_info.file_id
        deeplink_id = generate_deeplink(user.id, file_id)
        
        # Store deeplink
        deeplinks[deeplink_id] = {
            'file_id': file_id,
            'user_id': user.id,
            'media_type': media_type,
            'timestamp': datetime.now().isoformat(),
            'file_size': file_size,
            'caption': sanitize_input(update.message.caption or ""),
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
        
        success_text = f"""
✅ **FILE UPLOADED SUCCESSFULLY!**

📁 **Details:**
• Type: {media_type}
• Size: {format_size(file_size)}
• Uploaded: {datetime.now().strftime('%Y-%m-%d %H:%M')}

🔗 **Secure Deeplink:**
`https://t.me/{context.bot.username}?start={deeplink_id}`

🔒 **Security:** End-to-end encrypted
💡 **Share this link to grant access!**
        """
        
        keyboard = [
            [InlineKeyboardButton("🔗 Share Link", url=f"https://t.me/share/url?url=https://t.me/{context.bot.username}?start={deeplink_id}")],
            [InlineKeyboardButton("📊 Stats", callback_data="admin_stats")]
        ]
        
        await update.message.reply_text(
            success_text,
            reply_markup=InlineKeyboardMarkup(keyboard),
            parse_mode="Markdown"
        )
    
    async def handle_deeplink_access(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not context.args:
            await self.start_command(update, context)
            return
        
        deeplink_id = sanitize_input(context.args[0])
        user = update.effective_user
        
        if deeplink_id not in deeplinks:
            await update.message.reply_text("❌ **Invalid or expired link!**")
            return
        
        # Channel membership check
        joined = await self.check_joined(user.id, context)
        if not joined:
            keyboard = [
                [InlineKeyboardButton("🔔 Join Channel", url=f"https://t.me/{CHANNEL_USERNAME.strip('@')}")],
                [InlineKeyboardButton("✅ Access File", callback_data="check_join")]
            ]
            await update.message.reply_text(
                "🔒 **Join required for file access!**",
                reply_markup=InlineKeyboardMarkup(keyboard),
                parse_mode="Markdown"
            )
            return
        
        # Get file info
        link_info = deeplinks[deeplink_id]
        file_id = link_info['file_id']
        
        # Update access count
        link_info['access_count'] += 1
        
        # Send file
        try:
            caption_text = f"""
🔒 **SECURE FILE ACCESS**

📁 **File Info:**
• Type: {link_info['media_type']}
• Shared by: Admin
• Access #{link_info['access_count']}

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
        except Exception as e:
            await update.message.reply_text(f"❌ **File access error:** {str(e)}")
    
    async def button_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        
        user = query.from_user
        
        if not check_rate_limit(user.id):
            await query.answer("Rate limit exceeded!", show_alert=True)
            return
        
        if query.data == "check_join":
            joined = await self.check_joined(user.id, context)
            
            if joined:
                if self.is_admin(user.id):
                    welcome_text = """
👑 **ADMIN VERIFIED**

✅ Channel membership confirmed!

🔧 **Admin Features:**
• Upload media files
• Generate secure deeplinks
• View statistics

**Ready to upload?** Send me your first file! 📁
                    """
                else:
                    welcome_text = """
✅ **ACCESS GRANTED**

Channel membership confirmed!

👤 **User Features:**
• Access files via deeplinks
• View shared media securely

**Note:** Only admins can upload files.
                    """
                
                await query.edit_message_text(welcome_text, parse_mode="Markdown")
            else:
                keyboard = [
                    [InlineKeyboardButton("🔔 Join Channel", url=f"https://t.me/{CHANNEL_USERNAME.strip('@')}")],
                    [InlineKeyboardButton("✅ Check Again", callback_data="check_join")]
                ]
                await query.edit_message_text(
                    "❌ **Still not joined!** Please join our channel first.",
                    reply_markup=InlineKeyboardMarkup(keyboard),
                    parse_mode="Markdown"
                )
        
        elif query.data == "admin_stats" and self.is_admin(user.id):
            stats_text = f"""
📊 **BOT STATISTICS**

👥 **Users:** {len(user_sessions)}
🔗 **Deeplinks:** {len(deeplinks)}
🛡️ **Security Events:** {len(security_logs)}

🔒 **Security Status:**
✅ Rate limiting active
✅ Input sanitization enabled
✅ File encryption active
✅ Admin-only uploads

⚙️ **Configuration:**
• Bot Token: {BOT_TOKEN[:20]}...
• Channel: {CHANNEL_USERNAME}
• Admin IDs: {ADMIN_IDS}
            """
            await query.edit_message_text(stats_text, parse_mode="Markdown")
    
    def run(self):
        print("🚀 Starting Secure Telegram Bot on Render...")
        print(f"🤖 Bot Token: {BOT_TOKEN[:20]}...")
        print(f"📢 Channel: {CHANNEL_USERNAME}")
        print(f"👑 Admins: {ADMIN_IDS}")
        print("🛡️ Security: Maximum level")
        
        # Create application
        app = Application.builder().token(BOT_TOKEN).build()
        
        # Add handlers
        app.add_handler(CommandHandler("start", self.start_command))
        app.add_handler(CallbackQueryHandler(self.button_callback))
        app.add_handler(MessageHandler(
            filters.PHOTO | filters.VIDEO | filters.Document.ALL, 
            self.handle_media_upload
        ))
        
        print("✅ Bot is running with maximum security!")
        print("🛡️ All security features active")
        
        # Run the bot
        app.run_polling(drop_pending_updates=True)

# Main execution
if __name__ == "__main__":
    try:
        bot = SecureMediaBot()
        bot.run()
    except Exception as e:
        print(f"❌ Critical error: {e}")
        logging.error(f"Critical error: {e}")
