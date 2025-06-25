"""Discord-Teamup calendar synchronization bot.

Maintains bidirectional real-time sync between Discord scheduled events and Teamup calendar.
Designed for stateless operation - can recover from complete data loss by rebuilding state
from both APIs using embedded identifiers.

Architecture rationale:
- Thread-centric UX: Reduces channel noise while providing focused event discussion
- Stateless design: Eliminates complex state management and enables robust recovery
- Embedded tracking: Uses Teamup's remote_id field to store Discord event IDs
- Role-based access: Automates Teamup calendar access based on Discord roles
- External events only: Avoids Discord voice/stage dependencies for real-world events
"""

from __future__ import annotations
import json, logging, pathlib, datetime as dt, asyncio, hashlib, hmac, secrets
from typing import Dict, Any, Optional
import tempfile, shutil

# Rate limiting for API calls
from collections import defaultdict
import time

import discord
from discord.ext import commands
from discord import Interaction, Embed, ui, EntityType, ScheduledEvent

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import httpx
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings
import uvicorn

# ----------------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------------
class Settings(BaseSettings):
    """Configuration with fail-fast validation to catch deployment issues early."""
    model_config = {
        "env_file": ".env", 
        "env_file_encoding": "utf-8",
        "extra": "ignore"  # Ignore extra environment variables
    }
    
    discord_token: str = Field(..., alias="DISCORD_TOKEN")
    guild_id: int = Field(..., alias="DISCORD_GUILD_ID")
    events_channel: int = Field(..., alias="EVENTS_CHANNEL_ID")
    guest_role: int = Field(..., alias="CURRENT_GUEST_ROLE_ID")
    use_personal_links: bool = Field(True, alias="USE_PERSONAL_LINKS")

    teamup_calendar: str = Field(..., alias="TEAMUP_CALENDAR_KEY")
    teamup_token: str = Field(..., alias="TEAMUP_API_TOKEN")
    teamup_subcalendar_id: int = Field(..., alias="SUBCALENDAR_ID")
    teamup_access_link: str = Field("", alias="TEAMUP_ACCESS_LINK")  # General access link for viewing/modifying events
    webhook_secret: str = Field("", alias="TEAMUP_WEBHOOK_SECRET")  # Optional for initial setup

    # Performance caches only - system works without these files
    links_file: pathlib.Path = Field("links.json", alias="LINKS_FILE")
    events_file: pathlib.Path = Field("events_map.json", alias="EVENTS_FILE")
    threads_file: pathlib.Path = Field("threads_map.json", alias="THREADS_FILE")

    host: str = Field("0.0.0.0", alias="BOT_HOST")
    port: int = Field(8000, alias="BOT_PORT")
CFG = Settings()

# Configuration validation
def validate_config():
    """Fail fast on invalid config to prevent runtime errors in production."""
    errors = []
    
    # Check required tokens are not empty
    if not CFG.discord_token or not CFG.discord_token.strip():
        errors.append("Discord token is required")
    if not CFG.teamup_token or not CFG.teamup_token.strip():
        errors.append("Teamup token is required")
    if not CFG.teamup_calendar or not CFG.teamup_calendar.strip():
        errors.append("Teamup calendar key is required")
    
    # Webhook secret is optional for initial setup - warn if empty but don't fail
    if not CFG.webhook_secret:
        log.warning("Webhook secret is empty - webhook functionality will be disabled")
    
    # Check IDs are valid
    if CFG.guild_id <= 0:
        errors.append("Invalid guild ID")
    if CFG.events_channel <= 0:
        errors.append("Invalid events channel ID")
    if CFG.guest_role <= 0:
        errors.append("Invalid guest role ID")
    
    if errors:
        for error in errors:
            log.error("Configuration error: %s", error)
        raise ValueError(f"Configuration validation failed: {', '.join(errors)}")
    
    log.info("Configuration validated successfully")

# Enhanced HMAC validation
def verify_webhook_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Prevent webhook spoofing attacks using HMAC verification."""
    if not signature or not secret:
        return False
    
    try:
        expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        return secrets.compare_digest(signature, expected)
    except Exception as e:
        log.warning("HMAC verification error: %s", e)
        return False

# ----------------------------------------------------------------------------
# Util – load / save cache (optional)
# ----------------------------------------------------------------------------

def _load(path: pathlib.Path, default):
    """Graceful cache loading - missing files trigger state rebuild, not errors."""
    return json.loads(path.read_text()) if path.exists() else default


def _save_atomic(obj: Any, path: pathlib.Path):
    """Atomic writes prevent cache corruption during system crashes."""
    temp_path = path.with_suffix('.tmp')
    try:
        temp_path.write_text(json.dumps(obj, indent=2))
        shutil.move(temp_path, path)
    except Exception as e:
        if temp_path.exists():
            temp_path.unlink()
        raise e


# Core state mappings - kept in sync to enable bidirectional lookups
USER_LINKS: Dict[int, Dict[str, str]] = _load(CFG.links_file, {})
EVENT_MAP: Dict[str, int] = _load(CFG.events_file, {})
THREAD_MAP: Dict[int, int] = _load(CFG.threads_file, {})
REVERSE_MAP: Dict[int, str] = {v: k for k, v in EVENT_MAP.items()}

# Cache size limits to prevent memory issues
MAX_CACHE_SIZE = 1000
MAX_ACTIVE_VIEWS = 100

def manage_cache_size():
    """Prevent memory exhaustion by limiting cache growth in long-running processes."""
    global USER_LINKS, EVENT_MAP, THREAD_MAP, REVERSE_MAP, _active_views
    
    if len(USER_LINKS) > MAX_CACHE_SIZE:
        items = list(USER_LINKS.items())
        USER_LINKS = dict(items[-MAX_CACHE_SIZE:])
        save_links()
        log.info("Trimmed USER_LINKS cache to %d entries", len(USER_LINKS))
    
    if len(EVENT_MAP) > MAX_CACHE_SIZE:
        items = list(EVENT_MAP.items())
        EVENT_MAP = dict(items[-MAX_CACHE_SIZE:])
        REVERSE_MAP = {v: k for k, v in EVENT_MAP.items()}
        save_events()
        log.info("Trimmed EVENT_MAP cache to %d entries", len(EVENT_MAP))
    
    if len(_active_views) > MAX_ACTIVE_VIEWS:
        items = list(_active_views.items())
        for dc_id, view in items[:-MAX_ACTIVE_VIEWS]:
            view.cleanup()
            _active_views.pop(dc_id, None)
        log.info("Trimmed active views to %d entries", len(_active_views))

save_links = lambda: _save_atomic(USER_LINKS, CFG.links_file)

def save_events():
    """Atomic persistence prevents mapping inconsistencies during crashes."""
    try:
        _save_atomic(EVENT_MAP, CFG.events_file)
        _save_atomic(THREAD_MAP, CFG.threads_file)
    except Exception as e:
        log.error("Failed to save event mappings: %s", e)
        raise

# ----------------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------------
import discord.utils

# Set up Discord.py logging first
discord.utils.setup_logging(level=logging.INFO, root=True)

# Force all loggers to use Discord's formatting by clearing their handlers
# and ensuring they propagate to the root logger
def harmonize_all_logging():
    """Ensure all loggers use Discord's formatting from the root logger."""
    root_logger = logging.getLogger()
    
    # Get all existing loggers
    loggers_to_fix = [
        logging.getLogger(name) for name in logging.Logger.manager.loggerDict
    ]
    
    for logger in loggers_to_fix:
        if logger.handlers:  # Only clear if it has handlers
            logger.handlers.clear()
        logger.propagate = True  # Ensure it propagates to root

# Apply harmonization
harmonize_all_logging()

log = logging.getLogger("teamup_bot")

# Reduce HTTP request noise in production
logging.getLogger('discord.http').setLevel(logging.WARNING)
logging.getLogger('httpx').setLevel(logging.WARNING)

# ----------------------------------------------------------------------------
# HTTP – Teamup helper
# ----------------------------------------------------------------------------
TU_BASE = "https://api.teamup.com"
HEADERS = {"Teamup-Token": CFG.teamup_token, "Content-Type": "application/json"}
client = httpx.AsyncClient(headers=HEADERS, timeout=20)

# Health check functionality
async def health_check_discord() -> bool:
    """Check if Discord API is accessible."""
    try:
        return bot.is_ready() and bot.get_guild(CFG.guild_id) is not None
    except Exception as e:
        log.warning("Discord health check failed: %s", e)
        return False

async def health_check_teamup() -> bool:
    """Check if Teamup API is accessible."""
    try:
        await tu("GET", "/events", retry_count=1)
        return True
    except Exception as e:
        log.warning("Teamup health check failed: %s", e)
        return False

async def check_dependencies():
    """Check all external dependencies and log status."""
    discord_ok = await health_check_discord()
    teamup_ok = await health_check_teamup()
    
    if not discord_ok:
        log.error("Discord API is not accessible")
    if not teamup_ok:
        log.error("Teamup API is not accessible")
        
    return discord_ok and teamup_ok


async def tu(method: str, path: str, body: Optional[Dict[str, Any]] = None, retry_count: int = 3):
    """Centralized Teamup API client ensures consistent retry/rate limiting behavior."""
    await rate_limit_teamup()
    
    url = f"{TU_BASE}/{CFG.teamup_calendar}{path}"
    
    for attempt in range(retry_count):
        try:
            r = await client.request(method, url, json=body)
            if r.status_code not in (200, 201, 204):
                log.error("Teamup %s %s -> %s %s", method, path, r.status_code, r.text)
            r.raise_for_status()
            
            if not r.content or r.content.strip() == b'':
                return None
            try:
                return r.json()
            except json.JSONDecodeError as e:
                log.warning("Failed to decode JSON response from Teamup: %s", e)
                return None
        except httpx.RequestError as e:
            if attempt < retry_count - 1:
                wait_time = 2 ** attempt
                log.warning("Teamup API request failed (attempt %d/%d), retrying in %ds: %s", 
                           attempt + 1, retry_count, wait_time, e)
                await asyncio.sleep(wait_time)
            else:
                log.error("Teamup API request failed after %d attempts: %s", retry_count, e)
                raise
        except httpx.HTTPStatusError as e:
            log.error("Teamup HTTP error: %s", e)
            raise

# ----------------------------------------------------------------------------
# Discord bot  + helpers
# ----------------------------------------------------------------------------
intents = discord.Intents.default()
intents.members = True
intents.guilds = True
intents.guild_scheduled_events = True  # Required for scheduled event handlers!
bot = commands.Bot(command_prefix="!", intents=intents)

def guild() -> discord.Guild:  # type: ignore
    """Get target guild - fails early during bot startup if not ready."""
    g = bot.get_guild(CFG.guild_id)
    if not g:
        raise RuntimeError("Guild not cached yet")
    return g

# ----------------------------------------------------------------------------
# JSON‑warm reboot  – rebuild mapping if cache missing/cleared
# ----------------------------------------------------------------------------
# State rebuild lock to prevent race conditions
_rebuild_lock = asyncio.Lock()

# Webhook processing lock to prevent concurrent state updates
_webhook_lock = asyncio.Lock()

# Rate limiting for Discord API calls
_discord_rate_limiter = defaultdict(list)
_discord_rate_limit = 50  # requests per minute
_teamup_rate_limiter = []
_teamup_rate_limit = 100  # requests per minute

async def rate_limit_discord(operation: str):
    """Rate limit Discord API calls by operation type."""
    now = time.time()
    minute_ago = now - 60
    
    # Clean old entries
    _discord_rate_limiter[operation] = [
        t for t in _discord_rate_limiter[operation] if t > minute_ago
    ]
    
    # Check if we're at the limit
    if len(_discord_rate_limiter[operation]) >= _discord_rate_limit:
        sleep_time = 60 - (now - _discord_rate_limiter[operation][0])
        if sleep_time > 0:
            log.warning("Discord rate limit hit for %s, sleeping %.2fs", operation, sleep_time)
            await asyncio.sleep(sleep_time)
    
    _discord_rate_limiter[operation].append(now)

async def rate_limit_teamup():
    """Rate limit Teamup API calls."""
    now = time.time()
    minute_ago = now - 60
    
    # Clean old entries
    global _teamup_rate_limiter
    _teamup_rate_limiter = [t for t in _teamup_rate_limiter if t > minute_ago]
    
    # Check if we're at the limit
    if len(_teamup_rate_limiter) >= _teamup_rate_limit:
        sleep_time = 60 - (now - _teamup_rate_limiter[0])
        if sleep_time > 0:
            log.warning("Teamup rate limit hit, sleeping %.2fs", sleep_time)
            await asyncio.sleep(sleep_time)
    
    _teamup_rate_limiter.append(now)

async def rebuild_state():
    """Reconstruct mappings from live APIs when cache is missing - enables stateless recovery."""
    async with _rebuild_lock:
        needs_event_rebuild = len(EVENT_MAP) == 0
        needs_thread_rebuild = len(THREAD_MAP) == 0
        
        if not needs_event_rebuild and not needs_thread_rebuild:
            return

        try:
            if needs_event_rebuild:
                log.info("🛠️  Rebuilding Teamup↔Discord event mappings …")
                today = dt.date.today(); end = today + dt.timedelta(days=365)
                data = await tu("GET", f"/events?startDate={today}&endDate={end}")
                
                for ev in data.get("events", []):
                    rid = ev.get("remote_id", "")
                    if rid.startswith("dc-"):  # Discord-originated events
                        try:
                            dc_id = int(rid[3:]); tu_id = str(ev["id"])
                            EVENT_MAP[tu_id] = dc_id; REVERSE_MAP[dc_id] = tu_id
                        except (ValueError, KeyError) as e:
                            log.warning("Invalid remote_id format '%s': %s", rid, e)
                            
                log.info("   ↳ recovered %s events", len(EVENT_MAP))

            if needs_thread_rebuild:
                log.info("🛠️  Rebuilding Discord event→thread mappings …")
                chan: discord.TextChannel = bot.get_channel(CFG.events_channel)  # type: ignore
                if not chan:
                    log.warning("Events channel not found, skipping thread rebuild")
                    return
                    
                # Collect archived threads - chan.archived_threads() is an async iterator
                threads = {}
                async for thread in chan.archived_threads():
                    threads[thread.name] = thread.id
                    
                # Add active threads
                threads.update({th.name: th.id for th in chan.threads})
                g = guild()
                
                for ev in await g.fetch_scheduled_events():
                    if ev.entity_type != EntityType.external:
                        continue
                    th_name = f"🗓️ {ev.name}"
                    th_id = threads.get(th_name)
                    if th_id:
                        THREAD_MAP[ev.id] = th_id
                log.info("   ↳ recovered %s thread links", len(THREAD_MAP))
            
            save_events()
            
        except Exception as e:
            log.error("Failed to rebuild state: %s", e)
            # Continue with partial state - graceful degradation

# ----------------------------------------------------------------------------
# Provision / de‑provision Teamup modify links for residents
# ----------------------------------------------------------------------------
async def create_modify_link(name: str):
    """Generate personal modify links to automate calendar access based on Discord roles."""
    d = await tu("POST", "/keys", {
        "name": name,
        "role": "modify_from_same_link",
        "share_type": "all_subcalendars",
        "subcalendar_permissions": {}
    })
    k = d["key"]
    return str(k["id"]), k["key"]


async def disable_link(key_id: str):
    """Revoke calendar access when Discord role is removed."""
    await tu("PATCH", f"/keys/{key_id}", {"active": False})


async def provision(member: discord.Member):
    """Automatic calendar access provisioning reduces manual admin overhead."""
    if member.id in USER_LINKS:
        return
        
    try:
        kid, kstr = await create_modify_link(member.display_name)
        USER_LINKS[member.id] = {"key_id": kid, "key": kstr}
        save_links()
        
        try:
            await member.send(f"Here's your personal Teamup link:\nhttps://teamup.com/{kstr}")
        except discord.Forbidden:
            log.warning("DM blocked for %s", member)
        except Exception as e:
            log.error("Failed to send DM to %s: %s", member, e)
            
    except Exception as e:
        log.error("Failed to create modify link for %s: %s", member, e)
        raise


async def deprovision(member: discord.Member):
    """Automatic access revocation maintains security when roles change."""
    info = USER_LINKS.pop(member.id, None)
    save_links()
    
    if info and "key_id" in info:
        try:
            await disable_link(info["key_id"])
        except Exception as e:
            log.error("Failed to disable link for %s: %s", member, e)
            USER_LINKS[member.id] = info  # Restore on failure
            save_links()
            raise


@bot.event
async def on_member_update(before: discord.Member, after: discord.Member):
    """Role-based access control eliminates manual calendar permission management."""
    if not CFG.use_personal_links:
        return
    
    before_roles = getattr(before, 'roles', []) or []
    after_roles = getattr(after, 'roles', []) or []
    
    had = CFG.guest_role in [r.id for r in before_roles]
    has = CFG.guest_role in [r.id for r in after_roles]
    
    if not had and has:
        try:
            await provision(after)
        except Exception as e:
            log.error("Failed to provision user %s: %s", after, e)
    elif had and not has:
        try:
            await deprovision(after)
        except Exception as e:
            log.error("Failed to deprovision user %s: %s", after, e)

# ----------------------------------------------------------------------------
# Sign‑up helpers
# ----------------------------------------------------------------------------
async def tu_signup(tu_id: str, user: discord.abc.User):
    """Sync Discord interest to Teamup signup for bidirectional RSVP tracking."""
    try:
        await tu("POST", f"/events/{tu_id}/signups", {"name": user.display_name, "email": None})
    except Exception as e:
        log.error("Failed to sign up user %s for Teamup event %s: %s", user.display_name, tu_id, e)
        raise


async def tu_unsign(tu_id: str, user: discord.abc.User):
    """Remove signup using name matching - handles cases with duplicate names gracefully."""
    try:
        aux = await tu("GET", f"/events/{tu_id}/aux")
        matches = [s for s in aux.get("signups", []) if s.get("name") == user.display_name]
        
        if not matches:
            log.warning("No signup found for user %s in event %s", user.display_name, tu_id)
            return
        elif len(matches) > 1:
            log.warning("Multiple signups found for user %s in event %s, removing first", user.display_name, tu_id)
        
        await tu("DELETE", f"/events/{tu_id}/signups/{matches[0]['id']}")
        
    except Exception as e:
        log.error("Failed to unsign user %s from Teamup event %s: %s", user.display_name, tu_id, e)
        raise


# ----------------------------------------------------------------------------
# RSVP sync: Discord Interested ⇄ Teamup sign‑up
# ----------------------------------------------------------------------------
@bot.event
async def on_scheduled_event_user_add(event: ScheduledEvent, user: discord.User):
    """Sync Discord "Interested" to Teamup signup when user shows interest."""
    tu_id = REVERSE_MAP.get(event.id)
    if tu_id:
        try:
            await tu_signup(tu_id, user)
            log.debug("Synced Discord interest to Teamup signup for user %s, event %s", user.display_name, tu_id)
        except Exception as e:
            log.error("Failed to sync Discord interest to Teamup for user %s: %s", user.display_name, e)


@bot.event
async def on_scheduled_event_user_remove(event: ScheduledEvent, user: discord.User):
    """Sync Discord "Not Interested" to Teamup unsignup when user removes interest."""
    tu_id = REVERSE_MAP.get(event.id)
    if tu_id:
        try:
            await tu_unsign(tu_id, user)
            log.debug("Synced Discord disinterest to Teamup unsignup for user %s, event %s", user.display_name, tu_id)
        except Exception as e:
            log.error("Failed to sync Discord disinterest to Teamup for user %s: %s", user.display_name, e)


# ----------------------------------------------------------------------------
# Discord UI – sign‑up button
# ----------------------------------------------------------------------------
# Track active signup views for cleanup
_active_views: Dict[int, SignupView] = {}

class SignupView(ui.View):
    """Event-specific signup buttons enable one-click RSVP with bidirectional sync."""
    def __init__(self, tu_id: str, dc_id: int):
        super().__init__(timeout=None)
        self.tu_id = tu_id
        self.dc_id = dc_id
        _active_views[dc_id] = self  # Track for memory management

    @ui.button(label="Sign Up ✍️", style=discord.ButtonStyle.primary, custom_id="signup")
    async def signup(self, itx: Interaction, _: ui.Button):
        """Single-click signup updates both Discord interest and Teamup attendance."""
        try:
            await itx.response.defer(ephemeral=True)
            await tu_signup(self.tu_id, itx.user)
            
            try:
                ev = await guild().fetch_scheduled_event(self.dc_id)
                await ev.add_user(itx.user)
            except discord.NotFound:
                log.warning("Discord event %s not found during signup", self.dc_id)
            except Exception as e:
                log.warning("Failed to add user to Discord event: %s", e)
            
            thread_id = THREAD_MAP.get(self.dc_id)
            if thread_id:
                try:
                    thread = await bot.fetch_channel(thread_id)
                    if hasattr(thread, 'add_user'):
                        await thread.add_user(itx.user)
                        log.debug("Added user %s to thread %s for event %s", itx.user.display_name, thread_id, self.dc_id)
                except discord.NotFound:
                    log.warning("Thread %s not found during signup", thread_id)
                except discord.Forbidden:
                    log.warning("No permission to add user %s to thread %s", itx.user.display_name, thread_id)
                except Exception as e:
                    log.warning("Failed to add user %s to thread %s: %s", itx.user.display_name, thread_id, e)
                
            await itx.followup.send("✅ Signed up!", ephemeral=True)
            
        except Exception as e:
            log.error("Signup failed for user %s: %s", itx.user, e)
            await itx.followup.send("❌ Signup failed. Please try again.", ephemeral=True)
            
    def cleanup(self):
        """Prevent memory leaks by removing view references."""
        _active_views.pop(self.dc_id, None)


# ---------------------------------------------------------------------------
# Persistent dummy‑safe view (pre‑registered on startup so buttons survive reboot)
# ---------------------------------------------------------------------------
class PersistentSignupView(ui.View):
    """Fallback handler prevents button errors during bot startup before views are rebuilt."""
    def __init__(self):
        super().__init__(timeout=None)

    @ui.button(label="Sign Up ✍️", style=discord.ButtonStyle.primary, custom_id="signup")
    async def noop(self, itx: Interaction, _: ui.Button):
        """Graceful degradation during startup prevents user frustration."""
        await itx.response.send_message(
            "Bot is warming up – please try again in a moment…",
            ephemeral=True
        )


# ----------------------------------------------------------------------------
# Teamup → Discord helpers (create / edit / cancel)
# ----------------------------------------------------------------------------
def parse_datetime_safe(dt_str: str) -> dt.datetime:
    """Safely parse datetime string handling both naive and timezone-aware formats."""
    try:
        parsed = dt.datetime.fromisoformat(dt_str)
        # If already timezone-aware, convert to UTC; if naive, assume UTC
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=dt.timezone.utc)
        else:
            return parsed.astimezone(dt.timezone.utc)
    except ValueError as e:
        log.error("Failed to parse datetime '%s': %s", dt_str, e)
        raise

async def create_dc_event_from_tu(ev: Dict[str, Any]) -> int:
    """External events avoid Discord voice/stage dependencies for real-world events."""
    # Validate required fields
    if not ev.get("start_dt") or not ev.get("end_dt"):
        raise ValueError("Event missing required start_dt or end_dt")
        
    try:
        check_bot_ready()
        await rate_limit_discord("create_event")
        g = guild()
        start = parse_datetime_safe(ev["start_dt"])
        end = parse_datetime_safe(ev["end_dt"])
        
        # Validate times
        if start >= end:
            raise ValueError("Event start time must be before end time")
            
        notes_field = ev.get("notes")
        if isinstance(notes_field, dict) and 'html' in notes_field:
            teamup_description = notes_field['html']
        elif isinstance(notes_field, str):
            teamup_description = notes_field
        else:
            teamup_description = ""
        
        discord_description = teamup_description
        
        dc_ev = await g.create_scheduled_event(
            name=ev.get("title") or "(No title)",
            start_time=start,
            end_time=end,
            entity_type=EntityType.external,
            location=ev.get("location") or "Teamup",
            description=discord_description
        )
        return dc_ev.id
    except discord.RateLimited as e:
        log.warning("Discord rate limited, retrying after %s seconds", e.retry_after)
        await asyncio.sleep(e.retry_after)
        return await create_dc_event_from_tu(ev)  # Retry once
    except Exception as e:
        log.error("Failed to create Discord event from Teamup data: %s", e)
        raise


async def update_dc_event(dc_id: int, ev: Dict[str, Any]):
    """Update Discord event with Teamup event changes while preserving existing data."""
    # Validate required fields
    if not ev.get("start_dt") or not ev.get("end_dt"):
        log.warning("Event missing required start_dt or end_dt, skipping update")
        return
        
    try:
        check_bot_ready()
        await rate_limit_discord("update_event")
        dcev = await guild().fetch_scheduled_event(dc_id)
        start = parse_datetime_safe(ev["start_dt"])
        end = parse_datetime_safe(ev["end_dt"])
        
        # Validate times
        if start >= end:
            log.warning("Invalid event times (start >= end), skipping update")
            return
            
        notes_field = ev.get("notes")
        if isinstance(notes_field, dict) and 'html' in notes_field:
            teamup_description = notes_field['html']
        elif isinstance(notes_field, str):
            teamup_description = notes_field
        else:
            teamup_description = ""
        
        discord_description = teamup_description
        
        await dcev.edit(
            name=ev.get("title") or dcev.name,
            start_time=start,
            end_time=end,
            location=ev.get("location") or dcev.location or "Teamup",
            description=discord_description
        )
    except discord.NotFound:
        log.warning("Discord event %s not found, removing from mapping", dc_id)
        REVERSE_MAP.pop(dc_id, None)
        # Find and remove from EVENT_MAP
        for tu_id, disc_id in list(EVENT_MAP.items()):
            if disc_id == dc_id:
                EVENT_MAP.pop(tu_id, None)
                break
        save_events()
    except Exception as e:
        log.error("Failed to update Discord event %s: %s", dc_id, e)
        raise


async def cancel_dc_event(dc_id: int):
    """Cancel Discord event when corresponding Teamup event is deleted."""
    try:
        await rate_limit_discord("cancel_event")
        dcev = await guild().fetch_scheduled_event(dc_id)
        await dcev.cancel()
    except discord.NotFound:
        log.warning("Discord event %s already deleted", dc_id)
    except discord.RateLimited as e:
        log.warning("Discord rate limited while cancelling event, retrying after %s seconds", e.retry_after)
        await asyncio.sleep(e.retry_after)
        await cancel_dc_event(dc_id)  # Retry once
    except Exception as e:
        log.error("Failed to cancel Discord event %s: %s", dc_id, e)
        raise

# ----------------------------------------------------------------------------
# Discord → Teamup helpers (remote_id = "dc-<discord_event_id>")
# ----------------------------------------------------------------------------
# Dynamic MIN_BODY function to use configured subcalendar
def get_min_body():
    return {
        "signup_enabled": True,
        "signup_deadline": None,
        "comments_enabled": False, 
        "attachments": [],
        "subcalendar_ids": [CFG.teamup_subcalendar_id]
    }


def format_teamup_datetime(dt_obj: dt.datetime) -> str:
    """Format datetime for Teamup API (no microseconds)."""
    return dt_obj.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat()

async def create_tu_event_from_dc(ev: ScheduledEvent) -> str:
    """Embed Discord ID in remote_id field to enable stateless event origin tracking."""
    try:
        body = {
            "title": ev.name,
            "start_dt": format_teamup_datetime(ev.start_time),
            "end_dt": format_teamup_datetime(ev.end_time),
            "location": ev.location or "Discord",
            "notes": {"html": ev.description or ""},
            "remote_id": f"dc-{ev.id}", 
            **get_min_body()
        }
        data = await tu("POST", "/events", body)
        return str(data["event"]["id"])
    except Exception as e:
        log.error("Failed to create Teamup event from Discord event %s: %s", ev.id, e)
        raise


async def update_tu_event(tu_id: str, ev: ScheduledEvent):
    """Update Teamup event with Discord event changes."""
    try:
        body = {
            "id": tu_id,
            "title": ev.name,
            "start_dt": format_teamup_datetime(ev.start_time),
            "end_dt": format_teamup_datetime(ev.end_time),
            "location": ev.location or "Discord",
            "notes": {"html": ev.description or ""},
            **get_min_body()
        }
        await tu("PUT", f"/events/{tu_id}", body)
    except Exception as e:
        log.error("Failed to update Teamup event %s: %s", tu_id, e)
        raise


async def delete_tu_event(tu_id: str):
    """Delete Teamup event when corresponding Discord event is removed."""
    try:
        await tu("DELETE", f"/events/{tu_id}")
    except Exception as e:
        log.error("Failed to delete Teamup event %s: %s", tu_id, e)
        # Don't re-raise for delete operations to avoid blocking cleanup

# ----------------------------------------------------------------------------
# Root embed + thread
# ----------------------------------------------------------------------------
async def post_root_embed(tu_ev: Dict[str, Any], trigger: str) -> tuple[int, int]:
    """Thread-per-event design reduces channel noise while enabling focused discussion."""
    try:
        chan: discord.TextChannel = bot.get_channel(CFG.events_channel)  # type: ignore
        if not chan:
            raise ValueError("Events channel not found")
            
        title = tu_ev.get("title") or "(No title)"
        start_iso = tu_ev.get("start_dt")
        end_iso = tu_ev.get("end_dt")
        if not start_iso:
            raise ValueError("Event missing start_dt")
            
        start_dt = dt.datetime.fromisoformat(start_iso)
        start_human = start_dt.strftime("%A, %B %d, %Y at %I:%M %p")
        
        time_info = start_human
        if end_iso:
            end_dt = dt.datetime.fromisoformat(end_iso)
            if start_dt.date() == end_dt.date():
                end_time = end_dt.strftime("%I:%M %p")
                time_info = f"{start_dt.strftime('%A, %B %d, %Y')} from {start_dt.strftime('%I:%M %p')} to {end_time}"
            else:
                end_human = end_dt.strftime("%A, %B %d, %Y at %I:%M %p")
                time_info = f"{start_human} → {end_human}"
        
        try:
            pointer = await tu("POST", f"/events/{tu_ev['id']}/pointer", {})
            pointer_url = pointer.get('url', 'https://teamup.com')
        except Exception as e:
            log.warning("Failed to get Teamup pointer URL: %s", e)
            pointer_url = 'https://teamup.com'
            
        colors = {"event.created": 0x2ecc71, "event.modified": 0xf1c40f, "event.removed": 0xe74c3c}
        verbs  = {"event.created": "created", "event.modified": "updated", "event.removed": "deleted"}

        thread = await chan.create_thread(
            name=f"🗓️ {title}", 
            auto_archive_duration=1440,
            type=discord.ChannelType.public_thread
        )
        
        embed = Embed(
            title=f"📅 {title}",
            url=pointer_url,
            description=f"**Event {verbs.get(trigger,'updated')}**",
            color=colors.get(trigger, 0x95a5a6)
        )
        
        embed.add_field(name="🕒 When", value=time_info, inline=False)
        
        location = tu_ev.get("location")
        log.info("DEBUG: location field data for event %s: type=%s, value=%r", tu_ev.get('id'), type(location).__name__, location)
        if location and location.strip():
            embed.add_field(name="📍 Where", value=location, inline=False)
        
        notes_field = tu_ev.get("notes")
        if isinstance(notes_field, dict) and 'html' in notes_field:
            notes_text = notes_field['html']
        elif isinstance(notes_field, str):
            notes_text = notes_field
        else:
            notes_text = None
            
        description = notes_text
        log.info("DEBUG: notes field data for event %s: notes_type=%s, notes_value=%r, extracted_notes=%r", 
                tu_ev.get('id'), 
                type(tu_ev.get("notes")).__name__, tu_ev.get("notes"),
                notes_text)
        if description and description.strip():
            if len(description) > 1000:
                description = description[:997] + "..."
            embed.add_field(name="📝 Details", value=description, inline=False)

        dc_id = EVENT_MAP.get(str(tu_ev["id"]))
        view = None if trigger == "event.removed" or not dc_id else SignupView(str(tu_ev["id"]), dc_id)
        
        access_message = ""
        if not CFG.use_personal_links and CFG.teamup_access_link:
            access_message = f"\n\n📅 You can view and modify this event on Teamup: {CFG.teamup_access_link}"
        
        first_message = await thread.send(embed=embed, content=access_message, view=view)
        
        return first_message.id, thread.id
        
    except Exception as e:
        log.error("Failed to post root embed for event %s: %s", tu_ev.get('id'), e)
        raise


def create_event_diff_embed(before_data: Dict[str, Any] = None, after_data: Dict[str, Any] = None, 
                           discord_before: ScheduledEvent = None, discord_after: ScheduledEvent = None,
                           action: str = "updated") -> tuple[str, Embed]:
    """Create a rich diff embed showing what changed in an event."""
    
    if discord_before and discord_after:
        before = {
            "title": discord_before.name,
            "start_dt": discord_before.start_time.isoformat() if discord_before.start_time else None,
            "end_dt": discord_before.end_time.isoformat() if discord_before.end_time else None,
            "location": discord_before.location or "",
            "description": discord_before.description or ""
        }
        after = {
            "title": discord_after.name,
            "start_dt": discord_after.start_time.isoformat() if discord_after.start_time else None,
            "end_dt": discord_after.end_time.isoformat() if discord_after.end_time else None,
            "location": discord_after.location or "",
            "description": discord_after.description or ""
        }
    else:
        before = before_data or {}
        after = after_data or {}
    
    changes = []
    notification_parts = []
    
    def format_datetime(dt_str):
        if not dt_str:
            return "Not set"
        try:
            dt_obj = dt.datetime.fromisoformat(dt_str)
            return dt_obj.strftime("%A, %B %d, %Y at %I:%M %p")
        except:
            return dt_str
    
    # Check for changes
    if before.get("title") != after.get("title"):
        changes.append("📝 **Name**")
        if before.get("title"):
            changes.append(f"~~{before['title']}~~")
        changes.append(f"**{after.get('title', 'Unknown')}**")
        notification_parts.append(f"name → \"{after.get('title', 'Unknown')}\"")
    
    if before.get("start_dt") != after.get("start_dt") or before.get("end_dt") != after.get("end_dt"):
        changes.append("\n🕒 **Time**")
        
        def format_time_range(start, end):
            if not start:
                return "Not set"
            start_formatted = format_datetime(start)
            if not end:
                return start_formatted
            
            try:
                start_dt = dt.datetime.fromisoformat(start)
                end_dt = dt.datetime.fromisoformat(end)
                if start_dt.date() == end_dt.date():
                    end_time = end_dt.strftime("%I:%M %p")
                    return f"{start_dt.strftime('%A, %B %d, %Y')} from {start_dt.strftime('%I:%M %p')} to {end_time}"
                else:
                    return f"{start_formatted} → {format_datetime(end)}"
            except:
                return f"{start_formatted} → {format_datetime(end)}"
        
        old_time = format_time_range(before.get("start_dt"), before.get("end_dt"))
        new_time = format_time_range(after.get("start_dt"), after.get("end_dt"))
        
        if old_time != "Not set":
            changes.append(f"~~{old_time}~~")
        changes.append(f"**{new_time}**")
        
        try:
            new_start = dt.datetime.fromisoformat(after.get("start_dt", ""))
            notification_parts.append(f"time → {new_start.strftime('%b %d at %I:%M %p')}")
        except:
            notification_parts.append("time changed")
    
    # Debug logging for location field types
    before_location = before.get("location", "")
    after_location = after.get("location", "")
    log.info("DEBUG: location comparison - before_type=%s, before_value=%r, after_type=%s, after_value=%r", 
             type(before_location).__name__, before_location,
             type(after_location).__name__, after_location)
    
    if before.get("location", "").strip() != after.get("location", "").strip():
        changes.append("\n📍 **Location**")
        old_loc = before.get("location", "").strip()
        new_loc = after.get("location", "").strip()
        
        if old_loc:
            changes.append(f"~~{old_loc}~~")
        changes.append(f"**{new_loc or 'No location'}**")
        notification_parts.append(f"location → \"{new_loc or 'removed'}\"")
    
    # Debug logging for notes field types
    before_notes = before.get("notes")
    after_notes = after.get("notes")
    log.info("DEBUG: notes comparison - before_notes_type=%s, before_notes_value=%r, after_notes_type=%s, after_notes_value=%r", 
             type(before_notes).__name__, before_notes,
             type(after_notes).__name__, after_notes)
    
    def extract_notes_text(notes_field):
        if isinstance(notes_field, dict) and 'html' in notes_field:
            return notes_field['html']
        elif isinstance(notes_field, str):
            return notes_field
        else:
            return ""
    
    old_desc = extract_notes_text(before.get("notes")).strip()
    new_desc = extract_notes_text(after.get("notes")).strip()
    
    if old_desc != new_desc:
        changes.append("\n📝 **Details**")
        if old_desc:
            display_old = old_desc[:100] + "..." if len(old_desc) > 100 else old_desc
            changes.append(f"~~{display_old}~~")
        
        if new_desc:
            display_new = new_desc[:200] + "..." if len(new_desc) > 200 else new_desc
            changes.append(f"**{display_new}**")
        else:
            changes.append("**Details removed**")
        
        notification_parts.append("details changed")
    
    if action == "cancelled":
        notification = f"🗑️ **Event cancelled**"
        embed_title = "🗑️ Event Cancelled"
        embed_color = 0xe74c3c
    else:
        if notification_parts:
            notification = f"✏️ **Event updated**: {', '.join(notification_parts)}"
        else:
            notification = f"✏️ **Event updated**"
        embed_title = "✏️ Event Updated"
        embed_color = 0xf1c40f
    
    embed = Embed(
        title=embed_title,
        description="\n".join(changes) if changes else "Event details have been updated.",
        color=embed_color,
        timestamp=dt.datetime.now(dt.timezone.utc)
    )
    
    return notification, embed


async def cleanup_thread(dc_id: int):
    """Clean up a thread when its associated event is deleted."""
    tid = THREAD_MAP.pop(dc_id, None)
    if tid:
        try:
            await rate_limit_discord("thread_action")
            th = await bot.fetch_channel(tid)  # type: ignore
            if hasattr(th, 'edit'):
                await th.edit(archived=True, reason="Event cancelled")
                log.info("Archived thread %s for deleted event %s", tid, dc_id)
        except discord.NotFound:
            log.debug("Thread %s already deleted", tid)
        except discord.RateLimited as e:
            log.warning("Rate limited while archiving thread, waiting %s seconds", e.retry_after)
            await asyncio.sleep(e.retry_after)
            # Don't retry - thread cleanup is not critical
        except Exception as e:
            log.warning("Failed to archive thread %s: %s", tid, e)
        finally:
            save_events()

async def post_in_thread(dc_id: int, content: str = None, embed: Embed = None):
    """Post update messages in event-specific threads for focused discussions."""
    tid = THREAD_MAP.get(dc_id)
    if tid:
        try:
            await rate_limit_discord("thread_post")
            th = await bot.fetch_channel(tid)  # type: ignore
            await th.send(content=content, embed=embed)
        except discord.NotFound:
            log.warning("Thread %s not found, removing from mapping", tid)
            THREAD_MAP.pop(dc_id, None)
            save_events()
        except discord.RateLimited as e:
            log.warning("Rate limited while posting to thread, waiting %s seconds", e.retry_after)
            await asyncio.sleep(e.retry_after)
            # Retry once
            try:
                th = await bot.fetch_channel(tid)  # type: ignore
                await th.send(content=content, embed=embed)
            except Exception as retry_e:
                log.error("Failed to post in thread after retry %s: %s", tid, retry_e)
        except Exception as e:
            log.error("Failed to post in thread %s: %s", tid, e)

# ----------------------------------------------------------------------------
# Discord ➜ Teamup gateway events
# ----------------------------------------------------------------------------
@bot.event
async def on_scheduled_event_create(event: ScheduledEvent):
    """Sync all Discord event types to Teamup for comprehensive calendar integration."""
    log.info("🎯 DISCORD EVENT CREATE TRIGGERED!")
    log.info("   Event ID: %s", event.id)
    log.info("   Event Name: %s", event.name)
    log.info("   Event Type: %s", event.entity_type)
    log.info("   Event Guild: %s", event.guild_id if hasattr(event, 'guild_id') else 'unknown')
    log.info("   Target Guild: %s", CFG.guild_id)
    log.info("   Already in mapping: %s", event.id in REVERSE_MAP)
    
    if event.id in REVERSE_MAP:
        log.warning("Event %s already exists in mapping, skipping create", event.id)
        return

    try:
        log.info("🔧 Starting Teamup event creation process...")
        check_bot_ready()
        log.info("✅ Bot ready check passed")
        
        await rate_limit_teamup()
        log.info("✅ Rate limit check passed")
        
        log.info("📅 Creating Teamup event for Discord event %s (type: %s, name: %s)", 
                event.id, event.entity_type, event.name)
        
        tu_id = await create_tu_event_from_dc(event)
        log.info("✅ Teamup event created with ID: %s", tu_id)
        
        EVENT_MAP[tu_id] = event.id
        REVERSE_MAP[event.id] = tu_id
        save_events()
        log.info("✅ Mappings saved successfully")
        log.info("🎉 Successfully created Teamup event %s for Discord event %s", tu_id, event.id)
    except Exception as e:
        log.error("❌ Failed to create Teamup event for Discord event %s: %s", event.id, e)
        import traceback
        log.error("Full traceback: %s", traceback.format_exc())

@bot.event
async def on_scheduled_event_update(before: ScheduledEvent, after: ScheduledEvent):
    """Sync Discord event updates to corresponding Teamup events."""
    log.info("🔄 DISCORD EVENT UPDATE TRIGGERED!")
    log.info("   Event ID: %s", after.id)
    log.info("   Event Name: %s -> %s", before.name, after.name)
    log.info("   Event Type: %s", after.entity_type)
    
    tu_id = REVERSE_MAP.get(after.id)
    if tu_id:
        log.info("✅ Found Teamup mapping: %s", tu_id)
        try:
            await update_tu_event(tu_id, after)
            
            notification, embed = create_event_diff_embed(
                discord_before=before,
                discord_after=after,
                action="updated"
            )
            await post_in_thread(after.id, content=notification, embed=embed)
            
            log.info("✅ Successfully updated Teamup event %s", tu_id)
        except Exception as e:
            log.error("❌ Failed to update Teamup event %s: %s", tu_id, e)
            import traceback
            log.error("Full traceback: %s", traceback.format_exc())
    else:
        log.warning("❌ No Teamup mapping found for Discord event %s", after.id)


@bot.event
async def on_scheduled_event_delete(event: ScheduledEvent):
    """Cascading cleanup maintains sync integrity when events are deleted."""
    log.info("🗑️ DISCORD EVENT DELETE TRIGGERED!")
    log.info("   Event ID: %s", event.id)
    log.info("   Event Name: %s", event.name)
    log.info("   Event Type: %s", event.entity_type)
    
    tu_id = REVERSE_MAP.pop(event.id, None)
    
    view = _active_views.pop(event.id, None)
    if view:
        view.cleanup()
        log.info("✅ Cleaned up view for event %s", event.id)
        
    if tu_id:
        log.info("✅ Found Teamup mapping: %s", tu_id)
        try:
            await delete_tu_event(tu_id)
            EVENT_MAP.pop(tu_id, None)
            
            notification, embed = create_event_diff_embed(
                after_data={"title": event.name},
                action="cancelled"
            )
            await post_in_thread(event.id, content=notification, embed=embed)
            
            await cleanup_thread(event.id)
            save_events()
            log.info("✅ Successfully deleted Teamup event %s for Discord event %s", tu_id, event.id)
        except Exception as e:
            log.error("❌ Failed to delete Teamup event %s: %s", tu_id, e)
            import traceback
            log.error("Full traceback: %s", traceback.format_exc())
    else:
        log.warning("❌ No Teamup mapping found for Discord event %s", event.id)

# ----------------------------------------------------------------------------
# Teamup webhook → Discord dispatcher (FastAPI)
# ----------------------------------------------------------------------------
app = FastAPI()

@app.get("/debug")
async def debug_endpoint():
    """Debug endpoint to view current mappings and Discord events."""
    try:
        g = guild()
        discord_events = []
        
        # Get current Discord events
        for event in await g.fetch_scheduled_events():
            discord_events.append({
                "id": event.id,
                "name": event.name,
                "type": str(event.entity_type),
                "location": event.location,
                "start_time": event.start_time.isoformat() if event.start_time else None,
                "in_mapping": event.id in REVERSE_MAP
            })
        
        return JSONResponse({
            "event_mappings": {
                "teamup_to_discord": EVENT_MAP,
                "discord_to_teamup": REVERSE_MAP,
                "thread_mappings": THREAD_MAP
            },
            "discord_events": discord_events,
            "cache_sizes": {
                "event_map": len(EVENT_MAP),
                "reverse_map": len(REVERSE_MAP),
                "thread_map": len(THREAD_MAP),
                "active_views": len(_active_views)
            }
        })
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.get("/health")
@app.head("/health")
async def health_endpoint():
    """Health check endpoint for UptimeRobot and Koyeb monitoring.
    
    Returns 200 OK when both Discord and Teamup APIs are accessible,
    503 Service Unavailable when any critical service is down.
    """
    try:
        discord_healthy = await health_check_discord()
        teamup_healthy = await health_check_teamup()
        
        status = {
            "status": "healthy" if (discord_healthy and teamup_healthy) else "degraded",
            "discord": "ok" if discord_healthy else "error",
            "teamup": "ok" if teamup_healthy else "error",
            "bot_ready": bot.is_ready(),
            "guild_available": bot.get_guild(CFG.guild_id) is not None if bot.is_ready() else False
        }
        
        if discord_healthy and teamup_healthy:
            return JSONResponse(status, status_code=200)
        else:
            return JSONResponse(status, status_code=503)
            
    except Exception as e:
        log.error("Health check endpoint error: %s", e)
        return JSONResponse({
            "status": "error",
            "error": str(e),
            "discord": "unknown",
            "teamup": "unknown",
            "bot_ready": False,
            "guild_available": False
        }, status_code=503)

async def sync_teamup_signup_to_discord(event_id: str, signup_name: str, is_signup: bool):
    """Sync Teamup signup/unsignup to Discord event interest."""
    dc_id = EVENT_MAP.get(event_id)
    if not dc_id:
        log.warning("No Discord event found for Teamup event %s", event_id)
        return
        
    try:
        # Find Discord user by display name (best effort matching)
        guild_obj = guild()
        user = None
        
        # Try exact match first
        for member in guild_obj.members:
            if member.display_name == signup_name:
                user = member
                break
                
        # Try case-insensitive match if exact fails
        if not user:
            signup_lower = signup_name.lower()
            for member in guild_obj.members:
                if member.display_name.lower() == signup_lower:
                    user = member
                    break
                    
        if not user:
            log.warning("Could not find Discord user with name '%s' for signup sync", signup_name)
            return
            
        dc_event = await guild_obj.fetch_scheduled_event(dc_id)
        
        if is_signup:
            await dc_event.add_user(user)
            log.info("Synced Teamup signup to Discord interest: %s for event %s", signup_name, event_id)
        else:
            await dc_event.remove_user(user)
            log.info("Synced Teamup unsignup to Discord disinterest: %s for event %s", signup_name, event_id)
            
    except discord.NotFound:
        log.warning("Discord event %s not found during signup sync", dc_id)
    except Exception as e:
        log.error("Failed to sync Teamup signup to Discord for user %s: %s", signup_name, e)


async def handle_teamup_trigger(trigger: str, data: Dict[str, Any]):
    """Webhook-driven sync ensures real-time Discord updates from Teamup changes."""
    async with _webhook_lock:
        manage_cache_size()

    try:
        # Handle event lifecycle triggers
        if trigger in ["event.created", "event.modified", "event.removed"]:
            ev = data.get("event")
            if not ev or "id" not in ev:
                log.warning("Invalid event data in webhook: %s", ev)
                return
                
            # Debug logging for complete event structure
            log.info("DEBUG: Full event data structure for event %s: %r", ev.get("id"), ev)
                
            tu_id = str(ev["id"])
            
            if trigger == "event.created":
                # Check if this is a Discord-originated event that came back via webhook
                remote_id = ev.get("remote_id", "")
                is_discord_originated = remote_id.startswith("dc-")
                
                if tu_id in EVENT_MAP:
                    if is_discord_originated:
                        # This is a Discord event that was synced to Teamup and came back via webhook
                        # We should still create the thread and embed, but not a new Discord event
                        dc_id = EVENT_MAP[tu_id]
                        log.info("Discord-originated event %s (Discord ID: %s) came back via webhook, creating thread", tu_id, dc_id)
                        
                        try:
                            # Check if thread already exists to avoid duplicates
                            if dc_id not in THREAD_MAP:
                                root, thread = await post_root_embed(ev, trigger)
                                THREAD_MAP[dc_id] = thread
                                save_events()
                                log.info("Created thread %s for existing Discord event %s (Teamup event %s)", thread, dc_id, tu_id)
                            else:
                                log.info("Thread already exists for Discord event %s", dc_id)
                        except Exception as e:
                            log.error("Failed to create thread for Discord-originated event %s: %s", tu_id, e)
                    else:
                        log.warning("Event %s already exists, skipping create", tu_id)
                    return
                    
                dc_id = await create_dc_event_from_tu(ev)
                
                try:
                    root, thread = await post_root_embed(ev, trigger)
                    EVENT_MAP[tu_id] = dc_id
                    REVERSE_MAP[dc_id] = tu_id
                    THREAD_MAP[dc_id] = thread
                    save_events()
                    log.info("Created Discord event %s with thread %s for Teamup event %s", dc_id, thread, tu_id)
                except Exception as e:
                    log.error("Failed to create thread for event %s: %s", tu_id, e)
                    try:
                        await cancel_dc_event(dc_id)
                    except Exception as cleanup_error:
                        log.error("Failed to cleanup Discord event %s after thread failure: %s", dc_id, cleanup_error)
                    raise
                return

            if trigger == "event.modified":
                dc_id = EVENT_MAP.get(tu_id)
                if not dc_id:
                    log.warning("No Discord event found for Teamup event %s", tu_id)
                    return
                
                try:
                    current_discord_event = await guild().fetch_scheduled_event(dc_id)
                    
                    notes_field = ev.get("notes")
                    if isinstance(notes_field, dict) and 'html' in notes_field:
                        teamup_notes = notes_field['html']
                    elif isinstance(notes_field, str):
                        teamup_notes = notes_field
                    else:
                        teamup_notes = ""
                    
                    teamup_after = {
                        "title": ev.get("title", ""),
                        "start_dt": ev.get("start_dt"),
                        "end_dt": ev.get("end_dt"), 
                        "location": ev.get("location", ""),
                        "notes": notes_field,
                        "description": teamup_notes
                    }
                    
                    discord_before = {
                        "title": current_discord_event.name,
                        "start_dt": current_discord_event.start_time.isoformat() if current_discord_event.start_time else None,
                        "end_dt": current_discord_event.end_time.isoformat() if current_discord_event.end_time else None,
                        "location": current_discord_event.location or "",
                        "description": current_discord_event.description or ""
                    }
                    
                    await update_dc_event(dc_id, ev)
                    
                    notification, embed = create_event_diff_embed(
                        before_data=discord_before,
                        after_data=teamup_after,
                        action="updated"
                    )
                    
                    
                    await post_in_thread(dc_id, content=notification, embed=embed)
                    
                except discord.NotFound:
                    log.warning("Discord event %s not found during Teamup update", dc_id)
                except Exception as e:
                    log.warning("Failed to post thread update for event %s: %s", dc_id, e)
                return

            if trigger == "event.removed":
                dc_id = EVENT_MAP.pop(tu_id, None)
                if dc_id:
                    REVERSE_MAP.pop(dc_id, None)
                    save_events()
                    
                    try:
                        await cancel_dc_event(dc_id)
                        
                        notification, embed = create_event_diff_embed(
                            after_data={"title": ev.get("title", "Event")},
                            action="cancelled"
                        )
                        await post_in_thread(dc_id, content=notification, embed=embed)
                        
                        await cleanup_thread(dc_id)
                    except Exception as e:
                        log.error("Failed to cancel Discord event %s: %s", dc_id, e)
                        try:
                            await cleanup_thread(dc_id)
                        except Exception as cleanup_e:
                            log.error("Failed to cleanup thread after event cancellation failure: %s", cleanup_e)
                return
                
        # Handle signup lifecycle triggers  
        elif trigger in ["event_signup.created", "event_signup.removed"]:
            signup = data.get("signup")
            event_id = data.get("event_id")
            
            if not signup or not event_id:
                log.warning("Invalid signup data in webhook: signup=%s, event_id=%s", signup, event_id)
                return
                
            signup_name = signup.get("name")
            if not signup_name:
                log.warning("Signup missing name field: %s", signup)
                return
                
            is_signup = trigger == "event_signup.created"
            await sync_teamup_signup_to_discord(str(event_id), signup_name, is_signup)
            return
            
        elif trigger == "event_signup.modified":
            # For modified signups, we don't need to sync anything to Discord
            # since Discord only has binary interested/not interested state
            log.debug("Ignoring signup modification (no Discord equivalent): %s", data)
            return
            
        # Handle other triggers we don't care about
        elif trigger.startswith("event_comment."):
            log.debug("Ignoring comment trigger (not implemented): %s", trigger)
            return
            
        else:
            log.warning("Unknown trigger received: %s", trigger)
            return
                    
    except Exception as e:
        log.error("Failed to handle Teamup trigger '%s': %s", trigger, e)
        raise

@app.post("/teamup")
async def teamup_webhook(req: Request):
    """Secure webhook endpoint for Teamup notifications with HMAC validation.
    
    HMAC signature verification prevents unauthorized webhook calls that could
    trigger unwanted Discord events or manipulate the sync state.
    """
    try:
        raw = await req.body()
        sig = req.headers.get("Teamup-Signature", "")
        
        # Log detailed webhook information for debugging
        log.info("Received webhook request:")
        log.info("  Headers: %s", dict(req.headers))
        log.info("  Raw body: %s", raw.decode('utf-8', errors='replace'))
        log.info("  Signature: %s", sig)
        
        # Skip signature verification if webhook secret is not configured
        if CFG.webhook_secret and not verify_webhook_signature(raw, sig, CFG.webhook_secret):
            log.warning("HMAC signature verification failed")
            raise HTTPException(status_code=401, detail="Bad signature")
            
        payload = json.loads(raw)
        log.info("  Parsed payload: %s", payload)
        
        # Handle webhook verification requests (Teamup sends these when setting up webhooks)
        if not isinstance(payload, dict):
            log.warning("Payload is not a dictionary, treating as verification")
            return JSONResponse({"ok": True, "status": "verification_received"})
            
        # Handle verification/ping requests that might have different structure
        if "dispatch" not in payload:
            log.info("No 'dispatch' key found - might be a verification request")
            return JSONResponse({"ok": True, "status": "verification_ok"})
        
        # Handle dispatch as either array or single object
        if isinstance(payload["dispatch"], list):
            if len(payload["dispatch"]) == 0:
                log.info("Empty dispatch array - webhook verification request")
                return JSONResponse({"ok": True, "status": "verification_ok"})
            
            # Process each dispatch item in the array
            log.info("Processing %d dispatch items", len(payload["dispatch"]))
            results = []
            for i, dispatch_item in enumerate(payload["dispatch"]):
                try:
                    log.info("Processing dispatch item %d: %s", i + 1, dispatch_item.get("trigger", "unknown"))
                    
                    if "trigger" not in dispatch_item:
                        log.warning("Missing trigger in dispatch item %d: %s", i + 1, dispatch_item)
                        continue
                        
                    # Check if we can process the webhook (graceful degradation)
                    if not await health_check_discord():
                        log.warning("Discord unavailable, skipping dispatch item %d", i + 1)
                        continue
                    
                    await handle_teamup_trigger(dispatch_item["trigger"], dispatch_item)
                    results.append({"item": i + 1, "status": "success"})
                    
                except Exception as e:
                    log.error("Failed to process dispatch item %d: %s", i + 1, e)
                    results.append({"item": i + 1, "status": "error", "error": str(e)})
            
            return JSONResponse({"ok": True, "processed": len(results), "results": results})
        
        # Handle single dispatch object (legacy format)
        elif isinstance(payload["dispatch"], dict):
            dispatch_item = payload["dispatch"]
            
            if "trigger" not in dispatch_item:
                log.warning("Missing trigger in dispatch: %s", dispatch_item)
                raise HTTPException(status_code=400, detail="Missing trigger")
                
            # Check if we can process the webhook (graceful degradation)
            if not await health_check_discord():
                log.warning("Discord unavailable, deferring webhook processing")
                raise HTTPException(status_code=503, detail="Discord service unavailable")
            
            await handle_teamup_trigger(dispatch_item["trigger"], dispatch_item)
            return JSONResponse({"ok": True})
        
        else:
            log.warning("Dispatch is neither array nor object: %s", payload["dispatch"])
            raise HTTPException(status_code=400, detail="Invalid dispatch format")
            
    except HTTPException:
        raise
    except json.JSONDecodeError as e:
        log.error("Failed to parse JSON: %s", e)
        log.error("Raw body was: %s", raw.decode('utf-8', errors='replace'))
        raise HTTPException(status_code=400, detail="Invalid JSON")
    except Exception as e:
        log.error("Webhook processing error: %s", e)
        log.error("Raw body was: %s", raw.decode('utf-8', errors='replace') if 'raw' in locals() else 'unavailable')
        raise HTTPException(status_code=500, detail="Internal server error")

# ----------------------------------------------------------------------------
# Bot ready: register view & rebuild state
# ----------------------------------------------------------------------------
# Helper function to maintain mapping consistency
def cleanup_mappings():
    """Clean up any inconsistent mappings between EVENT_MAP and REVERSE_MAP."""
    # Rebuild REVERSE_MAP from EVENT_MAP to ensure consistency
    global REVERSE_MAP
    REVERSE_MAP = {v: k for k, v in EVENT_MAP.items()}
    
    # Remove any views for events that are no longer in our mappings
    for dc_id in list(_active_views.keys()):
        if dc_id not in REVERSE_MAP:
            view = _active_views.pop(dc_id, None)
            if view:
                view.cleanup()


@bot.event
async def on_ready():
    """Initialize bot state and register persistent UI components."""
    try:
        log.info("🚀 Bot connected, initializing...")
        log.info("   Bot user: %s", bot.user)
        log.info("   Bot ID: %s", bot.user.id)
        
        # Log intents for debugging
        log.info("🔧 Bot intents:")
        log.info("   members: %s", bot.intents.members)
        log.info("   guilds: %s", bot.intents.guilds)
        log.info("   guild_scheduled_events: %s", bot.intents.guild_scheduled_events)
        log.info("   message_content: %s", bot.intents.message_content)
        
        # Validate configuration first
        validate_config()
        log.info("✅ Configuration validated")
        
        # Check dependencies
        await check_dependencies()
        log.info("✅ Dependencies checked")
        
        # Check guild access
        target_guild = bot.get_guild(CFG.guild_id)
        if target_guild:
            log.info("✅ Target guild found: %s", target_guild.name)
            log.info("   Guild member count: %s", target_guild.member_count)
            log.info("   Bot permissions: %s", target_guild.me.guild_permissions.value if target_guild.me else 'unknown')
            
            # List existing events
            events = await target_guild.fetch_scheduled_events()
            log.info("📅 Found %d existing scheduled events:", len(events))
            for event in events:
                log.info("   - %s (ID: %s, Type: %s)", event.name, event.id, event.entity_type)
        else:
            log.error("❌ Target guild not found! Guild ID: %s", CFG.guild_id)
        
        bot.add_view(PersistentSignupView())  # global persistence for buttons
        log.info("✅ Persistent view added")
        
        await rebuild_state()
        log.info("✅ State rebuilt")
        
        # Ensure mapping consistency
        cleanup_mappings()
        log.info("✅ Mappings cleaned up")
        
        # Clean up any stale views from previous runs
        log.info("🧹 Cleaning up stale views...")
        for dc_id in list(_active_views.keys()):
            try:
                await guild().fetch_scheduled_event(dc_id)
            except discord.NotFound:
                # Event no longer exists, cleanup view
                view = _active_views.pop(dc_id, None)
                if view:
                    view.cleanup()
        
        # Run initial cache management
        manage_cache_size()
        log.info("✅ Cache management completed")
                    
        log.info("🎉 Bot ready - logged in as %s with %d active views", bot.user, len(_active_views))
        log.info("🎯 Bot is now listening for Discord scheduled event changes...")
        
    except Exception as e:
        log.error("❌ Failed to initialize bot: %s", e)
        import traceback
        log.error("Full traceback: %s", traceback.format_exc())
        raise

# ----------------------------------------------------------------------------
# Run both FastAPI + Discord bot under uvicorn
# ----------------------------------------------------------------------------
# Background health monitoring
async def health_monitor():
    """Periodically check system health and log warnings."""
    while True:
        try:
            await asyncio.sleep(300)  # Check every 5 minutes
            healthy = await check_dependencies()
            if not healthy:
                log.warning("System health check failed - some services may be degraded")
        except asyncio.CancelledError:
            break
        except Exception as e:
            log.error("Health monitor error: %s", e)

async def start_all():
    """Concurrent services enable bidirectional sync - Discord events + Teamup webhooks."""
    try:
        validate_config()
        
        loop = asyncio.get_running_loop()
        bot_task = loop.create_task(bot.start(CFG.discord_token))
        
        config = uvicorn.Config(
            app, 
            host=CFG.host, 
            port=CFG.port, 
            log_level="info",
            log_config=None  # Use system logging instead of uvicorn's default
        )
        server = uvicorn.Server(config)
        server_task = loop.create_task(server.serve())
        
        health_task = loop.create_task(health_monitor())
        
        done, pending = await asyncio.wait(
            [bot_task, server_task, health_task], 
            return_when=asyncio.FIRST_COMPLETED
        )
        
        for task in pending:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
                
    except Exception as e:
        log.error("Failed to start services: %s", e)
        raise
    finally:
        # Cleanup resources
        try:
            await cleanup_resources()
        except Exception as e:
            log.error("Failed to cleanup resources: %s", e)

# Add bot readiness check
def check_bot_ready():
    """Ensure bot is ready before processing events."""
    if not bot.is_ready():
        raise RuntimeError("Bot not ready")
    if not bot.get_guild(CFG.guild_id):
        raise RuntimeError("Guild not available")

# Clean up active views more aggressively
def cleanup_active_views():
    """Clean up all active views and prevent memory leaks."""
    global _active_views
    for view in _active_views.values():
        view.cleanup()
    _active_views.clear()

# Add proper resource cleanup on exit
import signal
import atexit

async def cleanup_resources():
    """Clean up all resources before shutdown."""
    try:
        cleanup_active_views()
        if client and not client.is_closed:
            await client.aclose()
        log.info("Resources cleaned up successfully")
    except Exception as e:
        log.error("Error during cleanup: %s", e)

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    log.info("Received shutdown signal %s", signum)
    asyncio.create_task(cleanup_resources())

# Register cleanup handlers
signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)
atexit.register(lambda: asyncio.run(cleanup_resources()))

if __name__ == "__main__":
    asyncio.run(start_all())