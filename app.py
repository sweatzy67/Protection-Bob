import discord
from discord.ext import commands
from discord import app_commands
import os
import json
from pathlib import Path
from dotenv import load_dotenv
import time
from collections import defaultdict, deque

dotenv_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path)
TOKEN = os.getenv('DISCORD_TOKEN')

intents = discord.Intents.default()
intents.message_content = True
intents.members = True

bot = commands.Bot(command_prefix='!', intents=intents)

SPAM_THRESHOLD = 5  # msgs in time window
SPAM_TIME_WINDOW = 5  # seconds
user_messages = {}

RAID_THRESHOLD = 4  # people joining = raid
RAID_TIME_WINDOW = 10  # seconds to count
recent_joins = []

DATA_FILE = Path(__file__).resolve().parent / "guild_settings.json"

# action limits for nuke detection
NUKE_ACTION_WINDOW = 10
MAX_CHANNEL_DELETES = 3
MAX_CHANNEL_CREATES = 5
MAX_ROLE_DELETES = 3
MAX_BANS = 5
MAX_KICKS = 5
MAX_WEBHOOK_CREATES = 3

UNVERIFIED_ROLE_NAME = "Unverified Bot"


def load_settings():
    if DATA_FILE.exists():
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def save_settings(data):
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


guild_settings = load_settings()


def get_guild_settings(guild_id: int) -> dict:
    key = str(guild_id)
    if key not in guild_settings:
        guild_settings[key] = {
            "setup_complete": False,
            "bot_approver_id": None,
            "bot_approver_is_role": False,
            "accept_channel_id": None,
            "unverified_role_id": None,
            "log_channel_id": None,
            "whitelist": [],
        }
        save_settings(guild_settings)
    return guild_settings[key]


def update_guild_settings(guild_id: int, **kwargs):
    settings = get_guild_settings(guild_id)
    settings.update(kwargs)
    save_settings(guild_settings)
    return settings


action_tracker: dict[int, dict[int, dict[str, deque]]] = defaultdict(
    lambda: defaultdict(lambda: defaultdict(deque))
)

punishment_in_progress: set[tuple[int, int]] = set()

pending_bot_requests: dict[int, dict[int, dict]] = defaultdict(dict)


def record_action(guild_id: int, user_id: int, action_type: str, limit: int, window: int = NUKE_ACTION_WINDOW) -> bool:
    # basically checks if someone's doing too much sketchy stuff in a short time
    # returns true if they've crossed the line
    now = time.time()
    dq = action_tracker[guild_id][user_id][action_type]
    dq.append(now)
    while dq and now - dq[0] > window:
        dq.popleft()
    return len(dq) > limit


async def is_whitelisted(guild: discord.Guild, user_id: int) -> bool:
    # people on this list never get punished - owner, bot itself, manually added users
    settings = get_guild_settings(guild.id)
    if user_id == guild.owner_id:
        return True
    if user_id == bot.user.id:
        return True
    if user_id in settings.get("whitelist", []):
        return True
    return False


async def get_audit_log_actor(guild: discord.Guild, action: discord.AuditLogAction, target_id: int | None = None):
    # finds who did the thing from the audit log
    # helps us identify nukers and spammers
    try:
        async for entry in guild.audit_logs(limit=5, action=action):
            if target_id is None or (entry.target and entry.target.id == target_id):
                if (discord.utils.utcnow() - entry.created_at).total_seconds() < 8:
                    return entry.user
    except discord.Forbidden:
        return None
    return None


async def punish_actor(guild: discord.Guild, actor: discord.Member, reason: str):
    # gets rid of nukers - either kicks bots or bans humans
    # also logs it if we have a log channel set up
    key = (guild.id, actor.id)
    if key in punishment_in_progress:
        return
    punishment_in_progress.add(key)
    try:
        if await is_whitelisted(guild, actor.id):
            return

        settings = get_guild_settings(guild.id)
        log_channel = None
        if settings.get("log_channel_id"):
            log_channel = guild.get_channel(settings["log_channel_id"])

        try:
            if actor.bot:
                await guild.kick(actor, reason=f"Anti-Nuke: {reason}")
                action_taken = "kicked (bot)"
            else:
                await guild.ban(actor, reason=f"Anti-Nuke: {reason}", delete_message_seconds=0)
                action_taken = "banned"
        except discord.Forbidden:
            action_taken = "FAILED (missing perms)"
        except discord.HTTPException:
            action_taken = "FAILED (http error)"

        embed = discord.Embed(
            title="🚨 Anti-Nuke ausgelöst",
            description=f"**Nutzer:** {actor.mention} (`{actor.id}`)\n**Grund:** {reason}\n**Aktion:** {action_taken}",
            color=discord.Color.red(),
            timestamp=discord.utils.utcnow(),
        )
        if log_channel:
            try:
                await log_channel.send(embed=embed)
            except discord.Forbidden:
                pass
        else:
            # fallback: use system channel if no log channel
            if guild.system_channel:
                try:
                    await guild.system_channel.send(embed=embed)
                except discord.Forbidden:
                    pass
    finally:
        punishment_in_progress.discard(key)


class BotAcceptView(discord.ui.View):
    # the buttons that pop up when a new bot joins
    # admins can accept or deny from here

    def __init__(self):
        super().__init__(timeout=None)

    async def _authorized(self, interaction: discord.Interaction, settings: dict) -> bool:
        approver_id = settings.get("bot_approver_id")
        if approver_id is None:
            await interaction.response.send_message(
                "❌ Es ist kein Bot-Approver konfiguriert. Nutze `/setup`.", ephemeral=True
            )
            return False

        if settings.get("bot_approver_is_role"):
            role = interaction.guild.get_role(approver_id)
            if role is None or role not in interaction.user.roles:
                await interaction.response.send_message(
                    "❌ you don't have the role needed to approve bots", ephemeral=True
                )
                return False
        else:
            if interaction.user.id != approver_id:
                await interaction.response.send_message(
                    "❌ you're not authorized to approve bots", ephemeral=True
                )
                return False
        return True

    @discord.ui.button(label="Akzeptieren", style=discord.ButtonStyle.green, custom_id="bot_accept_button", emoji="✅")
    async def accept(self, interaction: discord.Interaction, button: discord.ui.Button):
        guild = interaction.guild
        settings = get_guild_settings(guild.id)

        if not await self._authorized(interaction, settings):
            return

        bot_id = self._extract_bot_id(interaction.message)
        if bot_id is None:
            await interaction.response.send_message("❌ Konnte den Bot zu dieser Anfrage nicht zuordnen.", ephemeral=True)
            return

        member = guild.get_member(bot_id)
        if member is None:
            await interaction.response.send_message("❌ bot's not on the server anymore", ephemeral=True)
            await interaction.message.edit(view=None)
            return

        role_id = settings.get("unverified_role_id")
        role = guild.get_role(role_id) if role_id else None
        if role and role in member.roles:
            try:
                await member.remove_roles(role, reason=f"Bot akzeptiert von {interaction.user}")
            except discord.Forbidden:
                await interaction.response.send_message(
                    "⚠️ bot was approved but couldn't remove the role (no perms)",
                    ephemeral=True,
                )

        pending_bot_requests[guild.id].pop(bot_id, None)

        embed = interaction.message.embeds[0] if interaction.message.embeds else discord.Embed()
        embed.color = discord.Color.green()
        embed.add_field(name="Status", value=f"✅ Approved by {interaction.user.mention}", inline=False)
        for item in self.children:
            item.disabled = True
        await interaction.response.edit_message(embed=embed, view=self)

        try:
            await member.send(f"✅ you got approved on **{guild.name}** - full access now")
        except discord.Forbidden:
            pass

    @discord.ui.button(label="Ablehnen", style=discord.ButtonStyle.red, custom_id="bot_deny_button", emoji="❌")
    async def deny(self, interaction: discord.Interaction, button: discord.ui.Button):
        guild = interaction.guild
        settings = get_guild_settings(guild.id)

        if not await self._authorized(interaction, settings):
            return

        bot_id = self._extract_bot_id(interaction.message)
        if bot_id is None:
            await interaction.response.send_message("❌ Konnte den Bot zu dieser Anfrage nicht zuordnen.", ephemeral=True)
            return

        member = guild.get_member(bot_id)
        pending_bot_requests[guild.id].pop(bot_id, None)

        embed = interaction.message.embeds[0] if interaction.message.embeds else discord.Embed()
        embed.color = discord.Color.red()
        embed.add_field(name="Status", value=f"❌ Denied by {interaction.user.mention}", inline=False)
        for item in self.children:
            item.disabled = True
        await interaction.response.edit_message(embed=embed, view=self)

        if member is not None:
            try:
                await member.kick(reason=f"Bot-Anfrage abgelehnt von {interaction.user}")
            except discord.Forbidden:
                await interaction.followup.send(
                    "⚠️ bot was denied but couldn't get kicked (no perms). remove manually",
                    ephemeral=True,
                )

    @staticmethod
    def _extract_bot_id(message: discord.Message) -> int | None:
        if not message.embeds:
            return None
        footer = message.embeds[0].footer
        if footer and footer.text and footer.text.startswith("BotID:"):
            try:
                return int(footer.text.split("BotID:")[1].strip())
            except ValueError:
                return None
        return None


# ====================
# TICKET SYSTEM - still works from before
# ====================
# just basic support tickets with buttons

class TicketButton(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Ticket erstellen", style=discord.ButtonStyle.green, custom_id="ticket_button")
    async def create_ticket(self, interaction: discord.Interaction, button: discord.ui.Button):
        guild = interaction.guild
        
        ticket_name = f"ticket-{interaction.user.name.lower()}"
        existing_channel = discord.utils.get(guild.text_channels, name=ticket_name)

        if existing_channel:
            await interaction.response.send_message("Du hast bereits ein offenes Ticket!", ephemeral=True)
            return

        overwrites = {
            guild.default_role: discord.PermissionOverwrite(read_messages=False),
            interaction.user: discord.PermissionOverwrite(read_messages=True, send_messages=True),
            guild.me: discord.PermissionOverwrite(read_messages=True, send_messages=True)
        }

        category = discord.utils.get(guild.categories, name="Tickets")
        if not category:
            category = await guild.create_category("Tickets")

        ticket_channel = await guild.create_text_channel(name=ticket_name, category=category, overwrites=overwrites)
        
        await interaction.response.send_message(f"Dein Ticket wurde erstellt: {ticket_channel.mention}", ephemeral=True)
        await ticket_channel.send(f"Hallo {interaction.user.mention}, bitte beschreibe dein Problem. Ein Teammitglied wird dir gleich helfen.")


setup_group = app_commands.Group(name="setup", description="Konfiguriert das Anti-Raid & Bot-Accept System")


@setup_group.command(name="start", description="Startet die Einrichtung: Approver, Accept-Channel, Unverified-Rolle")
@app_commands.describe(
    approver="User ODER Rolle, die neue Bots akzeptieren/ablehnen darf",
    accept_channel="Kanal, in dem neue Bot-Anfragen gepostet werden",
    log_channel="(Optional) Kanal für Anti-Nuke Alerts",
)
async def setup_start(
    interaction: discord.Interaction,
    approver: discord.Role | discord.Member,
    accept_channel: discord.TextChannel,
    log_channel: discord.TextChannel | None = None,
):
    if not interaction.user.guild_permissions.administrator:
        await interaction.response.send_message("❌ Nur Administratoren dürfen das Setup ausführen.", ephemeral=True)
        return

    await interaction.response.defer(ephemeral=True, thinking=True)
    guild = interaction.guild

    existing_role = discord.utils.get(guild.roles, name=UNVERIFIED_ROLE_NAME)
    if existing_role:
        unverified_role = existing_role
    else:
        try:
            unverified_role = await guild.create_role(
                name=UNVERIFIED_ROLE_NAME,
                permissions=discord.Permissions.none(),
                color=discord.Color.dark_grey(),
                reason="Anti-Raid Setup: Rolle für nicht akzeptierte Bots",
            )
        except discord.Forbidden:
            await interaction.followup.send(
                "❌ Ich habe keine Berechtigung, Rollen zu erstellen. Bitte gib mir 'Rollen verwalten'.",
                ephemeral=True,
            )
            return

    failed_channels = []
    for channel in guild.channels:
        try:
            overwrite = channel.overwrites_for(unverified_role)
            overwrite.view_channel = False
            overwrite.send_messages = False
            overwrite.connect = False
            await channel.set_permissions(unverified_role, overwrite=overwrite, reason="Anti-Raid Setup")
        except discord.Forbidden:
            failed_channels.append(channel.name)
        except discord.HTTPException:
            failed_channels.append(channel.name)

    is_role = isinstance(approver, discord.Role)
    update_guild_settings(
        guild.id,
        setup_complete=True,
        bot_approver_id=approver.id,
        bot_approver_is_role=is_role,
        accept_channel_id=accept_channel.id,
        unverified_role_id=unverified_role.id,
        log_channel_id=log_channel.id if log_channel else None,
    )

    embed = discord.Embed(
        title="✅ Anti-Raid Setup abgeschlossen",
        color=discord.Color.green(),
        description=(
            f"**Bot-Approver:** {approver.mention} ({'Rolle' if is_role else 'User'})\n"
            f"**Accept-Channel:** {accept_channel.mention}\n"
            f"**Unverified-Rolle:** {unverified_role.mention}\n"
            f"**Log-Channel:** {log_channel.mention if log_channel else 'Nicht gesetzt'}"
        ),
    )
    if failed_channels:
        embed.add_field(
            name="⚠️ Hinweis",
            value=f"Konnte Rechte in {len(failed_channels)} Kanälen nicht setzen (fehlende Berechtigung): "
                  + ", ".join(failed_channels[:10]),
            inline=False,
        )
    await interaction.followup.send(embed=embed, ephemeral=True)


@setup_group.command(name="whitelist_add", description="Fügt einen User zur Anti-Nuke Whitelist hinzu (nie bestraft)")
async def setup_whitelist_add(interaction: discord.Interaction, user: discord.Member):
    if not interaction.user.guild_permissions.administrator:
        await interaction.response.send_message("❌ Nur Administratoren.", ephemeral=True)
        return
    settings = get_guild_settings(interaction.guild.id)
    wl = settings.get("whitelist", [])
    if user.id not in wl:
        wl.append(user.id)
        update_guild_settings(interaction.guild.id, whitelist=wl)
    await interaction.response.send_message(f"✅ {user.mention} zur Whitelist hinzugefügt.", ephemeral=True)


@setup_group.command(name="status", description="Zeigt die aktuelle Anti-Raid Konfiguration dieses Servers")
async def setup_status(interaction: discord.Interaction):
    settings = get_guild_settings(interaction.guild.id)
    if not settings.get("setup_complete"):
        await interaction.response.send_message("⚠️ Das Setup wurde noch nicht abgeschlossen. Nutze `/setup start`.", ephemeral=True)
        return

    guild = interaction.guild
    approver_mention = "Nicht gesetzt"
    if settings.get("bot_approver_id"):
        if settings.get("bot_approver_is_role"):
            role = guild.get_role(settings["bot_approver_id"])
            approver_mention = role.mention if role else "Rolle gelöscht"
        else:
            approver_mention = f"<@{settings['bot_approver_id']}>"

    accept_channel = guild.get_channel(settings.get("accept_channel_id")) if settings.get("accept_channel_id") else None
    log_channel = guild.get_channel(settings.get("log_channel_id")) if settings.get("log_channel_id") else None
    unverified_role = guild.get_role(settings.get("unverified_role_id")) if settings.get("unverified_role_id") else None

    embed = discord.Embed(title="⚙️ Anti-Raid Konfiguration", color=discord.Color.blurple())
    embed.add_field(name="Bot-Approver", value=approver_mention, inline=False)
    embed.add_field(name="Accept-Channel", value=accept_channel.mention if accept_channel else "Nicht gesetzt", inline=False)
    embed.add_field(name="Unverified-Rolle", value=unverified_role.mention if unverified_role else "Nicht gesetzt", inline=False)
    embed.add_field(name="Log-Channel", value=log_channel.mention if log_channel else "Nicht gesetzt", inline=False)
    embed.add_field(name="Whitelist", value=str(len(settings.get("whitelist", []))) + " User", inline=False)
    await interaction.response.send_message(embed=embed, ephemeral=True)


bot.tree.add_command(setup_group)


@bot.event
async def on_ready():
    print(f'Bot logged in as {bot.user}!')
    bot.add_view(TicketButton())
    bot.add_view(BotAcceptView())
    try:
        synced = await bot.tree.sync()
        print(f"{len(synced)} commands synced")
    except discord.HTTPException as e:
        print(f"error syncing commands: {e}")


@bot.event
async def on_member_join(member: discord.Member):
    # when someone joins - either it's a bot we need to verify
    # or it could be a raid attempt, so we gotta watch
    guild = member.guild
    settings = get_guild_settings(guild.id)

    if member.bot:
        if not settings.get("setup_complete"):
            return

        role_id = settings.get("unverified_role_id")
        role = guild.get_role(role_id) if role_id else None
        if role:
            try:
                await member.add_roles(role, reason="Neuer Bot: wartet auf Freigabe")
            except discord.Forbidden:
                pass

        # figure out who added this bot
        added_by = await get_audit_log_actor(guild, discord.AuditLogAction.bot_add, target_id=member.id)

        accept_channel_id = settings.get("accept_channel_id")
        accept_channel = guild.get_channel(accept_channel_id) if accept_channel_id else None
        if accept_channel:
            embed = discord.Embed(
                title="🤖 Neuer Bot wartet auf Freigabe",
                description=f"**Bot:** {member.mention} (`{member.name}`)\n"
                             f"**Hinzugefügt von:** {added_by.mention if added_by else 'Unbekannt'}\n\n"
                             f"Bitte akzeptieren oder ablehnen.",
                color=discord.Color.orange(),
                timestamp=discord.utils.utcnow(),
            )
            embed.set_thumbnail(url=member.display_avatar.url)
            embed.set_footer(text=f"BotID:{member.id}")
            try:
                msg = await accept_channel.send(embed=embed, view=BotAcceptView())
                pending_bot_requests[guild.id][member.id] = {
                    "message_id": msg.id,
                    "added_by": added_by.id if added_by else None,
                }
            except discord.Forbidden:
                pass
        return

    current_time = time.time()
    recent_joins.append(current_time)
    recent_joins[:] = [t for t in recent_joins if current_time - t < RAID_TIME_WINDOW]

    if len(recent_joins) > RAID_THRESHOLD:
        print(f"raid detected! kicking {member.name}")
        try:
            await member.kick(reason="Anti-Raid System aktiv")
        except discord.Forbidden:
            print("Fehler: Der Bot hat keine Rechte zum Kicken.")


@bot.event
async def on_message(message: discord.Message):
    # watch for spam - simple check just counts msgs
    if message.author == bot.user or message.author.bot:
        return

    author_id = message.author.id
    current_time = time.time()

    if author_id not in user_messages:
        user_messages[author_id] = []

    user_messages[author_id].append(current_time)
    user_messages[author_id] = [t for t in user_messages[author_id] if current_time - t < SPAM_TIME_WINDOW]

    if len(user_messages[author_id]) > SPAM_THRESHOLD:
        try:
            await message.delete()
            await message.channel.send(f"⚠️ {message.author.mention}, stop spamming!", delete_after=5)
        except discord.Forbidden:
            pass

    await bot.process_commands(message)


@bot.event
async def on_guild_channel_delete(channel: discord.abc.GuildChannel):
    guild = channel.guild
    settings = get_guild_settings(guild.id)
    if not settings.get("setup_complete"):
        return

    actor = await get_audit_log_actor(guild, discord.AuditLogAction.channel_delete, target_id=channel.id)
    if actor is None or await is_whitelisted(guild, actor.id):
        return

    if record_action(guild.id, actor.id, "channel_delete", MAX_CHANNEL_DELETES):
        await punish_actor(guild, actor, f"Zu viele Kanal-Löschungen ({MAX_CHANNEL_DELETES}+ in {NUKE_ACTION_WINDOW}s)")


@bot.event
async def on_guild_channel_create(channel: discord.abc.GuildChannel):
    guild = channel.guild
    settings = get_guild_settings(guild.id)
    if not settings.get("setup_complete"):
        return

    actor = await get_audit_log_actor(guild, discord.AuditLogAction.channel_create, target_id=channel.id)
    if actor is None or await is_whitelisted(guild, actor.id):
        return

    if record_action(guild.id, actor.id, "channel_create", MAX_CHANNEL_CREATES):
        await punish_actor(guild, actor, f"Zu viele Kanal-Erstellungen ({MAX_CHANNEL_CREATES}+ in {NUKE_ACTION_WINDOW}s, Spam-Kanal-Nuke)")


@bot.event
async def on_guild_role_delete(role: discord.Role):
    guild = role.guild
    settings = get_guild_settings(guild.id)
    if not settings.get("setup_complete"):
        return

    actor = await get_audit_log_actor(guild, discord.AuditLogAction.role_delete, target_id=role.id)
    if actor is None or await is_whitelisted(guild, actor.id):
        return

    if record_action(guild.id, actor.id, "role_delete", MAX_ROLE_DELETES):
        await punish_actor(guild, actor, f"Zu viele Rollen-Löschungen ({MAX_ROLE_DELETES}+ in {NUKE_ACTION_WINDOW}s)")


@bot.event
async def on_member_ban(guild: discord.Guild, user: discord.User):
    settings = get_guild_settings(guild.id)
    if not settings.get("setup_complete"):
        return

    actor = await get_audit_log_actor(guild, discord.AuditLogAction.ban, target_id=user.id)
    if actor is None or await is_whitelisted(guild, actor.id):
        return

    if record_action(guild.id, actor.id, "ban", MAX_BANS):
        await punish_actor(guild, actor, f"Zu viele Bans ({MAX_BANS}+ in {NUKE_ACTION_WINDOW}s, Massen-Bann-Verdacht)")


@bot.event
async def on_member_remove(member: discord.Member):
    # detects if someone's mass kicking
    # gotta tell the difference between leaving and getting booted
    guild = member.guild
    settings = get_guild_settings(guild.id)
    if not settings.get("setup_complete"):
        return

    actor = await get_audit_log_actor(guild, discord.AuditLogAction.kick, target_id=member.id)
    if actor is None or await is_whitelisted(guild, actor.id):
        return

    if record_action(guild.id, actor.id, "kick", MAX_KICKS):
        await punish_actor(guild, actor, f"Zu viele Kicks ({MAX_KICKS}+ in {NUKE_ACTION_WINDOW}s, Massen-Kick-Verdacht)")


@bot.event
async def on_webhooks_update(channel: discord.abc.GuildChannel):
    guild = channel.guild
    settings = get_guild_settings(guild.id)
    if not settings.get("setup_complete"):
        return

    actor = await get_audit_log_actor(guild, discord.AuditLogAction.webhook_create)
    if actor is None or await is_whitelisted(guild, actor.id):
        return

    if record_action(guild.id, actor.id, "webhook_create", MAX_WEBHOOK_CREATES):
        await punish_actor(guild, actor, f"Zu viele Webhook-Erstellungen ({MAX_WEBHOOK_CREATES}+ in {NUKE_ACTION_WINDOW}s, Webhook-Spam)")
        try:
            webhooks = await channel.webhooks()
            for wh in webhooks:
                if wh.user and wh.user.id == actor.id:
                    await wh.delete(reason="Anti-Nuke: Webhook-Spam gestoppt")
        except discord.Forbidden:
            pass


@bot.command()
@commands.has_permissions(administrator=True)
async def setup_ticket(ctx):
    """Sendet die Ticket-Nachricht mit dem Button (Nur für Admins)"""
    embed = discord.Embed(
        title="Support Tickets", 
        description="Klicke auf den Button unten, um ein privates Ticket mit dem Team zu öffnen.", 
        color=discord.Color.blue()
    )
    await ctx.send(embed=embed, view=TicketButton())

@setup_ticket.error
async def setup_ticket_error(ctx, error):
    if isinstance(error, commands.MissingPermissions):
        await ctx.send("you need admin to use that")
    else:
        raise error


if __name__ == "__main__":
    if TOKEN is None:
        print("error: no token found in .env")
    else:
        bot.run(TOKEN)
