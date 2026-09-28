#!/usr/bin/env python3
"""
Zee5 Downloader GUI - with L3 Widevine CDM
Made by Rvind  |  DRM layer by Nono

pip install requests pywidevine
python zee5_downloader.py
"""

import sys, os, re, json, time, subprocess, threading, uuid, base64, struct
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

try:
    import requests
except ImportError:
    subprocess.run([sys.executable, "-m", "pip", "install", "requests", "-q"])
    import requests


#  CONSTANTS / HELPERS


APP_DIR  = os.path.dirname(os.path.abspath(__file__))
CFG_FILE = os.path.join(APP_DIR, "zee5_cfg.json")
DID_FILE = os.path.join(APP_DIR, ".zee5_did")

# app constants
ZEE5_APP_VERSION = "7.1.1"
ZEE5_PLATFORM    = "web_app"
ZEE5_COUNTRY     = "IN"
ZEE5_APP_ID      = "tvr-web"
ZEE5_UA          = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
ZEE5_SECRET_KEY  = "gBQaZLiNdGN9UsCKZaloghz9t9StWLSD"  # public, baked into zee5's JS bundle

def get_device_id():
    if os.path.exists(DID_FILE):
        return open(DID_FILE).read().strip()
    did = str(uuid.uuid4())
    open(DID_FILE, 'w').write(did)
    return did

DEVICE_ID = get_device_id()

# Module-level device code obtained during OTP flow (for getdeviceuser exchange)
_DEVICE_CODE: str = ""

LANG_NAMES = {
    # 3-letter ISO 639-2
    "hin":"Hindi","tam":"Tamil","tel":"Telugu","eng":"English","kan":"Kannada",
    "mal":"Malayalam","ben":"Bengali","mar":"Marathi","pun":"Punjabi","guj":"Gujarati",
    "urd":"Urdu","arb":"Arabic","fre":"French","spa":"Spanish","ger":"German",
    "jpn":"Japanese","kor":"Korean","chi":"Chinese","zho":"Chinese","por":"Portuguese",
    "mul":"Multi",
    # 2-letter ISO 639-1 (Zee5 MPD uses these)
    "hi":"Hindi","ta":"Tamil","te":"Telugu","en":"English","kn":"Kannada",
    "ml":"Malayalam","bn":"Bengali","mr":"Marathi","pa":"Punjabi","gu":"Gujarati",
    "ur":"Urdu","ar":"Arabic","fr":"French","es":"Spanish","de":"German",
    "ja":"Japanese","ko":"Korean","zh":"Chinese","pt":"Portuguese",
}

def lang_label(code):
    return LANG_NAMES.get((code or "").lower(), (code or "").upper())

def fmt_size(b):
    if b is None: return "?"
    if b < 1024**2: return f"{b/1024:.0f} KB"
    if b < 1024**3: return f"{b/1024**2:.0f} MB"
    return f"{b/1024**3:.2f} GB"


#  CONFIG


DEFAULT_CFG = {
    "token_file":      os.path.join(APP_DIR, "zee5_token.json"),
    "output_dir":      os.path.expanduser("~/Downloads"),
    "n_m3u8dl_path":   "",
    "ytdlp_path":      "yt-dlp",
    "ffmpeg_path":     "ffmpeg",
    "threads":         16,
    "grab_subs":       False,
    "engine":          "n_m3u8dl",
    "cdm_path":        "",
    "mp4decrypt_path": "mp4decrypt",
    "mkvmerge_path":   "mkvmerge",     # mkvtoolnix - fastest lossless muxer
    "decrypt_tool":    "auto",
    "audio_lang":      "best",
    "sub_lang":        "NONE",
    "country":         "IN",
    "app_version":     "7.1.1",
    "user_agent":      (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
}

def load_cfg():
    c = dict(DEFAULT_CFG)
    if os.path.exists(CFG_FILE):
        try: c.update(json.load(open(CFG_FILE)))
        except: pass
    _sync_constants(c)
    return c

def _sync_constants(c):
    global ZEE5_COUNTRY, ZEE5_APP_VERSION, ZEE5_UA
    ZEE5_COUNTRY     = c.get("country",     ZEE5_COUNTRY)
    ZEE5_APP_VERSION = c.get("app_version", ZEE5_APP_VERSION)
    ZEE5_UA          = c.get("user_agent",  ZEE5_UA)

def save_cfg(c): json.dump(c, open(CFG_FILE,'w'), indent=2)


def load_token(cfg):
    path = cfg.get("token_file","")
    candidates = [path, os.path.join(APP_DIR,"zee5_token.json")]
    for p in candidates:
        if p and os.path.exists(p):
            try:
                d = json.load(open(p))
                t = d.get("access_token","")
                exp = d.get("expires_at", 0)
                if t and (exp == 0 or exp > time.time() + 60):
                    return t, p
            except: pass
    return None, None

def save_token(token_data, cfg):
    path = cfg.get("token_file", os.path.join(APP_DIR,"zee5_token.json"))
    token_data["saved_at"] = int(time.time())
    json.dump(token_data, open(path,'w'), indent=2)
    return path


#  ZEE5 AUTH


# x-dd-token: exact schema decoded from HAR sendotp request.
# Structure confirmed from second HAR (maxxx.har) x-dd-token header.
# Keys: schema_version, os_name, os_version, platform_name, platform_version,
#       device_name, app_name, app_version, player_capabilities, security_capabilities
_DD_TOKEN_PAYLOAD = {
    "schema_version": "1",
    "os_name":        "Windows",
    "os_version":     "10",
    "platform_name":  "Chrome",
    "platform_version": "124",
    "device_name":    "",
    "app_name":       "web_app",
    "app_version":    "2.52.31",
    "player_capabilities": {
        "audio_channel": ["STEREO"],
        "video_codec":   ["H264"],
        "container":     ["MP4", "TS"],
        "package":       ["DASH", "HLS"],
        "resolution":    ["240p", "SD", "HD", "FHD"],
        "dynamic_range": ["SDR"],
    },
    "security_capabilities": {
        "encryption":              ["WIDEVINE_AES_CTR"],
        "widevine_security_level": ["L3"],
        "hdcp_version":            ["HDCP_V1", "HDCP_V2", "HDCP_V2_1", "HDCP_V2_2"],
    },
}

def make_dd_token():
    """Build x-dd-token header (base64 JSON)."""
    return base64.b64encode(
        json.dumps(_DD_TOKEN_PAYLOAD, separators=(',', ':')).encode()
    ).decode()

def make_esk():
    """
    Build ESK header.
    ESK header: base64(device_id + __ + SECRET_KEY + __ + timestamp_ms)
    """
    ts = int(time.time() * 1000)
    raw_esk = f"{DEVICE_ID}__{ZEE5_SECRET_KEY}__{ts}"
    return base64.b64encode(raw_esk.encode()).decode()

def _base_headers(token=None, platform_token=None, esk=None, dd_token=None, extra=None):
    h = {
        "User-Agent":      ZEE5_UA,
        "Accept":          "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Origin":          "https://www.zee5.com",
        "Referer":         "https://www.zee5.com/",
        "Cache-Control":   "no-cache",
    }
    if token:         h["x-access-token"]  = token
    if platform_token:h["platform_token"]  = platform_token
    if esk:           h["esk"]             = esk
    if dd_token:      h["x-dd-token"]      = dd_token
    if extra:         h.update(extra)
    return h

def _auth_headers(esk=None, dd_token=None, guest_token_hdr=None):
    """
    Headers used on auth.zee5.com calls.
    device_id always present. esk + x-dd-token on sendotp. x-z5-guest-token on verifyotp.
    """
    h = {
        "User-Agent":      ZEE5_UA,
        "Accept":          "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Origin":          "https://www.zee5.com",
        "Referer":         "https://www.zee5.com/",
        "Content-Type":    "application/json",
        "device_id":       DEVICE_ID,
    }
    if esk:              h["esk"]               = esk
    if dd_token:         h["x-dd-token"]        = dd_token
    if guest_token_hdr:  h["x-z5-guest-token"]  = guest_token_hdr
    return h

def get_platform_token():
    """
    Fetch Zee5's anonymous platform token from launchapi.
    This token is needed for ALL subsequent API calls (like hotstarauth in Hotstar).
    """
    url = "https://launchapi.zee5.com/token/platform_tokens"
    params = {
        "platform_name": ZEE5_PLATFORM,
        "country":       ZEE5_COUNTRY,
    }
    try:
        r = requests.get(url, params=params, headers=_base_headers(), timeout=15)
        d = r.json()
        tok = d.get("platform_token") or d.get("token") or ""
        if tok:
            return tok
    except: pass
    return ""

def zee5_get_user_token(mobile):
    """
    Step 1 of Zee5 OTP auth flow.
    POST urlencoded `mobile=91{mobile}` to getusertoken.
    ESK is client-generated (SESSION_KEY), this call is still required
    as part of the flow (server expects it before sendotp).
    """
    url = "https://auth.zee5.com/v1/user/getusertoken"
    body = f"mobile=91{mobile}"
    # getusertoken ALSO requires device_id + esk headers (from HAR)
    h = {
        "User-Agent":    ZEE5_UA,
        "Accept":        "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Origin":        "https://www.zee5.com",
        "Referer":       "https://www.zee5.com/",
        "Content-Type":  "application/x-www-form-urlencoded",
        "Cache-Control": "no-cache",
        "device_id":     DEVICE_ID,
        "esk":           make_esk(),
    }
    try:
        r = requests.post(url, data=body, headers=h, timeout=15)
        if r.status_code == 200:
            d = r.json()
            # Response carries session token used in ESK
            sess = (d.get("token") or d.get("session_token") or
                    d.get("user_token") or d.get("access_token") or "")
            return sess
    except:
        pass
    return ""

# Full consents object exactly as captured in HAR
_CONSENTS = {
    "IsThirdPartyDataSharing":              True,
    "IsThirdPartyWatchHistoryDataSharing":  True,
    "IsTargetedAds":                        True,
    "IsPrivacyPolicy":                      True,
    "IsEmailNotificationEnabled":           False,
    "IsSMSNotificationEnabled":             True,
    "IsWhatsappNotificationEnabled":        True,
    "IsPushNotificationEnabled":            True,
    "PolicyVersion":                        "1.0",
    "PlatformName":                         "Web",
}

def zee5_get_device_code():
    """
    Obtain a one-time device_code from Zee5 that pairs with the OTP session.
    The browser calls this before sendotp; we then use it in getdeviceuser
    after verifyotp to swap for the proper RS256 user JWT.
    """
    global _DEVICE_CODE
    url = "https://auth.zee5.com/useraction/device/getcode"
    params = {
        "platform_name": ZEE5_PLATFORM,
        "country":       ZEE5_COUNTRY,
    }
    h = {
        "User-Agent":    ZEE5_UA,
        "Accept":        "application/json, text/plain, */*",
        "Origin":        "https://www.zee5.com",
        "Referer":       "https://www.zee5.com/",
        "Cache-Control": "no-cache",
    }
    try:
        r = requests.get(url, params=params, headers=h, timeout=15)
        if r.status_code == 200:
            d = r.json()
            code = (d.get("device_code") or d.get("code") or
                    d.get("deviceCode")   or d.get("session_code") or "")
            if code:
                _DEVICE_CODE = code
                return code
    except:
        pass
    return ""


def zee5_get_device_user(device_code):
    """
    Exchange the device_code (obtained pre-OTP) for the RS256 user JWT.
    Called after verifyotp succeeds.
    Zee5 browser calls: POST auth.zee5.com/useraction/device/getdeviceuser
    Body (urlencoded): device_name=web_app&device_code={code}
    Returns the RS256 JWT string, or "" on failure.
    """
    if not device_code:
        return ""
    url = "https://auth.zee5.com/useraction/device/getdeviceuser"
    payload = f"device_name=web_app&device_code={device_code}"
    h = {
        "User-Agent":    ZEE5_UA,
        "Accept":        "application/json, text/plain, */*",
        "Content-Type":  "application/x-www-form-urlencoded",
        "Origin":        "https://www.zee5.com",
        "Referer":       "https://www.zee5.com/",
        "Cache-Control": "no-cache",
    }
    try:
        r = requests.post(url, data=payload, headers=h, timeout=15)
        if r.status_code == 200:
            d = r.json()
            # RS256 JWT typically comes back as access_token, token, or user_token
            tok = (d.get("access_token") or d.get("token") or
                   d.get("user_token")   or d.get("jwt")   or "")
            # Validate it's a proper JWT (3 dot-separated parts) and reasonably long
            if tok and tok.count('.') == 2 and len(tok) > 100:
                return tok
    except:
        pass
    return ""


def zee5_send_otp(mobile, platform_token):
    """
    Step 2: Send OTP to mobile number via Zee5 auth API.
    Also kicks off getdeviceuser device_code pairing flow.
    """
    # get device code first
    zee5_get_device_code()

    # getusertoken (step 1 of OTP flow)
    zee5_get_user_token(mobile)
    esk = make_esk()
    dd  = make_dd_token()

    url = "https://auth.zee5.com/v1/user/sendotp"
    # phoneno with 91 country code prefix inline, NO separate country_code field
    payload = {
        "phoneno":  f"91{mobile}",
        "consents": _CONSENTS,
    }
    h = _auth_headers(esk=esk, dd_token=dd)

    try:
        r = requests.post(url, json=payload, headers=h, timeout=15)
        d = r.json()
        if r.status_code in (200, 201):
            # Any truthy status or empty error means OTP was dispatched
            status = str(d.get("status", "")).upper()
            if status in ("SUCCESS", "OTP_SENT", "OK", "TRUE", "") or d.get("code") == 200:
                return True, "web"
            # Some endpoints return a message-only success
            if "otp" in str(d).lower() or "sent" in str(d).lower():
                return True, "web"
            err = d.get("message") or d.get("error") or d.get("status") or str(d)
            return False, str(err)
        return False, f"HTTP {r.status_code}: {r.text[:200]}"
    except Exception as e:
        return False, str(e)

def zee5_verify_otp(mobile, otp, platform_token):
    """
    Step 3: Verify OTP and return user access token dict.
    guest_token = DEVICE_ID (per HAR capture).

    After verifying OTP, we also call getdeviceuser with the device_code
    obtained in zee5_send_otp to get the RS256 JWT required by spapi.
    """
    esk = make_esk()
    dd  = make_dd_token()

    url = "https://auth.zee5.com/v1/user/verifyotp"
    # Exact payload from HAR capture
    payload = {
        "otp":          otp,
        "guest_token":  DEVICE_ID,        # device_id used as guest_token
        "platform":     "PWA",
        "device":       "Desktop",
        "version":      "0.1.4",
        "phoneno":      f"91{mobile}",
    }
    # x-z5-guest-token header = device_id
    h = _auth_headers(esk=esk, dd_token=dd, guest_token_hdr=DEVICE_ID)

    try:
        r = requests.post(url, json=payload, headers=h, timeout=15)
        d = r.json()

        # Debug: log all keys in response (print to stderr so GUI doesn't see it)
        import sys as _sys
        print(f"[DEBUG verifyotp] HTTP {r.status_code}", file=_sys.stderr)
        print(f"[DEBUG verifyotp] response keys: {list(d.keys())}", file=_sys.stderr)
        # Log token lengths for each candidate key
        for k in ("access_token","token","user_token","usertoken","jwt_token","refresh_token","id_token"):
            v = d.get(k, "")
            if v: print(f"[DEBUG verifyotp] {k}: len={len(str(v))} first60={str(v)[:60]}", file=_sys.stderr)

        # Walk common token field names
        tok = (d.get("access_token") or d.get("token") or
               d.get("user_token")   or d.get("usertoken") or
               d.get("jwt_token")    or d.get("id_token")  or "")

        if tok and len(tok) > 20:
            # try device user token exchange for RS256 JWT
            # The browser's parallel device flow gives a proper RS256 JWT
            # (alg: RS256, iss: userapi.zee5.com) needed by spapi.
            rs256_tok = zee5_get_device_user(_DEVICE_CODE) if _DEVICE_CODE else ""
            print(f"[DEBUG verifyotp] getdeviceuser result: len={len(rs256_tok)} first60={rs256_tok[:60]}", file=_sys.stderr)

            # Use RS256 JWT if obtained, otherwise fall back to verifyotp token
            final_tok = rs256_tok if rs256_tok else tok
            print(f"[DEBUG verifyotp] final token choice: {'rs256' if rs256_tok else 'verifyotp'} len={len(final_tok)}", file=_sys.stderr)

            return {
                "access_token":         final_tok,
                "verifyotp_token":      tok,         # keep original for reference
                "mobile":               mobile,
                "expires_at":           d.get("expires_at", 0),
                "user_id":              d.get("user_id", ""),
                "subscription_status":  d.get("subscription_status", ""),
            }
        # surface raw error for debug
        err = d.get("message") or d.get("error") or str(d)
        return {"_error": str(err), "_raw": d}
    except Exception as e:
        return {"_error": str(e)}

def zee5_guest_token(platform_token):
    """Get a guest user token for browsing (unauthenticated)."""
    url = "https://auth.zee5.com/v1/user/guestUserRegistration"
    payload = {
        "device_id":     DEVICE_ID,
        "platform_name": ZEE5_PLATFORM,
        "country":       ZEE5_COUNTRY,
    }
    h = _base_headers(platform_token=platform_token)
    h["Content-Type"] = "application/json"
    try:
        r = requests.post(url, json=payload, headers=h, timeout=15)
        d = r.json()
        tok = d.get("access_token") or d.get("token") or ""
        return tok
    except:
        return ""


#  ZEE5 CONTENT / STREAM API


WIDEVINE_SYSTEM_ID = "edef8ba979d64acea3c827dcd51d21ed"

def extract_content_id(url_or_id):
    """
    Extract Zee5 content ID from URL.
    Zee5 URL patterns:
      https://www.zee5.com/movies/details/movie-name/0-0-XXXXXXXXXX
      https://www.zee5.com/tvshows/details/show-name/0-6-XXXXXXXXXX/episode-name/0-1-XXXXXXXXXX
    Content IDs look like: 0-0-1z53022040  or  0-1-1z53022040
    """
    s = url_or_id.strip()
    # direct content id (e.g. 0-0-1z53022040)
    if re.match(r'^\d+-\d+-[a-zA-Z0-9]+$', s):
        return s
    # strip query params
    s = s.split('?')[0].rstrip('/')
    # grab last segment that matches content id pattern
    parts = s.split('/')
    for part in reversed(parts):
        if re.match(r'^\d+-\d+-[a-zA-Z0-9]+$', part):
            return part
    return None

def extract_show_info_zee5(url):
    """Extract show/episode name from Zee5 URL."""
    # junk segments we never want as show titles
    _SKIP = {"embed", "details", "watch", "player",
             "tvshows", "shows", "movies", "episodes", "clips", "trailers", "web"}
    try:
        # strip scheme, host, query — work only on path segments
        clean = url.strip().split('?')[0].rstrip('/')
        # remove scheme (https://, http://)
        clean = re.sub(r'^https?://', '', clean)
        # remove host (first segment like www.zee5.com)
        path_parts = clean.split('/')
        if path_parts and ('.' in path_parts[0] or not path_parts[0]):
            path_parts = path_parts[1:]
        # filter out content-id patterns (e.g. 0-6-xyz123)
        parts = [p for p in path_parts if p and not re.match(r'^\d+-\d+-[a-zA-Z0-9]+$', p)]
        show, ep = "", ""
        for kw in ('tvshows', 'shows', 'movies'):
            if kw in parts:
                idx = parts.index(kw)
                # skip noise segments
                remaining = [p for p in parts[idx+1:] if p.lower() not in _SKIP]
                if remaining: show = remaining[0].replace('-',' ').title()
                if len(remaining) > 1:
                    ep = remaining[-1].replace('-',' ').title()
                break
        if not show:
            # fallback: last meaningful path segment
            candidates = [p for p in parts if p.lower() not in _SKIP]
            if candidates:
                show = candidates[-1].replace('-', ' ').title()
        return show, ep
    except:
        return "", ""

def fetch_content_details(content_id, access_token, platform_token):
    """
    Fetch content metadata from Zee5 content API.
    Returns the first content item dict (title, content_type, etc.).
    Zee5 API wraps results in {"response":[...]} or {"items":[...]} etc.
    """
    url = "https://contentapi.zee5.com/content/query"
    params = {
        "content_id":  content_id,
        "translation": "en",
        "country":     ZEE5_COUNTRY,
    }
    h = _base_headers(access_token, platform_token)
    try:
        r = requests.get(url, params=params, headers=h, timeout=15)
        if r.status_code == 200:
            d = r.json()
            # unwrap nested structures Zee5 uses
            for key in ("response", "items", "contents", "data", "result"):
                if key in d and isinstance(d[key], list) and d[key]:
                    d = d[key][0]
                    break
            return d
    except:
        pass
    return {}

def _parse_jwt_sub(token):
    """
    Extract 'sub' (user/profile UUID) from a JWT access token.
    JWT is base64url(header).base64url(payload).signature
    """
    try:
        parts = token.split('.')
        if len(parts) >= 2:
            # Add padding
            payload_b64 = parts[1] + '=='
            payload = json.loads(base64.b64decode(payload_b64).decode('utf-8', errors='replace'))
            return payload.get('sub', '').lower()
    except:
        pass
    return ''


def fetch_stream(content_id, access_token, platform_token, _log_fn=None):
    """
    Fetch Zee5 playback URL (MPD / M3U8) from the confirmed real endpoint:
      POST spapi.zee5.com/singlePlayback/v2/getDetails/secure

    Request body (JSON): x-access-token (platform), Authorization bearer (user), x-dd-token
    Response: assetDetails.video_url.mpd / .hls

    Returns (mpd_url, m3u8_url, licence_url, status_code)
    """
    def dbg(msg):
        if _log_fn: _log_fn(msg)

    # token info
    if access_token:
        tok_parts = access_token.split('.')
        tok_type = "JWT" if len(tok_parts) == 3 else "plain"
        dbg(f"[TOKEN] type={tok_type} len={len(access_token)} first80={access_token[:80]}\n")
        if len(tok_parts) == 3:
            try:
                import base64 as _b64, json as _json
                hdr = _json.loads(_b64.b64decode(tok_parts[0] + '==').decode('utf-8','replace'))
                dbg(f"[TOKEN] JWT header: alg={hdr.get('alg')} kid={hdr.get('kid','?')[:20]}\n")
            except: pass
    else:
        dbg(f"[TOKEN] WARNING - no access_token!\n")

    # Extract profile UUID from user JWT
    profile_uid = _parse_jwt_sub(access_token) if access_token else ''
    if profile_uid:
        dbg(f"[TOKEN] profile_uid={profile_uid}\n")

    # request body
    body = {
        "x-access-token": platform_token or "",
        "Authorization":  f"bearer {access_token}" if access_token else "",
        "x-dd-token":     make_dd_token(),
    }

    # headers
    h = {
        "User-Agent":      ZEE5_UA,
        "Accept":          "application/json",
        "Accept-Language": "en-US,en;q=0.9",
        "Origin":          "https://www.zee5.com",
        "Referer":         "https://www.zee5.com/",
        "Content-Type":    "application/json",
        "Cache-Control":   "no-cache",
    }
    if profile_uid:
        h["profile-id"]      = profile_uid
        h["x-z5-profile-id"] = profile_uid

    # query params
    user_type = "premium"  # try premium first; 401 means fall back to registered

    # Detect content type from content_id prefix
    # 0-1- = episode, 0-6- = show/season, 0-0- = movie, 0-2- = clip
    cid_type = content_id.split('-')[1] if '-' in content_id else ''
    is_show  = cid_type in ('6', '7')   # show or season ID

    def _make_params(cid, utype):
        p = {
            "content_id":             cid,
            "device_id":              DEVICE_ID,
            "platform_name":          "desktop_web",
            "translation":            "en",
            "user_language":          "hi,en,te",
            "country":                ZEE5_COUNTRY,
            "state":                  "TS",
            "app_version":            ZEE5_APP_VERSION,
            "user_type":              utype,
            "is_kids_profile":        "false",
            "check_parental_control": "false",
            "ppid":                   DEVICE_ID,
            "version":                "15",
        }
        if is_show:
            # Show/season IDs need latest=true to resolve to the latest episode
            p["latest"]    = "true"
            p["marketing"] = "true"
        if profile_uid:
            p["uid"] = profile_uid
        return p

    mpd = m3u8 = licence_url = None

    # Try v2 endpoint first (confirmed working), then v1 fallback
    endpoints = [
        f"https://spapi.zee5.com/singlePlayback/v2/getDetails/secure",
        f"https://spapi.zee5.com/singlePlayback/getDetails/secure",
    ]
    user_types = ["premium", "registered", "guest"]

    for ep_url in endpoints:
        for utype in user_types:
            params = _make_params(content_id, utype)
            short = ep_url.replace('https://spapi.zee5.com','')
            dbg(f"[STREAM] POST {short} (user_type={utype})\n")
            try:
                r = requests.post(ep_url, params=params, json=body, headers=h, timeout=20)
                dbg(f"[STREAM] → HTTP {r.status_code}\n")

                if r.status_code == 401:
                    try:
                        err_body = r.json()
                        dbg(f"[STREAM] 401 body: {json.dumps(err_body)[:200]}\n")
                    except:
                        dbg(f"[STREAM] 401 body: {r.text[:200]}\n")
                    continue
                if r.status_code not in (200, 206):
                    dbg(f"[STREAM] Response: {r.text[:200]}\n")
                    continue  # try next user_type / endpoint

                try:
                    d = r.json()
                except Exception:
                    dbg(f"[STREAM] Non-JSON response: {r.text[:200]}\n")
                    continue

                # parse response
                asset = d.get('assetDetails', {})

                # prefer mpd stream
                video_url_obj = asset.get('video_url', {})
                if isinstance(video_url_obj, dict):
                    mpd   = video_url_obj.get('mpd') or video_url_obj.get('dash') or ''
                    m3u8  = video_url_obj.get('hls') or video_url_obj.get('m3u8') or ''
                elif isinstance(video_url_obj, str) and video_url_obj.startswith('http'):
                    if '.mpd' in video_url_obj: mpd = video_url_obj
                    elif '.m3u8' in video_url_obj: m3u8 = video_url_obj

                # Subtitles / license info
                subs = asset.get('subtitle_url', [])
                # Nagra/KeyOS license endpoint
                key_os     = d.get('keyOsDetails', {})
                nl_token   = key_os.get('nl', '')          # Nagra license token
                # license server - same domain as stream API,
                # always reachable (no ISP DNS blocking). nl goes in headers, not URL.
                licence_url = "https://spapi.zee5.com/widevine/getLicense"

                # Regex sweep on raw text as final fallback
                raw = r.text
                if not mpd:
                    for u in re.findall(r'https://[^\s"\'<>]+\.mpd[^\s"\'<>]*', raw):
                        mpd = u; break
                if not m3u8:
                    for u in re.findall(r'https://[^\s"\'<>]+\.m3u8[^\s"\'<>]*', raw):
                        m3u8 = u; break

                if mpd or m3u8:
                    dbg(f"[STREAM] ✓ Got stream! MPD={bool(mpd)} HLS={bool(m3u8)}\n")
                    if mpd: dbg(f"[STREAM] MPD: {mpd[:100]}\n")
                    if nl_token: dbg(f"[STREAM] nl token: {nl_token[:16]}...\n")
                    return mpd or None, m3u8 or None, licence_url, nl_token, 200

                # Got 200 but no stream URL — dump response for debug
                dbg(f"[STREAM] 200 but no stream URL. Keys: {list(asset.keys())[:15]}\n")
                dbg(f"[STREAM] video_url field: {asset.get('video_url','(missing)')}\n")
                break

            except Exception as exc:
                dbg(f"[STREAM] Error: {exc}\n")
                break

    dbg(f"[STREAM] All attempts failed\n")
    return None, None, None, "", 0


#  DRM — PSSH EXTRACTION + WIDEVINE KEY FETCHING


def extract_pssh(mpd_text):
    """Extract Widevine PSSH box (base64) from MPD."""
    # Form 1: cenc:pssh inside Widevine ContentProtection block
    cp_blocks = re.findall(
        r'<ContentProtection\b[^>]*schemeIdUri="[^"]*edef8ba9[^"]*"[^>]*>(.*?)</ContentProtection>',
        mpd_text, re.DOTALL | re.IGNORECASE
    )
    for block in cp_blocks:
        m = re.search(r'<(?:[^:]+:)?pssh\b[^>]*>(.*?)</(?:[^:]+:)?pssh>', block, re.DOTALL | re.IGNORECASE)
        if m:
            data = m.group(1).strip()
            if data: return data

    # Form 2: any cenc:pssh anywhere
    m = re.search(r'<(?:[^:]+:)?pssh\b[^>]*>(.*?)</(?:[^:]+:)?pssh>', mpd_text, re.DOTALL | re.IGNORECASE)
    if m:
        data = m.group(1).strip()
        if data: return data

    # Form 3: build minimal PSSH from KIDs
    kids_hex = re.findall(r'default_KID="([0-9a-fA-F\-]{32,36})"', mpd_text)
    kids_hex += re.findall(r'cenc:default_KID="([0-9a-fA-F\-]{32,36})"', mpd_text, re.IGNORECASE)
    kids_raw = []
    seen = set()
    for k in kids_hex:
        k_clean = k.replace("-","").lower()
        if k_clean not in seen and len(k_clean) == 32:
            seen.add(k_clean)
            kids_raw.append(bytes.fromhex(k_clean))
    if not kids_raw: return None

    proto_data = b""
    for kid in kids_raw:
        proto_data += b"\x12" + bytes([len(kid)]) + kid

    system_id = bytes.fromhex(WIDEVINE_SYSTEM_ID)
    data_size  = struct.pack(">I", len(proto_data))
    box_body   = b"pssh" + b"\x00\x00\x00\x00" + system_id + data_size + proto_data
    box_size   = struct.pack(">I", len(box_body) + 4)
    return base64.b64encode(box_size + box_body).decode()

def extract_license_url_from_mpd(mpd_text):
    """Pull Widevine license URL from MPD ContentProtection."""
    patterns = [
        r'<(?:[^:]+:)?[Ll]a[Uu][Rr][Ll][^>]*>(https?://[^<]+)</(?:[^:]+:)?[Ll]a[Uu][Rr][Ll]>',
        r'laURL="(https?://[^"]+)"',
        r'Laurl="(https?://[^"]+)"',
        r'licenseUrl["\s:=]+(https?://[^\s"&,]+)',
    ]
    for pat in patterns:
        m = re.search(pat, mpd_text, re.IGNORECASE)
        if m: return m.group(1).strip()
    return None

def get_widevine_keys(pssh_b64, access_token, platform_token, mpd_url,
                      cdm_path="", log_cb=None, license_url=None, nl_token=""):
    """
    Fetch Widevine content keys using L3 software CDM (pywidevine).
    Zee5 license server is different from Hotstar - uses different auth headers.
    """
    def _log(msg):
        if log_cb: log_cb(msg)

    # import pywidevine
    try:
        from pywidevine.cdm import Cdm
        from pywidevine.device import Device
        from pywidevine.pssh import PSSH
    except ImportError:
        _log("[DRM] pywidevine not found - installing...\n")
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "pywidevine", "-q",
                            "--break-system-packages"], timeout=90, check=False)
            subprocess.run([sys.executable, "-m", "pip", "install", "pywidevine", "-q"], timeout=90, check=False)
            from pywidevine.cdm import Cdm
            from pywidevine.device import Device
            from pywidevine.pssh import PSSH
            _log("[DRM] pywidevine installed ✓\n")
        except Exception as e:
            _log(f"[DRM] ✗ Can't install pywidevine: {e}\n")
            return []

    # load wvd device file
    wvd_candidates = []
    if cdm_path and os.path.exists(cdm_path):
        wvd_candidates.append(cdm_path)
    for name in ["device.wvd", "l3.wvd", "cdm.wvd", "widevine.wvd"]:
        p = os.path.join(APP_DIR, name)
        if os.path.exists(p): wvd_candidates.append(p)
    for p in [os.path.expanduser("~/.wvd/device.wvd"), os.path.expanduser("~/device.wvd")]:
        if os.path.exists(p): wvd_candidates.append(p)

    device = None
    for wvd in wvd_candidates:
        try:
            device = Device.load(wvd)
            _log(f"[DRM] Loaded CDM: {wvd}\n")
            break
        except Exception as e:
            _log(f"[DRM] Failed to load {wvd}: {e}\n")

    if device is None:
        _log("[DRM] ✗ No valid .wvd file found. Drop device.wvd next to script.\n")
        return []

    # cdm session + challenge
    try:
        cdm   = Cdm.from_device(device)
        sess  = cdm.open()
        pssh  = PSSH(pssh_b64)
        challenge = cdm.get_license_challenge(sess, pssh)
    except Exception as e:
        _log(f"[DRM] ✗ CDM challenge failed: {e}\n")
        return []

    # license server POST
    # Extract content ID from MPD URL for license request
    cid_matches = re.findall(r'([0-9]+-[0-9]+-[a-zA-Z0-9]+)', mpd_url or "")
    content_id = cid_matches[0] if cid_matches else ""
    _log(f"[DRM] Content ID: {content_id or '(none)'}\n")
    _log(f"[DRM] License URL: {license_url or '(none)'}\n")

    # widevine license endpoint
    # HAR shows: POST https://spapi.zee5.com/widevine/getLicense
    #   Headers: customdata: Nagra_<nl>  |  nl: <nl>  |  content-type: application/octet-stream
    #   Body:    raw binary Widevine challenge (NOT JSON-wrapped)
    #   Response: 200 OK with raw binary license
    # All zkl.zee5.com / wv-keyos.zee5.com / drm.zee5.com are blocked by ISP DNS.
    # spapi.zee5.com is the same domain as the stream API — always reachable.

    _NAGRA_LIC_URL = "https://spapi.zee5.com/widevine/getLicense"

    # Build Nagra license headers using nl_token
    _nl = nl_token or ""
    _nagra_hdrs = {
        "User-Agent":    ZEE5_UA,
        "Origin":        "https://www.zee5.com",
        "Referer":       "https://www.zee5.com/",
        "Accept":        "*/*",
        "Content-Type":  "application/octet-stream",
        "customdata":    f"Nagra_{_nl}" if _nl else "Nagra_",
        "nl":            _nl,
    }

    # license_entries: (url, headers_dict)
    license_entries = [(
        license_url or _NAGRA_LIC_URL,
        _nagra_hdrs
    )]
    # If caller passed a different URL, also try spapi as fallback
    if license_url and license_url != _NAGRA_LIC_URL:
        license_entries.append((_NAGRA_LIC_URL, _nagra_hdrs))

    # Minimal headers dict kept for DNS-bypass retry branch
    _MINIMAL_HDRS = dict(_nagra_hdrs)

    def _unwrap(raw):
        if not raw: return None, "empty"
        if raw[:1] in (b'{', b'['):
            try:
                j = json.loads(raw)
                for k in ("license","licenseData","widevine_license","data","keyResponse","licenseToken"):
                    if isinstance(j, dict) and k in j:
                        decoded = base64.b64decode(j[k])
                        return decoded, f"JSON[{k}] {len(decoded)} bytes"
                return None, f"JSON no key - {list(j.keys()) if isinstance(j,dict) else 'list'}"
            except: pass
        return raw, f"raw {len(raw)} bytes"

    raw_challenge = bytes(challenge)
    lic_resp = None

    import urllib.parse as _up
    import socket as _socket

    # dns bypass via raw UDP
    # ISP may block zee5 DRM domains at DNS level. We bypass their resolver by
    # querying public DNS servers directly over UDP (port 53) — bypasses ISP DNS.
    def _udp_dns_resolve(hostname):
        """Resolve hostname by sending raw DNS query UDP to 8.8.8.8 / 1.1.1.1."""
        # Try dnspython first (most reliable)
        try:
            import importlib
            dns_mod = importlib.import_module("dns.resolver")
            for ns in ("8.8.8.8", "1.1.1.1", "9.9.9.9"):
                try:
                    resolver = dns_mod.Resolver(configure=False)
                    resolver.nameservers = [ns]
                    resolver.timeout = 4
                    resolver.lifetime = 6
                    answers = resolver.resolve(hostname, "A")
                    ip = str(answers[0])
                    return ip
                except Exception:
                    continue
        except ImportError:
            pass

        # Fallback: raw UDP DNS query (no library needed)
        def _raw_udp_dns(hostname, nameserver):
            import struct, random
            txid  = random.randint(0, 65535)
            flags = 0x0100  # standard query, recursion desired
            qdcount = 1
            header = struct.pack(">HHHHHH", txid, flags, qdcount, 0, 0, 0)
            labels = b"".join(
                bytes([len(p)]) + p.encode() for p in hostname.split(".")
            ) + b"\x00"
            question = labels + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
            packet = header + question
            sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
            sock.settimeout(4)
            try:
                sock.sendto(packet, (nameserver, 53))
                data, _ = sock.recvfrom(512)
            finally:
                sock.close()
            # Parse answer section: skip header(12) + question, find first A record
            offset = 12
            # Skip question section
            while offset < len(data) and data[offset] != 0:
                if data[offset] & 0xC0 == 0xC0:  # pointer
                    offset += 2; break
                offset += data[offset] + 1
            else:
                offset += 1  # null terminator
            offset += 4  # QTYPE + QCLASS
            ancount = struct.unpack(">H", data[6:8])[0]
            for _ in range(ancount):
                if offset >= len(data): break
                # Skip name (may be pointer or label)
                if data[offset] & 0xC0 == 0xC0:
                    offset += 2
                else:
                    while offset < len(data) and data[offset] != 0:
                        offset += data[offset] + 1
                    offset += 1
                if offset + 10 > len(data): break
                rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[offset:offset+10])
                offset += 10
                if rtype == 1 and rdlen == 4:  # A record
                    return ".".join(str(b) for b in data[offset:offset+4])
                offset += rdlen
            return None

        for ns in ("8.8.8.8", "1.1.1.1", "9.9.9.9"):
            try:
                ip = _raw_udp_dns(hostname, ns)
                if ip: return ip
            except Exception:
                continue
        return None

    # Monkey-patch socket.getaddrinfo for DRM hostnames only
    _drm_hosts = {}  # hostname → IP cache
    _orig_getaddrinfo = _socket.getaddrinfo

    def _patched_getaddrinfo(host, port, *args, **kwargs):
        if isinstance(host, str) and host in _drm_hosts:
            ip = _drm_hosts[host]
            results = _orig_getaddrinfo(ip, port, *args, **kwargs)
            # Replace the IP in results but socket connects to the IP
            return results
        return _orig_getaddrinfo(host, port, *args, **kwargs)

    def _url_with_ip(url, hostname, ip):
        return url.replace(f"://{hostname}", f"://{ip}", 1)

    sess_r = requests.Session()
    sess_r.headers["User-Agent"] = ZEE5_UA
    sess_r.trust_env = True

    # Install dnspython quietly if missing
    try:
        import dns.resolver as _dns_resolver_check  # noqa
    except ImportError:
        _log("[DRM] Installing dnspython for DNS bypass...\n")
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "dnspython", "-q",
                 "--break-system-packages"], timeout=30, check=False
            )
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "dnspython", "-q"],
                timeout=30, check=False
            )
        except Exception:
            pass

    for lic_url, entry_hdrs in license_entries:
        # Always raw binary only — HAR confirms Zee5 license server expects raw challenge
        bodies = [(raw_challenge, "raw")]

        _parsed   = _up.urlparse(lic_url)
        _hostname = _parsed.hostname

        for body, label in bodies:
            h = dict(entry_hdrs)   # already has Content-Type: application/octet-stream
            success = False
            raw = b""; status = 0

            # Attempt 1: normal request
            try:
                _log(f"[DRM] POST {label} → {lic_url[:80]}\n")
                _log(f"[DRM]   nl={_nl[:16] + '...' if _nl else '(none)'} | customdata={h.get('customdata','')[:24]}\n")
                r = sess_r.post(lic_url, data=body, headers=h, timeout=30)
                raw = r.content; status = r.status_code; success = True
            except Exception as e:
                err_str = str(e)
                _log(f"[DRM]   error: {err_str[:120]}\n")

                # Attempt 2: UDP DNS bypass → connect via IP with Host header
                if _hostname and ("NameResolution" in err_str or "getaddrinfo" in err_str
                                   or "Failed to resolve" in err_str or "Name or service" in err_str):
                    _log(f"[DRM]   DNS blocked - bypassing via UDP DNS to 8.8.8.8...\n")
                    _ip = _drm_hosts.get(_hostname) or _udp_dns_resolve(_hostname)
                    if _ip:
                        _drm_hosts[_hostname] = _ip
                        _ip_url = _url_with_ip(lic_url, _hostname, _ip)
                        h2 = dict(h); h2["Host"] = _hostname
                        try:
                            _log(f"[DRM]   Resolved {_hostname} → {_ip}, retrying...\n")
                            r = sess_r.post(_ip_url, data=body, headers=h2,
                                            timeout=30, verify=False)
                            raw = r.content; status = r.status_code; success = True
                        except Exception as e2:
                            _log(f"[DRM]   IP-direct also failed: {e2}\n")
                    else:
                        _log(f"[DRM]   UDP DNS also failed to resolve {_hostname}\n")

            if not success:
                continue   # try next entry instead of breaking

            if status == 200:
                data, info = _unwrap(raw)
                _log(f"[DRM]   200 OK → {info}\n")
                if data: lic_resp = data; break
            else:
                _log(f"[DRM]   HTTP {status} | {raw[:200].decode('utf-8','replace')}\n")
        if lic_resp: break

    if not lic_resp:
        _log("[DRM] ✗ All license endpoints failed\n")
        _log("[DRM]   Your ISP is blocking Zee5 DRM domains at DNS level.\n")
        _log("[DRM]   Fix: set your DNS to 8.8.8.8 in Windows Network Settings,\n")
        _log("[DRM]         or use a VPN. Download will continue (encrypted).\n")
        cdm.close(sess)
        return []

    # parse license + extract keys
    try:
        cdm.parse_license(sess, lic_resp)
        keys = []
        for key in cdm.get_keys(sess):
            if key.type == "CONTENT":
                kid_hex = key.kid.hex
                key_hex = key.key.hex()
                keys.append((kid_hex, key_hex))
                _log(f"[DRM] ✓ Key: {kid_hex}:{key_hex}\n")
        cdm.close(sess)
        if not keys: _log("[DRM] ✗ No CONTENT keys in response\n")
        return keys
    except Exception as e:
        _log(f"[DRM] ✗ License parse failed: {e}\n")
        cdm.close(sess)
        return []

def extract_pssh_from_mpd_url(mpd_url, log_cb=None):
    """Download MPD and extract PSSH + license URL."""
    def _log(m):
        if log_cb: log_cb(m)
    try:
        r = requests.get(mpd_url, timeout=12, headers={
            "Referer": "https://www.zee5.com/",
            "User-Agent": ZEE5_UA,
        })
        mpd_text = r.text
        pssh = extract_pssh(mpd_text)
        lic  = extract_license_url_from_mpd(mpd_text)
        if pssh: _log(f"[DRM] PSSH found ({len(pssh)} chars)\n")
        else:    _log("[DRM] No PSSH in MPD - stream may be unencrypted\n")
        if lic: _log(f"[DRM] License URL from MPD: {lic[:80]}\n")
        return mpd_text, pssh, lic
    except Exception as e:
        _log(f"[DRM] MPD fetch error: {e}\n")
        return "", None, None


#  QUALITY PARSING (DASH MPD)


def _split_adaptation_sets(mpd_text):
    blocks = []
    parts = re.split(r'(<AdaptationSet\b[^>]*>)', mpd_text, flags=re.IGNORECASE)
    i = 1
    while i < len(parts) - 1:
        open_tag = parts[i]
        body_and_rest = parts[i+1]
        end_m = re.search(r'</AdaptationSet>', body_and_rest, re.IGNORECASE)
        body = body_and_rest[:end_m.start()] if end_m else body_and_rest
        as_attrs = re.search(r'<AdaptationSet\b(.*?)>', open_tag, re.DOTALL | re.IGNORECASE)
        attrs_str = as_attrs.group(1) if as_attrs else ""
        blocks.append((attrs_str, body))
        i += 2
    return blocks

def _get_attr(text, name, default=None):
    safe_name = re.escape(name)
    m = re.search(rf'(?<![:\w]){safe_name}\s*=\s*"([^"]*)"', text, re.IGNORECASE)
    return m.group(1) if m else default

def get_duration_secs(mpd_text):
    try:
        m = re.search(r'mediaPresentationDuration="PT(?:(\d+)H)?(?:(\d+)M)?([0-9.]+)S"', mpd_text)
        if m:
            return int(m.group(1) or 0)*3600 + int(m.group(2) or 0)*60 + float(m.group(3) or 0)
    except: pass
    return None

def parse_qualities(mpd_url):
    """Parse Zee5 MPD for video qualities, audio tracks, subs."""
    try:
        r = requests.get(mpd_url, timeout=12, headers={
            "Referer": "https://www.zee5.com/",
            "User-Agent": ZEE5_UA,
        })
        txt = r.text
        dur = get_duration_secs(txt)
        out = []; seen_h = set()
        audio_seen = {}; sub_tracks = []; seen_subs = set()
        video_global_idx = 0

        for as_attrs, as_body in _split_adaptation_sets(txt):
            mime   = _get_attr(as_attrs, "mimeType", "")
            ctype  = _get_attr(as_attrs, "contentType", "")
            lang   = (_get_attr(as_attrs, "lang","") or
                      _get_attr(as_attrs, "xml:lang","") or "und")

            is_video = "video" in mime or ctype.lower() == "video"
            is_audio = "audio" in mime or ctype.lower() == "audio"
            is_text  = "text"  in mime or ctype.lower() == "text"

            if not (is_video or is_audio or is_text):
                sample_codecs = _get_attr(as_body[:500], "codecs", "")
                if any(c in sample_codecs.lower() for c in ("avc","hevc","vp9","av1")):
                    is_video = True
                elif any(c in sample_codecs.lower() for c in ("mp4a","ac-3","ec-3","opus")):
                    is_audio = True

            as_w = _get_attr(as_attrs, "width")
            as_h = _get_attr(as_attrs, "height")

            as_id = _get_attr(as_attrs, "id", "")   # AdaptationSet id

            if is_video:
                for rep_attrs in re.findall(r'<Representation\b([^>]+)>', as_body, re.IGNORECASE):
                    w_s = _get_attr(rep_attrs, "width")  or as_w
                    h_s = _get_attr(rep_attrs, "height") or as_h
                    bw_s= _get_attr(rep_attrs, "bandwidth")
                    rid = _get_attr(rep_attrs, "id", "") or as_id  # Representation id (e.g. "manifest240p")

                    if not (w_s and h_s and bw_s):
                        video_global_idx += 1; continue
                    w, h, bw = int(w_s), int(h_s), int(bw_s)
                    if bw < 5000 or h < 144 or (h > 0 and (w/h) > 5.0):
                        video_global_idx += 1; continue

                    lbl = f"{h}p"
                    if lbl not in seen_h:
                        seen_h.add(lbl)
                        est = int((bw/8) * dur * 1.2) if dur else None
                        out.append({
                            "label": lbl, "height": h, "width": w,
                            "bw": bw, "id": rid,
                            "mpd_video_idx": video_global_idx,
                            "est_size": fmt_size(est),
                            "mbps": bw / 1e6,
                        })
                    video_global_idx += 1

            elif is_audio:
                role_m = re.search(r'<Role\b[^>]*value="([^"]*)"', as_body, re.IGNORECASE)
                role_val = role_m.group(1).lower() if role_m else ""
                if role_val in ("description","alternate","supplementary"):
                    continue
                bws = [int(b) for b in re.findall(r'bandwidth="(\d+)"', as_body, re.IGNORECASE)]
                max_kbps = max(bws) / 1000 if bws else 128
                if lang not in audio_seen or max_kbps > audio_seen[lang]:
                    audio_seen[lang] = max_kbps

            elif is_text:
                if lang not in seen_subs:
                    seen_subs.add(lang)
                    sub_tracks.append({"code": lang, "label": lang_label(lang)})

        out.sort(key=lambda x: x["height"], reverse=True)
        audio_tracks = [{"code": lang, "label": lang_label(lang), "max_kbps": kbps}
                        for lang, kbps in audio_seen.items()]
        pssh = extract_pssh(txt)
        return out, dur, audio_tracks, sub_tracks, pssh
    except Exception as e:
        print(f"[parse_qualities] error: {e}")
        import traceback; traceback.print_exc()
        return [], None, [], [], None


#  FILENAME BUILDER


def make_filename(url, quality_height, codec="AVC", audio_codes=None, audio_kbps=None,
                  est_size_str=None, has_subs=False, api_title=None):
    show, ep = extract_show_info_zee5(url)

    def san(s): return re.sub(r'[<>:"/\\|?*]', '', s).strip()
    # prefer real API title over URL-parsed title
    if api_title:
        title = san(api_title[:60])
    else:
        title = san(show[:60]) if show else "Zee5"

    lang_tag = ""
    if audio_codes:
        codes = [c.strip().lower() for c in audio_codes if c.strip()]
        if len(codes) == 1:
            lang_tag = " " + LANG_NAMES.get(codes[0], codes[0].title())
        elif codes:
            names = [LANG_NAMES.get(c, c.title()) for c in codes]
            lang_tag = " " + " + ".join(names)

    kbps = int(audio_kbps) if audio_kbps and audio_kbps > 0 else 0
    if kbps >= 320:
        audio_tag = f"DD+5.1 - {kbps}Kbps"
    elif kbps > 0:
        audio_tag = f"AAC - {kbps}Kbps"
    else:
        audio_tag = "AAC"

    size_tag = f" - {est_size_str}" if est_size_str else ""
    ep_tag   = f" {san(ep[:50])}" if ep else ""

    name = (f"{title}{ep_tag}{lang_tag} TRUE WEB-DL"
            f" - {quality_height}p - {codec} - ({audio_tag}){size_tag}"
            + (" - ESub" if has_subs else "")
            + ".mkv")
    name = re.sub(r'[<>:"/\\|?*]', '', name)
    return name


#  DOWNLOADER


def find_exe(candidates):
    for c in candidates:
        if not c: continue
        try:
            if subprocess.run([c, "--version"], capture_output=True, timeout=5).returncode == 0:
                return c
        except: pass
    return None

def ts_to_secs(ts):
    try:
        p = ts.split(':')
        return int(p[0])*3600 + int(p[1])*60 + float(p[2])
    except: return 0

def mkvmerge_remux(src_path, dst_path, mkvmerge_exe, log_cb, cancel_flag):
    """
    Lossless remux with mkvmerge - fastest possible, zero re-encode.
    mkvmerge is 3-5× faster than ffmpeg -c copy for same output quality.
    Returns True on success.
    """
    if not mkvmerge_exe: return False
    mkvmerge = find_exe([mkvmerge_exe, "mkvmerge"])
    if not mkvmerge:
        log_cb("[mux] mkvmerge not found - skipping fast remux\n"); return False
    tmp = dst_path + ".tmp.mkv"
    cmd = [mkvmerge, "-o", tmp, src_path]
    log_cb(f"[mux] ⚡ mkvmerge remux → {os.path.basename(dst_path)}\n")
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1, errors="replace")
        pct_re = re.compile(r'Progress:\s*(\d+)%')
        for line in proc.stdout:
            if cancel_flag.is_set():
                proc.terminate(); return False
            m = pct_re.search(line)
            if m: log_cb(f"\r[mux] {m.group(1)}%")
        proc.wait()
        if proc.returncode in (0, 1):   # mkvmerge rc=1 = warnings only
            if os.path.exists(tmp):
                os.replace(tmp, dst_path)
                log_cb(f"\n[mux] ✓ mkvmerge done\n"); return True
    except Exception as e:
        log_cb(f"[mux] mkvmerge error: {e}\n")
    if os.path.exists(tmp):
        try: os.remove(tmp)
        except: pass
    return False

def strip_mpd_to_quality(mpd_url, desired_height, log_cb=None):
    """
    Download the MPD, remove every video Representation that does NOT match
    desired_height, inject an absolute <BaseURL> so segments resolve from the
    temp file, and return (tmp_path, base_url_str).

    Strategy:
      • Keep ALL AdaptationSets that are NOT video (audio, text, image …)
      • For the video AdaptationSet(s), keep only the <Representation> whose
        height attribute equals desired_height.
      • If no match found, return (None, None) and caller falls back to full MPD.

    Returns (tmp_mpd_path, None) on success, (None, None) on failure.
    """
    import tempfile
    _log = log_cb or (lambda m: None)

    try:
        import requests as _req
        hdrs = {
            "User-Agent": ZEE5_UA,
            "Referer":    "https://www.zee5.com/",
            "Origin":     "https://www.zee5.com",
        }
        resp = _req.get(mpd_url, headers=hdrs, timeout=15)
        resp.raise_for_status()
        mpd_text = resp.text
    except Exception as e:
        _log(f"[MPD-strip] fetch failed: {e}\n")
        return None, None

    # Derive absolute base URL from MPD URL (everything before ?query and last path component)
    base_url = mpd_url.split('?')[0].rsplit('/', 1)[0] + '/'

    # Detect whether there's already a <BaseURL> in the MPD
    has_base = bool(re.search(r'<BaseURL\b', mpd_text, re.IGNORECASE))

    # collect AdaptationSet blocks
    # Regex: find every <AdaptationSet ... > ... </AdaptationSet>
    as_pattern = re.compile(
        r'(<AdaptationSet\b[^>]*(?:/>|>.*?</AdaptationSet>))',
        re.DOTALL | re.IGNORECASE
    )

    def _attr(text, name):
        m = re.search(rf'\b{re.escape(name)}\s*=\s*"([^"]*)"', text, re.IGNORECASE)
        return m.group(1) if m else ""

    def _content_type(as_block):
        ct = _attr(as_block, "contentType") or _attr(as_block, "mimeType")
        if "video" in ct: return "video"
        if "audio" in ct: return "audio"
        if "text"  in ct: return "text"
        # fallback: check if it has video Representations (width/height)
        if re.search(r'\bheight\s*=\s*"\d+"', as_block, re.IGNORECASE): return "video"
        return "other"

    def _filter_video_as(as_block, height):
        """Keep only Representations matching height; return None if none match."""
        rep_pattern = re.compile(
            r'<Representation\b[^>]*(?:/>|>.*?</Representation>)',
            re.DOTALL | re.IGNORECASE
        )
        matching = []
        for m in rep_pattern.finditer(as_block):
            rep = m.group(0)
            h_str = _attr(rep, "height")
            try:
                h = int(h_str)
            except ValueError:
                continue
            if h == height:
                matching.append(rep)

        if not matching:
            return None   # no matching quality in this AS → drop it

        # Rebuild: open tag + matching Reps only + close tag
        open_m = re.match(r'<AdaptationSet\b[^>]*>', as_block, re.IGNORECASE | re.DOTALL)
        open_tag = open_m.group(0) if open_m else "<AdaptationSet>"
        # Get everything between open and first <Representation> (SegmentTemplate etc.)
        first_rep_pos = rep_pattern.search(as_block)
        pre = as_block[len(open_tag):first_rep_pos.start()] if first_rep_pos else ""
        return open_tag + pre + "\n".join(matching) + "\n</AdaptationSet>"

    # rebuild MPD for target quality
    new_as_blocks = []
    found_video = False
    for m in as_pattern.finditer(mpd_text):
        block = m.group(1)
        ct = _content_type(block)
        if ct == "video":
            filtered = _filter_video_as(block, desired_height)
            if filtered:
                new_as_blocks.append(filtered)
                found_video = True
            # else: drop this video AS (wrong height, no match)
        else:
            new_as_blocks.append(block)   # keep audio/text unchanged

    if not found_video:
        _log(f"[MPD-strip] no video match for height={desired_height} - using original MPD\n")
        return None, None

    # rebuild full MPD doc
    # Find Period block and replace its AdaptationSets
    period_m = re.search(r'<Period\b[^>]*>', mpd_text, re.IGNORECASE | re.DOTALL)
    if not period_m:
        _log("[MPD-strip] no <Period> found - using original MPD\n")
        return None, None

    period_open = period_m.group(0)
    period_start = period_m.start()

    # Everything before Period (includes <MPD> open tag)
    pre_period = mpd_text[:period_start]

    # Inject absolute BaseURL at MPD ROOT level (right before <Period>),
    # NOT inside <Period> — N_m3u8DL-RE resolves segments relative to BaseURL
    # at MPD root scope. Putting it inside Period causes it to be ignored.
    if not has_base:
        base_tag = f"  <BaseURL>{base_url}</BaseURL>\n"
        pre_period = pre_period.rstrip() + "\n" + base_tag
    else:
        base_tag = ""

    new_period = period_open + "\n" + "\n".join(new_as_blocks) + "\n</Period>"

    # Close MPD
    mpd_close_m = re.search(r'</MPD\s*>', mpd_text, re.IGNORECASE)
    mpd_close = mpd_close_m.group(0) if mpd_close_m else "</MPD>"

    new_mpd = pre_period + new_period + "\n" + mpd_close

    # write temp MPD
    try:
        fd, tmp_path = tempfile.mkstemp(suffix=".mpd", prefix="zee5_q_")
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(new_mpd)
        _log(f"[MPD-strip] ✓ stripped MPD → {desired_height}p only | {tmp_path}\n")
        return tmp_path, base_url
    except Exception as e:
        _log(f"[MPD-strip] write failed: {e}\n")
        return None, None


def run_download(stream_url, out_dir, out_name, quality, cfg,
                 progress_cb, log_cb, cancel_flag,
                 drm_keys=None, phase_cb=None):
    """
    Download Zee5 stream with DRM decryption support.
    Engines: N_m3u8DL-RE → yt-dlp → ffmpeg
    Final mux: mkvmerge (fastest, no re-encode) if available, else ffmpeg -c copy.
    """
    os.makedirs(out_dir, exist_ok=True)
    n_path    = cfg.get("n_m3u8dl_path","")
    ytdlp_path= cfg.get("ytdlp_path","yt-dlp")
    ff_path   = cfg.get("ffmpeg_path","ffmpeg")
    mkvmerge_path = cfg.get("mkvmerge_path","mkvmerge")
    threads   = cfg.get("threads", 16)
    dur       = cfg.get("_duration")
    height    = quality["height"] if quality else 0
    out_mkv   = os.path.join(out_dir, out_name + ".mkv")
    engine    = cfg.get("engine","auto")
    audio_lang = cfg.get("audio_lang","best")
    sub_lang   = cfg.get("sub_lang","NONE")
    subs       = cfg.get("grab_subs", False)

    key_flags = []
    if drm_keys:
        for kid, key in drm_keys:
            key_flags += ["--key", f"{kid}:{key}"]

    _mux_keywords     = ("mux","ffmpeg","merge","remux","writing output")
    _decrypt_keywords = ("decrypt","decoding","removing protection")

    def run_proc(cmd, parse_fn):
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, bufsize=1, errors='replace')
            _phase_done = [False]
            for line in proc.stdout:
                if cancel_flag.is_set():
                    proc.terminate()
                    try: proc.wait(timeout=3)
                    except: proc.kill()
                    log_cb("\n[!] Cancelled\n")
                    return -99
                log_cb(line)
                parse_fn(line)
                if phase_cb:
                    ll = line.lower()
                    if any(k in ll for k in _decrypt_keywords):
                        phase_cb("decrypting")
                    elif any(k in ll for k in _mux_keywords):
                        phase_cb("muxing")
            proc.wait()
            return proc.returncode
        except Exception as e:
            log_cb(f"[!] Error: {e}\n")
            return -1

    # N_m3u8DL-RE path
    use_n = engine in ("auto","n_m3u8dl")
    if use_n and n_path and os.path.exists(n_path):
        # quality selection
        # Two Zee5 CDN types:
        #   drongo-vod.zee5.com    → named IDs: "manifest240p", "manifest480p" …
        #   zee5vod.akamaized.net  → numeric IDs: "1", "2", "7" …
        #
        # N_m3u8DL-RE `name=` filter matches stream LABEL, NOT numeric id.
        # So `name=7` silently selects nothing → audio-only output.
        #
        # Safe fallback chain (using original CDN URL so res= resolves fine):
        # priority: res=WxH > name= (named only) > res=Hp > no filter
        stream_name = quality.get("id", "").strip() if quality else ""
        width       = quality.get("width", 0) if quality else 0

        if height and width:
            sel = f"res={width}x{height}"
            log_cb(f"[quality] Using resolution filter: {sel}\n")
        elif stream_name and not stream_name.isdigit():
            # Named stream ID (manifest240p etc.) — safe to use name= filter
            sel = f"name={stream_name}"
            log_cb(f"[quality] Using stream name filter: {sel}\n")
        elif height:
            sel = f"res={height}p"
            log_cb(f"[quality] Using height filter: {sel}\n")
        else:
            sel = None

        cmd = [n_path, stream_url,
               "--save-name", out_name, "--save-dir", out_dir,
               "--binary-merge", "--del-after-done", "--no-date-info",
               "--thread-count", str(threads), "-mt",
               "--mux-after-done", "format=mkv",
               "--no-log",
               "--header", "Referer: https://www.zee5.com/",
               "--header", "Origin: https://www.zee5.com"]

        if key_flags:
            cmd += key_flags
            log_cb(f"[DRM] Passing {len(drm_keys)} key(s) to N_m3u8DL-RE\n")

        # Audio selection:
        # N_m3u8DL-RE REQUIRES an explicit --select-audio flag; omitting it = no audio selected.
        # "all" is a literal keyword that selects every audio track.
        # lang=te  filters to single lang.
        # lang=(te|hi) picks only the FIRST regex match — not multi-audio.
        # So: single lang → filter; multi lang / best / all → "all" keyword.
        if audio_lang and audio_lang not in ("best","all",""):
            codes = [c.strip() for c in audio_lang.split(",") if c.strip()]
            if len(codes) == 1:
                cmd += ["--select-audio", f"lang={codes[0]}:for=best"]
                log_cb(f"[audio] Filter: lang={codes[0]}:for=best\n")
            else:
                # Use :for=bestN to select exactly N tracks matching the regex
                # e.g. lang=(ta|te):for=best2 picks best Tamil + best Telugu
                lang_re = "|".join(codes)
                n = len(codes)
                cmd += ["--select-audio", f"lang=({lang_re}):for=best{n}"]
                log_cb(f"[audio] Multi-lang ({','.join(codes)}) → lang=({lang_re}):for=best{n}\n")
        else:
            cmd += ["--select-audio", "all"]
            log_cb(f"[audio] --select-audio all\n")

        if sel:
            cmd += ["--select-video", sel]

        if sub_lang == "ALL" or subs:
            cmd += ["--select-subtitle", "all"]
        elif sub_lang and sub_lang not in ("NONE",""):
            codes_s = [c.strip() for c in sub_lang.split(",") if c.strip()]
            if len(codes_s) == 1:
                cmd += ["--select-subtitle", f"lang={codes_s[0]}"]
            else:
                cmd += ["--select-subtitle", "lang=(" + "|".join(codes_s) + ")"]

        mode_label = "sel=" + (sel or "best")
        log_cb(f"[N_m3u8DL-RE] {threads} threads | {height}p | {mode_label}\n")
        log_cb(f"[N_m3u8DL-RE] cmd: {' '.join(str(x) for x in cmd[-14:])}\n\n")
        pct_re  = re.compile(r'(\d+(?:\.\d+)?)\s*%')
        spd_re  = re.compile(r'(\d+(?:\.\d+)?)\s*(K|M|G)B/s', re.I)
        _mux_kw = re.compile(r'binary merging|mux|remux|ffmpeg|writing output', re.I)
        def parse_n(line):
            if _mux_kw.search(line):
                if phase_cb: phase_cb("muxing")
                return
            pm = pct_re.search(line); sm = spd_re.search(line)
            if pm:
                if phase_cb: phase_cb("downloading")
                progress_cb(float(pm.group(1)), f"{sm.group(1)} {sm.group(2)}B/s" if sm else "")
        rc = run_proc(cmd, parse_n)
        if rc == 0:
            progress_cb(100,"")
            # ⚡ Fast mkvmerge remux — cleans DASH container artifacts, near-instant
            if os.path.exists(out_mkv) and find_exe([mkvmerge_path, "mkvmerge"]):
                if phase_cb: phase_cb("muxing")
                mkvmerge_remux(out_mkv, out_mkv, mkvmerge_path, log_cb, cancel_flag)
            return True, out_mkv
        if rc == -99: return False, None
        if engine == "n_m3u8dl":
            log_cb("[✗] N_m3u8DL-RE failed.\n"); return False, None
        log_cb("[!] N_m3u8DL-RE failed, trying yt-dlp...\n\n")

    # yt-dlp path
    use_yt = engine in ("auto","ytdlp")
    ytdlp = None
    if use_yt:
        ytdlp = find_exe([ytdlp_path,"yt-dlp"])
        if not ytdlp:
            try:
                subprocess.run([sys.executable, "-m", "pip", "install", "yt-dlp", "-q"], timeout=60)
                ytdlp = find_exe(["yt-dlp"])
                if ytdlp: log_cb("[✓] yt-dlp installed\n\n")
            except: pass

    if use_yt and ytdlp:
        if audio_lang and audio_lang not in ("best",""):
            first_lang = audio_lang.split(",")[0].strip()
            audio_fmt = f"bestaudio[language={first_lang}]/bestaudio"
        else:
            audio_fmt = "bestaudio"
        fmt = (f"bestvideo[height<={height}]+{audio_fmt}/best[height<={height}]"
               if height else f"bestvideo+{audio_fmt}/best")
        cmd = [ytdlp, stream_url,
               "-f", fmt,
               "--concurrent-fragments", str(min(threads,16)),
               "--no-playlist", "-o", out_mkv,
               "--add-header", "Referer: https://www.zee5.com/",
               "--add-header", "Origin: https://www.zee5.com",
               "--merge-output-format", "mkv",
               "--no-warnings", "--newline"]
        if key_flags:
            log_cb("[DRM] Note: yt-dlp doesn't support raw key injection - use N_m3u8DL-RE for DRM\n")
        log_cb(f"[yt-dlp] {min(threads,16)} frags | {height}p\n\n")
        pct_re  = re.compile(r'\[download\]\s+(\d+\.?\d*)%.*?(\d+\.?\d*\s*\w+/s)')
        pct_re2 = re.compile(r'\[download\]\s+(\d+\.?\d*)%')
        def parse_yt(line):
            m = pct_re.search(line)
            if m: progress_cb(float(m.group(1)), m.group(2)); return
            m = pct_re2.search(line)
            if m: progress_cb(float(m.group(1)), "")
        rc = run_proc(cmd, parse_yt)
        if rc == 0: progress_cb(100,""); return True, out_mkv
        if rc == -99: return False, None
        if engine == "ytdlp":
            log_cb("[✗] yt-dlp failed.\n"); return False, None
        log_cb("[!] yt-dlp failed, falling back to ffmpeg\n\n")

    # 3. ffmpeg fallback
    ff = find_exe([ff_path,"ffmpeg"])
    if not ff:
        log_cb("[✗] No downloader found.\n    Install yt-dlp: pip install yt-dlp\n")
        return False, None

    mpd_idx = quality.get("mpd_video_idx") if quality else None
    cmd = [ff, "-allowed_extensions", "ALL",
           "-headers", "Referer: https://www.zee5.com/\r\nOrigin: https://www.zee5.com\r\n",
           "-i", stream_url]
    if mpd_idx is not None:
        cmd += ["-map", f"0:v:{mpd_idx}", "-map", "0:a:0"]
    cmd += ["-c", "copy", out_mkv, "-y",
            "-progress", "pipe:1", "-nostats", "-loglevel", "error"]
    if key_flags:
        log_cb("[DRM] Note: ffmpeg fallback doesn't support raw Widevine key injection\n")
    log_cb(f"[ffmpeg] sequential | {height}p\n\n")

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, bufsize=1, errors='replace')
        def read_err():
            for l in proc.stderr: log_cb(l)
        threading.Thread(target=read_err, daemon=True).start()
        spd = ""
        for line in proc.stdout:
            if cancel_flag.is_set():
                proc.terminate()
                try: proc.wait(timeout=3)
                except: proc.kill()
                return False, None
            sm = re.search(r'speed=\s*([0-9.]+)x', line)
            if sm: spd = f"{sm.group(1)}x"
            m = re.search(r'out_time=(\d+:\d+:\d+\.\d+)', line)
            if m and dur:
                pct = min(ts_to_secs(m.group(1)) / dur * 100, 99.9)
                progress_cb(pct, spd)
        proc.wait()
        if proc.returncode == 0:
            progress_cb(100, ""); return True, out_mkv
        log_cb(f"[✗] ffmpeg failed (rc={proc.returncode})\n")
        return False, None
    except Exception as e:
        log_cb(f"[!] ffmpeg error: {e}\n")
        return False, None


#  GUI


# colour palette (matches JioHotstar dark UI)
C_BG       = "#111827"   # main background
C_PANEL    = "#1f2937"   # card / panel background
C_PANEL2   = "#283040"   # slightly lighter panel
C_ACCENT   = "#6c63ff"   # purple accent (buttons, active tab)
C_ACCENT2  = "#5b54e8"   # hover / darker accent
C_TEXT     = "#f3f4f6"   # primary text
C_MUTED    = "#9ca3af"   # secondary text
C_GREEN    = "#34d399"   # success
C_RED      = "#f87171"   # error
C_ORANGE   = "#fbbf24"   # warning
C_CYAN     = "#67e8f9"   # info / size labels
C_BORDER   = "#374151"   # border / separator


class CheckRow(tk.Frame):
    """Quality-row widget - custom canvas checkbox + info columns, JioHotstar style."""
    def __init__(self, parent, var, height_p, width_p, mbps, est_size, runtime="", is_top=False, **kw):
        super().__init__(parent, bg=C_PANEL, cursor="hand2", **kw)
        self.var = var
        self._hovered = False

        self.cv = tk.Canvas(self, width=18, height=18, bg=C_PANEL,
                            highlightthickness=0, cursor="hand2")
        self.cv.pack(side="left", padx=(6, 8), pady=6)
        self._draw()

        q_color = {1080: C_ACCENT, 720: C_GREEN, 480: C_ORANGE, 360: C_MUTED}.get(height_p, C_MUTED)
        tk.Label(self, text=f"{height_p}p",     bg=C_PANEL, fg=q_color,
                 font=("Consolas", 10, "bold"), width=6,  anchor="w").pack(side="left")
        tk.Label(self, text=f"{width_p}×{height_p}", bg=C_PANEL, fg=C_MUTED,
                 font=("Consolas", 9),           width=11, anchor="w").pack(side="left")
        tk.Label(self, text=f"{mbps:.1f} Mbps", bg=C_PANEL, fg=C_MUTED,
                 font=("Consolas", 9),           width=10, anchor="w").pack(side="left")
        tk.Label(self, text=est_size,            bg=C_PANEL,
                 fg=C_GREEN if is_top else C_MUTED,
                 font=("Consolas", 9, "bold" if is_top else "normal"),
                 width=10, anchor="w").pack(side="left")
        tk.Label(self, text=runtime,             bg=C_PANEL, fg=C_MUTED,
                 font=("Consolas", 9),           width=9,  anchor="w").pack(side="left")

        self._bind_all(self)
        var.trace_add("write", lambda *_: self._draw())

    def _bind_all(self, w):
        w.bind("<Button-1>", self._toggle)
        w.bind("<Enter>",    self._on_enter)
        w.bind("<Leave>",    self._on_leave)
        for child in w.winfo_children():
            self._bind_all(child)

    def _toggle(self, e=None):   self.var.set(not self.var.get())
    def _on_enter(self, e=None): self._hovered = True;  self._set_bg(C_PANEL2)
    def _on_leave(self, e=None): self._hovered = False; self._set_bg(C_PANEL)

    def _set_bg(self, c):
        self.configure(bg=c); self.cv.configure(bg=c)
        for w in self.winfo_children():
            try: w.configure(bg=c)
            except: pass

    def _draw(self):
        cv = self.cv; cv.delete("all")
        checked = self.var.get()
        cv.create_rectangle(1, 1, 17, 17,
                            fill=C_ACCENT if checked else C_PANEL2,
                            outline=C_ACCENT if checked else C_BORDER, width=1)
        if checked:
            cv.create_line(3, 9,  7, 13, fill="#fff", width=2, capstyle="round")
            cv.create_line(7, 13, 15, 5, fill="#fff", width=2, capstyle="round")


class Zee5DownloaderApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Zee5 Downloader  •  v1 DRM")
        self.root.geometry("980x720")
        self.root.minsize(820, 600)
        self.root.resizable(True, True)
        self.cfg     = load_cfg()
        self.token   = None
        self.platform_token = ""
        self.qualities    = []
        self.audio_tracks = []
        self.sub_tracks   = []
        self.mpd_url   = None
        self.m3u8_url  = None
        self.lic_url   = None
        self.nl_token  = ""   # Nagra license token (from keyOsDetails.nl)
        self.api_title = ""   # real title from content API (overrides URL parse)
        self.cancel_flag = threading.Event()
        self._build_ui()
        self._startup()

    # colour helpers (use tk.Label for anything needing dynamic fg)
    def _lbl(self, parent, text, fg=C_TEXT, bg=C_PANEL, font=None, **kw):
        kw.setdefault("anchor", "w")
        return tk.Label(parent, text=text, fg=fg, bg=bg,
                        font=font or ("Segoe UI", 9), **kw)

    def _btn(self, parent, text, cmd, accent=False, small=False, **kw):
        bg  = C_ACCENT  if accent else C_PANEL2
        fg  = "#ffffff"
        abg = C_ACCENT2 if accent else C_BORDER
        font = ("Segoe UI", 9, "bold") if accent else ("Segoe UI", 9)
        if small:
            font = ("Segoe UI", 8)
        b = tk.Button(parent, text=text, command=cmd, bg=bg, fg=fg,
                      activebackground=abg, activeforeground=fg,
                      relief="flat", bd=0, padx=10, pady=5, cursor="hand2",
                      font=font, **kw)
        b.bind("<Enter>", lambda e: b.config(bg=abg))
        b.bind("<Leave>", lambda e: b.config(bg=bg))
        return b

    def _entry(self, parent, var, width=None, **kw):
        e = tk.Entry(parent, textvariable=var,
                     bg=C_PANEL2, fg=C_TEXT, insertbackground=C_TEXT,
                     relief="flat", bd=0, highlightthickness=1,
                     highlightbackground=C_BORDER, highlightcolor=C_ACCENT,
                     font=("Segoe UI", 9), **kw)
        if width: e.config(width=width)
        return e

    def _sep(self, parent, color=C_BORDER):
        return tk.Frame(parent, bg=color, height=1)

    # STARTUP
    def _startup(self):
        def _bg():
            pt = get_platform_token()
            self.platform_token = pt
            if pt:
                self.root.after(0, lambda: self._log("[✓] Platform token obtained\n"))
            else:
                self.root.after(0, lambda: self._log("[!] Could not get platform token\n"))
            tok, path = load_token(self.cfg)
            if tok:
                self.token = tok
                self.root.after(0, lambda: [
                    self._log(f"[✓] Loaded saved token from {path}\n"),
                    self._set_login_state(True),
                ])
            else:
                self.root.after(0, lambda: self._log("[!] No saved token - please log in\n"))
        threading.Thread(target=_bg, daemon=True).start()

    def _set_login_state(self, ok, msg=None):
        if ok:
            self.lbl_login_status.config(text="● " + (msg or "Logged in"), fg=C_GREEN)
            self.hdr_status.config(text="● Logged in", fg=C_GREEN)
            self.btn_send_otp.config(text="Re-Login")
        else:
            self.lbl_login_status.config(text="✗ " + (msg or "Login failed"), fg=C_RED)

    # UI BUILD
    def _build_ui(self):
        root = self.root
        root.configure(bg=C_BG)

        # Header bar
        hdr = tk.Frame(root, bg=C_PANEL, pady=8)
        hdr.pack(fill="x")

        tk.Label(hdr, text="▶", fg=C_ACCENT, bg=C_PANEL,
                 font=("Segoe UI", 16, "bold")).pack(side="left", padx=(14,6))
        tk.Label(hdr, text="Zee5 Downloader", fg=C_TEXT, bg=C_PANEL,
                 font=("Segoe UI", 13, "bold")).pack(side="left")

        self.hdr_status = tk.Label(hdr, text="● Not logged in", fg=C_RED,
                                   bg=C_PANEL, font=("Segoe UI", 9))
        self.hdr_status.pack(side="right", padx=16)

        self._sep(root, C_ACCENT).pack(fill="x")

        # Tab bar (manual, like JioHotstar)
        tab_bar = tk.Frame(root, bg=C_PANEL)
        tab_bar.pack(fill="x")

        self._tab_frames   = {}
        self._tab_btns     = {}
        self._content_host = tk.Frame(root, bg=C_BG)
        self._content_host.pack(fill="both", expand=True)

        for name in ("Login", "Download", "Settings"):
            f = tk.Frame(self._content_host, bg=C_BG)
            self._tab_frames[name] = f
            btn = tk.Button(tab_bar, text=name, bg=C_PANEL, fg=C_MUTED,
                            relief="flat", bd=0, padx=20, pady=8,
                            font=("Segoe UI", 10), cursor="hand2",
                            command=lambda n=name: self._switch_tab(n))
            btn.pack(side="left")
            self._tab_btns[name] = btn

        self._sep(root, C_BORDER).pack(fill="x")

        # Build each tab
        self._build_login_tab()
        self._build_download_tab()
        self._build_settings_tab()

        # footer
        footer = tk.Frame(root, bg=C_PANEL, pady=4)
        footer.pack(fill="x", side="bottom")
        tk.Label(footer, text="made by Rvind", fg=C_MUTED,
                 bg=C_PANEL, font=("Segoe UI", 8)).pack()

        self._switch_tab("Login")

    def _switch_tab(self, name):
        for n, f in self._tab_frames.items():
            f.pack_forget()
        for n, b in self._tab_btns.items():
            if n == name:
                b.config(bg=C_ACCENT, fg="#ffffff", font=("Segoe UI", 10, "bold"))
            else:
                b.config(bg=C_PANEL, fg=C_MUTED, font=("Segoe UI", 10))
        self._tab_frames[name].pack(fill="both", expand=True)


    #  TAB: LOGIN

    def _build_login_tab(self):
        f = self._tab_frames["Login"]

        card = tk.Frame(f, bg=C_PANEL, bd=0, relief="flat", padx=30, pady=24)
        card.place(relx=0.5, rely=0.38, anchor="center")

        tk.Label(card, text="Phone Login", fg=C_ACCENT, bg=C_PANEL,
                 font=("Segoe UI", 15, "bold")).grid(
                 row=0, column=0, columnspan=2, sticky="w", pady=(0,16))

        # Phone field
        tk.Label(card, text="Phone number  (10 digits, no +91)",
                 fg=C_MUTED, bg=C_PANEL, font=("Segoe UI", 8)).grid(
                 row=1, column=0, columnspan=2, sticky="w")
        self.var_mobile = tk.StringVar()
        phone_row = tk.Frame(card, bg=C_PANEL)
        phone_row.grid(row=2, column=0, columnspan=2, sticky="w", pady=(4,12))
        self._entry(phone_row, self.var_mobile, width=22).pack(side="left", padx=(0,8), ipady=4)
        self.btn_send_otp = self._btn(phone_row, "Send OTP", self._do_send_otp, accent=True)
        self.btn_send_otp.pack(side="left")

        # OTP field
        tk.Label(card, text="OTP", fg=C_MUTED, bg=C_PANEL,
                 font=("Segoe UI", 8)).grid(row=3, column=0, sticky="w")
        self.var_otp = tk.StringVar()
        otp_row = tk.Frame(card, bg=C_PANEL)
        otp_row.grid(row=4, column=0, columnspan=2, sticky="w", pady=(4,16))
        self._entry(otp_row, self.var_otp, width=12).pack(side="left", padx=(0,8), ipady=4)
        self._btn(otp_row, "Verify & Login", self._do_verify_otp).pack(side="left")

        # Status
        self.lbl_login_status = tk.Label(card, text="", fg=C_MUTED, bg=C_PANEL,
                                          font=("Segoe UI", 9))
        self.lbl_login_status.grid(row=5, column=0, columnspan=2, sticky="w")

        # Session panel
        sess = tk.Frame(f, bg=C_PANEL, padx=24, pady=14)
        sess.place(relx=0.5, rely=0.72, anchor="center")
        tk.Label(sess, text="Session", fg=C_ACCENT, bg=C_PANEL,
                 font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.lbl_sess_detail = tk.Label(sess, text="✗  No token - use Login tab",
                                         fg=C_RED, bg=C_PANEL, font=("Segoe UI", 9))
        self.lbl_sess_detail.pack(anchor="w", pady=(4,8))
        self._btn(sess, "Clear Token", self._do_clear_token, small=True).pack(anchor="w")


    #  TAB: DOWNLOAD

    def _build_download_tab(self):
        f = self._tab_frames["Download"]
        f.columnconfigure(0, weight=1)

        pad = dict(padx=12, pady=6)

        # URL bar
        url_row = tk.Frame(f, bg=C_BG)
        url_row.pack(fill="x", **pad)
        self._lbl(url_row, "Zee5 URL or Content ID", fg=C_MUTED, bg=C_BG,
                  font=("Segoe UI", 8)).pack(anchor="w", pady=(0,2))
        ue = tk.Frame(url_row, bg=C_BG)
        ue.pack(fill="x")
        self.var_url = tk.StringVar()
        self._entry(ue, self.var_url).pack(side="left", fill="x", expand=True,
                                           padx=(0,8), ipady=5)
        self._btn(ue, "🔍  Fetch Qualities", self._do_fetch, accent=True).pack(side="left")

        # Queue row
        q_row = tk.Frame(f, bg=C_BG)
        q_row.pack(fill="x", padx=12, pady=(0,6))
        self._lbl(q_row, "or add to queue:", fg=C_MUTED, bg=C_BG,
                  font=("Segoe UI", 8)).pack(side="left")
        self._btn(q_row, "+ Queue", lambda: None, small=True).pack(side="left", padx=6)
        self.lbl_queue = tk.Label(q_row, text="Queue: 0 items",
                                   fg=C_MUTED, bg=C_BG, font=("Segoe UI", 8))
        self.lbl_queue.pack(side="left")

        self._sep(f).pack(fill="x", padx=12, pady=4)

        # ttk style (kept for progressbar only)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Horizontal.TProgressbar",
                        background=C_ACCENT, troughcolor=C_PANEL2)

        # Qualities / Tracks card
        tracks_card = tk.Frame(f, bg=C_PANEL, padx=12, pady=10)
        tracks_card.pack(fill="x", padx=12, pady=4)

        # Card header row with All / None quality toggles
        tc_hdr = tk.Frame(tracks_card, bg=C_PANEL)
        tc_hdr.pack(fill="x")
        self._lbl(tc_hdr, "Select Qualities to Download", fg=C_MUTED, bg=C_PANEL,
                  font=("Segoe UI", 9)).pack(side="left")
        self._btn(tc_hdr, "None", lambda: self._check_all_q(False),
                  small=True).pack(side="right", padx=(2, 0))
        self._btn(tc_hdr, "All",  lambda: self._check_all_q(True),
                  small=True).pack(side="right")

        # Dynamic frame — _show_quals() rebuilds this on every fetch
        self._q_frame = tk.Frame(tracks_card, bg=C_PANEL)
        self._q_frame.pack(fill="x")
        self._q_vars        = []   # list of BooleanVar (one per quality row)
        self._audio_cb_vars = {}   # code → BooleanVar
        self._sub_cb_vars   = {}   # code → BooleanVar
        # legacy compat aliases still used by _check_all
        self.audio_vars = []
        self.sub_vars   = []

        self._q_hint = tk.Label(self._q_frame,
            text="← paste a URL and click  Fetch Qualities",
            bg=C_PANEL, fg=C_MUTED, font=("Segoe UI", 9))
        self._q_hint.pack(anchor="w", pady=6)

        # Output dir
        out_card = tk.Frame(f, bg=C_PANEL, padx=12, pady=10)
        out_card.pack(fill="x", padx=12, pady=4)
        out_card.columnconfigure(1, weight=1)

        self._lbl(out_card, "Output Directory", fg=C_TEXT, bg=C_PANEL).grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0,6))
        self.var_outdir = tk.StringVar(value=self.cfg.get("output_dir", ""))
        self._entry(out_card, self.var_outdir).grid(row=1, column=0, sticky="ew",
                                                     padx=(0,8), ipady=4, columnspan=2)
        self._btn(out_card, "Browse", self._browse_outdir, small=True).grid(
            row=1, column=2, sticky="e")

        # Filename
        fn_row = tk.Frame(f, bg=C_BG)
        fn_row.pack(fill="x", padx=12, pady=(2,6))
        self._lbl(fn_row, "Filename:", fg=C_MUTED, bg=C_BG,
                  font=("Segoe UI", 8)).pack(side="left", padx=(0,6))
        self.var_fname = tk.StringVar()
        self._entry(fn_row, self.var_fname).pack(side="left", fill="x", expand=True, ipady=3)

        # DRM status
        drm_row = tk.Frame(f, bg=C_BG)
        drm_row.pack(fill="x", padx=12)
        self.lbl_drm = tk.Label(drm_row, text="DRM: -", fg=C_MUTED, bg=C_BG,
                                 font=("Segoe UI", 8))
        self.lbl_drm.pack(side="left")

        # Download btn + progress
        dl_row = tk.Frame(f, bg=C_BG)
        dl_row.pack(fill="x", padx=12, pady=8)
        self.btn_dl = self._btn(dl_row, "⬇  Download", self._do_download, accent=True)
        self.btn_dl.pack(side="left")
        self._btn(dl_row, "⏷  Open Folder", self._open_folder, small=True).pack(
            side="left", padx=8)
        self.lbl_status = tk.Label(dl_row, text="", fg=C_GREEN, bg=C_BG,
                                    font=("Segoe UI", 9))
        self.lbl_status.pack(side="left", padx=8)
        self._btn(dl_row, "✕", self._do_cancel, small=True).pack(side="right", padx=4)

        self.var_progress = tk.DoubleVar()
        pbar_row = tk.Frame(f, bg=C_BG)
        pbar_row.pack(fill="x", padx=12, pady=(0,4))
        self.pbar = ttk.Progressbar(pbar_row, variable=self.var_progress, maximum=100,
                                     style="Horizontal.TProgressbar")
        self.pbar.pack(side="left", fill="x", expand=True)
        self.lbl_pct = tk.Label(pbar_row, text="0%", fg=C_ACCENT, bg=C_BG,
                                 font=("Segoe UI", 8, "bold"), width=5)
        self.lbl_pct.pack(side="left", padx=(6,0))
        self.lbl_speed = tk.Label(f, text="", fg=C_ACCENT, bg=C_BG, font=("Segoe UI", 8))
        self.lbl_speed.pack(anchor="e", padx=14)

        # Log toggle
        log_toggle = tk.Frame(f, bg=C_BG)
        log_toggle.pack(fill="x", padx=12, pady=(0,2))
        self.log_visible = tk.BooleanVar(value=True)
        tk.Button(log_toggle, text="▾ Show log", fg=C_MUTED, bg=C_BG,
                  relief="flat", bd=0, cursor="hand2", font=("Segoe UI", 8),
                  command=self._toggle_log).pack(side="left")

        self.log_box = scrolledtext.ScrolledText(
            f, height=10, bg="#0d1117", fg="#cdd6f4",
            font=("Consolas", 8), relief="flat", bd=0,
            insertbackground=C_TEXT)
        self.log_box.pack(fill="both", expand=True, padx=12, pady=(0,8))


    #  TAB: SETTINGS

    def _build_settings_tab(self):
        f = self._tab_frames["Settings"]

        canvas = tk.Canvas(f, bg=C_BG, highlightthickness=0)
        canvas.pack(fill="both", expand=True)
        inner = tk.Frame(canvas, bg=C_BG)
        canvas.create_window((0,0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: canvas.configure(
            scrollregion=canvas.bbox("all")))

        def section(title):
            tk.Frame(inner, bg=C_BORDER, height=1).pack(fill="x", padx=16, pady=(16,4))
            tk.Label(inner, text=f"--  {title}  --", fg=C_MUTED, bg=C_BG,
                     font=("Segoe UI", 8)).pack(padx=16, anchor="w")

        # Custom radio card helpers (no tkinter Radiobutton — avoids Windows
        #    rendering bug where selectcolor bleeds into ALL cards at once) ──────
        _engine_cards  = {}   # key → (outer_frame, dot_canvas, title_label, sub_label)
        _decrypt_cards = {}

        def _refresh_engine_cards(*_):
            sel = self._cfg_vars["engine"].get()
            for k, (outer, dot, tlbl, slbl) in _engine_cards.items():
                active = (k == sel)
                bg  = C_PANEL2
                bdr = C_ACCENT if active else C_BORDER
                outer.config(highlightbackground=bdr, highlightcolor=bdr,
                             highlightthickness=2 if active else 1)
                dot.delete("all")
                dot.create_oval(1, 1, 13, 13,
                                outline=C_ACCENT if active else C_MUTED, width=2)
                if active:
                    dot.create_oval(4, 4, 10, 10, fill=C_ACCENT, outline=C_ACCENT)
                tlbl.config(fg=C_TEXT if active else C_MUTED)

        def _refresh_decrypt_cards(*_):
            sel = self._cfg_vars["decrypt_tool"].get()
            for k, (outer, dot, tlbl, slbl) in _decrypt_cards.items():
                active = (k == sel)
                outer.config(highlightbackground=C_ACCENT if active else C_BORDER,
                             highlightcolor=C_ACCENT if active else C_BORDER,
                             highlightthickness=2 if active else 1)
                dot.delete("all")
                dot.create_oval(1, 1, 13, 13,
                                outline=C_ACCENT if active else C_MUTED, width=2)
                if active:
                    dot.create_oval(4, 4, 10, 10, fill=C_ACCENT, outline=C_ACCENT)
                tlbl.config(fg=C_TEXT if active else C_MUTED)

        def engine_card(parent, label, sublabel, key):
            outer = tk.Frame(parent, bg=C_PANEL2,
                             highlightthickness=1, highlightbackground=C_BORDER,
                             highlightcolor=C_BORDER, cursor="hand2")
            outer.pack(side="left", expand=True, fill="both", padx=4)
            inner_c = tk.Frame(outer, bg=C_PANEL2, padx=10, pady=8)
            inner_c.pack(fill="both", expand=True)
            # dot indicator
            dot = tk.Canvas(inner_c, width=14, height=14, bg=C_PANEL2,
                            bd=0, highlightthickness=0)
            dot.pack(side="left", anchor="n", padx=(0, 6), pady=2)
            right = tk.Frame(inner_c, bg=C_PANEL2)
            right.pack(side="left", fill="both", expand=True)
            tlbl = tk.Label(right, text=label, fg=C_TEXT, bg=C_PANEL2,
                            font=("Segoe UI", 9, "bold"), anchor="w")
            tlbl.pack(anchor="w")
            slbl = tk.Label(right, text=sublabel, fg=C_MUTED, bg=C_PANEL2,
                            font=("Segoe UI", 7), wraplength=155, justify="left")
            slbl.pack(anchor="w")
            _engine_cards[key] = (outer, dot, tlbl, slbl)
            def _click(_k=key):
                self._cfg_vars["engine"].set(_k)
                _refresh_engine_cards()
            for w in (outer, inner_c, dot, right, tlbl, slbl):
                w.bind("<Button-1>", lambda e, _k=key: _click(_k))
            return outer

        def decrypt_card(parent, label, sublabel, key):
            outer = tk.Frame(parent, bg=C_PANEL2,
                             highlightthickness=1, highlightbackground=C_BORDER,
                             highlightcolor=C_BORDER, cursor="hand2")
            outer.pack(side="left", expand=True, fill="both", padx=4)
            inner_c = tk.Frame(outer, bg=C_PANEL2, padx=10, pady=8)
            inner_c.pack(fill="both", expand=True)
            dot = tk.Canvas(inner_c, width=14, height=14, bg=C_PANEL2,
                            bd=0, highlightthickness=0)
            dot.pack(side="left", anchor="n", padx=(0, 6), pady=2)
            right = tk.Frame(inner_c, bg=C_PANEL2)
            right.pack(side="left", fill="both", expand=True)
            tlbl = tk.Label(right, text=label, fg=C_TEXT, bg=C_PANEL2,
                            font=("Segoe UI", 9, "bold"), anchor="w")
            tlbl.pack(anchor="w")
            slbl = tk.Label(right, text=sublabel, fg=C_MUTED, bg=C_PANEL2,
                            font=("Segoe UI", 7), wraplength=155, justify="left")
            slbl.pack(anchor="w")
            _decrypt_cards[key] = (outer, dot, tlbl, slbl)
            def _click(_k=key):
                self._cfg_vars["decrypt_tool"].set(_k)
                _refresh_decrypt_cards()
            for w in (outer, inner_c, dot, right, tlbl, slbl):
                w.bind("<Button-1>", lambda e, _k=key: _click(_k))

        self._cfg_vars = {}

        # engine + decrypt vars need to exist before calling engine_card
        self._cfg_vars["engine"]       = tk.StringVar(value=self.cfg.get("engine","n_m3u8dl"))
        self._cfg_vars["decrypt_tool"] = tk.StringVar(value=self.cfg.get("decrypt_tool","auto"))

        section("Download Engine")
        eng_row = tk.Frame(inner, bg=C_BG)
        eng_row.pack(fill="x", padx=16, pady=4)
        engine_card(eng_row, "⬡  Auto",        "Fastest - picks best tool automatically", "auto")
        engine_card(eng_row, "⚡ N_m3u8DL-RE", "Fastest - parallel · multi-audio · DRM keys ✓", "n_m3u8dl")
        engine_card(eng_row, "⬇  yt-dlp",      "Good fallback - single audio · no DRM key inject", "ytdlp")
        engine_card(eng_row, "✂  ffmpeg",       "Slow but stable - no DRM key inject", "ffmpeg")
        # Apply initial highlight state after all cards are built
        self.root.after(10, _refresh_engine_cards)

        section("Paths")
        _home = os.path.expanduser("~")
        _dl   = os.path.join(_home, "Downloads")
        path_fields = [
            ("Token File",         "token_file",      os.path.join(APP_DIR, "zee5_token.json"),
             "Path to save/load your login token"),
            ("Output Folder",      "output_dir",      _dl,
             "Default download destination"),
            ("N_m3u8DL-RE exe",    "n_m3u8dl_path",   "N_m3u8DL-RE",
             "⚡ Fastest + inline DRM.  github.com/nilaoda/N_m3u8DL-RE"),
            ("yt-dlp exe",         "ytdlp_path",      "yt-dlp",
             "⬇ Fallback.  pip install yt-dlp"),
            ("ffmpeg exe",         "ffmpeg_path",     "ffmpeg",
             "✂ Muxing.  'ffmpeg' if in PATH"),
            ("WVD Device File",    "cdm_path",        "",
             "🔑 Widevine L3 .wvd for key fetching"),
            ("Shaka Packager exe", "shaka_path",      "shaka-packager",
             "📦 Post-decrypt tool.  github.com/shaka-project/shaka-packager"),
            ("mp4decrypt exe",     "mp4decrypt_path", "mp4decrypt",
             "🔓 Bento4 post-decrypt.  github.com/axiomatic-systems/Bento4"),
            ("mkvmerge exe",       "mkvmerge_path",   "mkvmerge",
             "⚡ MKVToolNix - fastest lossless mux.  mkvtoolnix.download"),
        ]

        path_card = tk.Frame(inner, bg=C_PANEL, padx=12, pady=8)
        path_card.pack(fill="x", padx=16, pady=4)
        path_card.columnconfigure(1, weight=1)

        def browse_path(var, title="Select File"):
            from tkinter import filedialog as fd
            p = fd.askopenfilename(title=title)
            if p: var.set(p)

        for i, (label, key, default, hint) in enumerate(path_fields):
            current = self.cfg.get(key, default) or default
            v = tk.StringVar(value=current)
            self._cfg_vars[key] = v

            tk.Label(path_card, text=label, fg=C_TEXT, bg=C_PANEL,
                     font=("Segoe UI", 9, "bold"), width=18, anchor="w").grid(
                     row=i, column=0, sticky="w", padx=(0,8), pady=4)
            self._entry(path_card, v).grid(row=i, column=1, sticky="ew",
                                            padx=(0,8), ipady=3)
            self._btn(path_card, "Browse",
                      lambda _v=v, _l=label: browse_path(_v, f"Select {_l}"),
                      small=True).grid(row=i, column=2, padx=(0,8))
            tk.Label(path_card, text=hint, fg=C_MUTED, bg=C_PANEL,
                     font=("Segoe UI", 7), anchor="w").grid(
                     row=i, column=3, sticky="w")

        section("DRM Decrypt Tool")
        dec_row = tk.Frame(inner, bg=C_BG)
        dec_row.pack(fill="x", padx=16, pady=4)
        decrypt_card(dec_row, "⬡  Auto",           "Picks best available", "auto")
        decrypt_card(dec_row, "⚡ Inline (N_m3u8DL)","Keys passed during download", "n_m3u8dl")
        decrypt_card(dec_row, "🔓 mp4decrypt",      "Bento4 - fast, single-pass", "mp4decrypt")
        decrypt_card(dec_row, "📦 Shaka Packager",  "Per-track decrypt + re-mux", "shaka")
        self.root.after(10, _refresh_decrypt_cards)

        # Threads + Country
        section("Advanced")
        adv = tk.Frame(inner, bg=C_BG)
        adv.pack(fill="x", padx=16, pady=4)
        tk.Label(adv, text="Threads:", fg=C_TEXT, bg=C_BG,
                 font=("Segoe UI", 9)).pack(side="left")
        self._cfg_vars["threads"] = tk.StringVar(value=str(self.cfg.get("threads", 16)))
        self._entry(adv, self._cfg_vars["threads"], width=6).pack(side="left", padx=8, ipady=3)
        tk.Label(adv, text="Country:", fg=C_TEXT, bg=C_BG,
                 font=("Segoe UI", 9)).pack(side="left", padx=(16, 0))
        self._cfg_vars["country"] = tk.StringVar(value=self.cfg.get("country", "IN"))
        self._entry(adv, self._cfg_vars["country"], width=5).pack(side="left", padx=8, ipady=3)
        tk.Label(adv, text="(e.g. IN, US, UK)", fg=C_MUTED, bg=C_BG,
                 font=("Segoe UI", 8)).pack(side="left")

        # App config
        section("App Config")
        keys_card = tk.Frame(inner, bg=C_PANEL, padx=12, pady=8)
        keys_card.pack(fill="x", padx=16, pady=4)
        keys_card.columnconfigure(1, weight=1)

        key_fields = [
            ("App Version",  "app_version", "Zee5 app version string"),
            ("User Agent",   "user_agent",  "Browser UA sent with all requests"),
        ]
        for i, (label, key, hint) in enumerate(key_fields):
            v = tk.StringVar(value=self.cfg.get(key, ""))
            self._cfg_vars[key] = v
            tk.Label(keys_card, text=label, fg=C_TEXT, bg=C_PANEL,
                     font=("Segoe UI", 9, "bold"), width=18, anchor="w").grid(
                     row=i, column=0, sticky="w", padx=(0,8), pady=4)
            self._entry(keys_card, v).grid(row=i, column=1, sticky="ew", padx=(0,8), ipady=3)
            tk.Label(keys_card, text=hint, fg=C_MUTED, bg=C_PANEL,
                     font=("Segoe UI", 7), anchor="w").grid(row=i, column=2, sticky="w")

        # Save button
        btn_row = tk.Frame(inner, bg=C_BG)
        btn_row.pack(fill="x", padx=16, pady=16)
        self._btn(btn_row, "💾  Save Settings", self._save_settings, accent=True).pack(side="left")

    # EVENTS

    def _log(self, msg):
        self.log_box.insert("end", msg)
        self.log_box.see("end")

    def _toggle_log(self):
        if self.log_box.winfo_viewable():
            self.log_box.pack_forget()
        else:
            self.log_box.pack(fill="both", expand=True, padx=12, pady=(0,8))

    def _browse_outdir(self):
        d = filedialog.askdirectory(initialdir=self.var_outdir.get() or os.getcwd())
        if d: self.var_outdir.set(d)

    def _open_folder(self):
        d = self.var_outdir.get()
        if d and os.path.isdir(d):
            import subprocess as sp
            try: sp.Popen(f'explorer "{d}"')
            except: pass

    def _do_clear_token(self):
        self.token = None
        self.hdr_status.config(text="● Not logged in", fg=C_RED)
        self.lbl_sess_detail.config(text="✗  No token - use Login tab", fg=C_RED)
        self.lbl_login_status.config(text="", fg=C_MUTED)

    def _save_settings(self):
        global ZEE5_COUNTRY
        for k, v in self._cfg_vars.items():
            val = v.get().strip()
            if k == "threads":
                try: self.cfg[k] = int(val)
                except: pass
            else:
                self.cfg[k] = val
        _sync_constants(self.cfg)
        save_cfg(self.cfg)
        messagebox.showinfo("Settings", "Settings saved ✓")

    def _do_send_otp(self):
        mobile = self.var_mobile.get().strip()
        if not mobile:
            messagebox.showwarning("Mobile", "Enter your mobile number first"); return
        mobile = re.sub(r'^(\+91|91|0)', '', mobile).strip()

        self._switch_tab("Download")
        self._log(f"[LOGIN] Sending OTP to {mobile}...\n")
        self.lbl_login_status.config(text="Sending OTP...", fg=C_ORANGE)
        self._switch_tab("Login")
        def _bg():
            ok, method = zee5_send_otp(mobile, self.platform_token)
            if ok:
                self.root.after(0, lambda: [
                    self._log(f"[✓] OTP sent via {method}\n"),
                    self.lbl_login_status.config(text="OTP sent - enter it now", fg=C_ORANGE),
                ])
            else:
                self.root.after(0, lambda: [
                    self._log(f"[✗] OTP send failed: {method}\n"),
                    self.lbl_login_status.config(text=f"✗ {method}", fg=C_RED),
                ])
        threading.Thread(target=_bg, daemon=True).start()

    def _do_verify_otp(self):
        mobile = self.var_mobile.get().strip()
        mobile = re.sub(r'^(\+91|91|0)', '', mobile).strip()
        otp    = self.var_otp.get().strip()
        if not mobile or not otp:
            messagebox.showwarning("OTP", "Enter mobile + OTP"); return
        self.lbl_login_status.config(text="Verifying...", fg=C_ORANGE)
        self._log("[LOGIN] Verifying OTP...\n")
        def _bg():
            token_data = zee5_verify_otp(mobile, otp, self.platform_token)
            if token_data and token_data.get("access_token"):
                self.token = token_data["access_token"]
                path = save_token(token_data, self.cfg)
                sub  = token_data.get("subscription_status","")
                tok_len = len(self.token)
                tok_src = "RS256-JWT" if tok_len > 500 else "session-token"
                self.root.after(0, lambda: [
                    self._log(f"[✓] Logged in! Sub: {sub} | Token: {tok_src} (len={tok_len}) | Saved → {path}\n"),
                    self._set_login_state(True),
                    self.hdr_status.config(text="● Logged in", fg=C_GREEN),
                    self.lbl_sess_detail.config(
                        text=f"✓  Logged in  |  {mobile}", fg=C_GREEN),
                ])
            else:
                err = (token_data or {}).get("_error","unknown error")
                self.root.after(0, lambda: [
                    self._log(f"[✗] OTP verification failed: {err}\n"),
                    self.lbl_login_status.config(text=f"✗ {err}", fg=C_RED),
                ])
        threading.Thread(target=_bg, daemon=True).start()

    def _do_fetch(self):
        url = self.var_url.get().strip()
        if not url:
            messagebox.showwarning("URL", "Enter a Zee5 URL or Content ID"); return
        cid = extract_content_id(url)
        if not cid:
            messagebox.showerror("Content ID", "Could not extract content ID from URL"); return
        self._log(f"\n[FETCH] Content ID: {cid}\n")
        # Show "fetching" placeholder while we wait
        for w in self._q_frame.winfo_children(): w.destroy()
        tk.Label(self._q_frame, text="Fetching stream info…",
                 bg=C_PANEL, fg=C_MUTED, font=("Segoe UI", 9)).pack(anchor="w", pady=6)
        self._q_vars = []; self._audio_cb_vars = {}; self._sub_cb_vars = {}
        tok = self.token or ""
        if not tok:
            self._log("[!] Not logged in - trying with guest token\n")
            tok = zee5_guest_token(self.platform_token)
        def _bg():
            self.root.after(0, lambda: self._log("[...] Fetching playback URL...\n"))
            # Grab real title from content API (runs fast, no DRM needed)
            try:
                meta = fetch_content_details(cid, tok, self.platform_token)
                raw_title = (meta.get("title") or meta.get("name") or
                             meta.get("asset_title") or meta.get("show_title") or
                             meta.get("content_title") or meta.get("program_title") or "")
                if raw_title:
                    self.api_title = re.sub(r'[<>:"/\\|?*]', '', raw_title).strip()
                    self.root.after(0, lambda t=self.api_title: self._log(f"[✓] Title: {t}\n"))
            except:
                pass
            mpd, m3u8, lic, nl_tok, status = fetch_stream(cid, tok, self.platform_token,
                                                    _log_fn=lambda m: self.root.after(0, lambda msg=m: self._log(msg)))
            if not (mpd or m3u8):
                self.root.after(0, lambda: self._log(
                    f"[✗] No stream URL (HTTP {status}) - try logging in\n"))
                return
            self.mpd_url   = mpd
            self.m3u8_url  = m3u8
            self.lic_url   = lic
            self.nl_token  = nl_tok   # Nagra license token for Widevine headers
            stream = mpd or m3u8
            self.root.after(0, lambda: self._log(
                f"[✓] Stream: {stream[:80]}...\n"
                f"[✓] License: {lic[:60] if lic else 'none'}\n"))
            if mpd:
                self.root.after(0, lambda: self._log("[...] Parsing MPD qualities...\n"))
                quals, dur, atracks, stracks, pssh = parse_qualities(mpd)
                self.qualities    = quals
                self.audio_tracks = atracks
                self.sub_tracks   = stracks
                self.cfg["_duration"] = dur
                drm_status = "Widevine DRM detected ✓" if pssh else "No DRM"
                self.root.after(0, lambda: self._update_selectors(url, dur, drm_status, pssh))
            else:
                self.root.after(0, lambda: self._update_selectors_hls(url))
        threading.Thread(target=_bg, daemon=True).start()

    def _make_mini_cb(self, parent, var, label, color=None):
        """Tiny canvas-drawn checkbox for inline audio/sub track rows."""
        fg = color or C_TEXT
        f  = tk.Frame(parent, bg=C_PANEL, cursor="hand2")
        cv = tk.Canvas(f, width=14, height=14, bg=C_PANEL, highlightthickness=0)
        cv.pack(side="left", padx=(0, 3))
        lbl = tk.Label(f, text=label, bg=C_PANEL, fg=fg, font=("Segoe UI", 8))
        lbl.pack(side="left")
        def _draw(*_):
            cv.delete("all")
            on = var.get()
            cv.create_rectangle(1, 1, 13, 13,
                                fill=C_ACCENT if on else C_PANEL2,
                                outline=C_ACCENT if on else C_BORDER)
            if on:
                cv.create_line(2, 7,  5, 11, fill="#fff", width=1, capstyle="round")
                cv.create_line(5, 11, 12, 3, fill="#fff", width=1, capstyle="round")
        _draw()
        var.trace_add("write", _draw)
        def _toggle(e=None): var.set(not var.get())
        cv.bind("<Button-1>", _toggle)
        lbl.bind("<Button-1>", _toggle)
        f.bind("<Button-1>", _toggle)
        return f

    def _check_all(self, var_list, state):
        """Legacy helper - still used for audio_vars / sub_vars list of (code,lbl,BooleanVar)."""
        for _, _, bv in var_list:
            bv.set(state)

    def _check_all_q(self, state):
        """Toggle all quality CheckRow vars."""
        for bv in self._q_vars:
            bv.set(state)

    def _show_quals(self, quals, audio_tracks=None, sub_tracks=None):
        """
        Rebuild _q_frame in JioHotstar style:
          🔊 Audio  [inline mini-cbs]  [all]
          💬 Subs   [inline mini-cbs]  [all]
          --- separator ---
          Quality / Resolution / Bitrate / Est.Size  (column headers)
          CheckRow  CheckRow  CheckRow …
        """
        for w in self._q_frame.winfo_children():
            w.destroy()
        self._q_vars        = []
        self._audio_cb_vars = {}
        self._sub_cb_vars   = {}
        self.audio_vars     = []   # compat list
        self.sub_vars       = []   # compat list

        audio_tracks = audio_tracks or []
        sub_tracks   = sub_tracks   or []

        # Audio row
        if audio_tracks:
            ar = tk.Frame(self._q_frame, bg=C_PANEL)
            ar.pack(fill="x", pady=(4, 2))
            tk.Label(ar, text="🔊 Audio:", bg=C_PANEL, fg=C_MUTED,
                     font=("Segoe UI", 8, "bold"), width=8, anchor="w").pack(side="left")
            for i, t in enumerate(audio_tracks):
                v = tk.BooleanVar(value=True)
                self._audio_cb_vars[t["code"]] = v
                self.audio_vars.append((t["code"], t["label"], v))
                self._make_mini_cb(ar, v, t["label"]).pack(side="left", padx=(0, 8))
            def _tog_audio():
                new = not all(v.get() for v in self._audio_cb_vars.values())
                for v in self._audio_cb_vars.values(): v.set(new)
            btn_a = tk.Label(ar, text="[all]", bg=C_PANEL, fg=C_ACCENT,
                             font=("Segoe UI", 7), cursor="hand2")
            btn_a.pack(side="left", padx=(4, 0))
            btn_a.bind("<Button-1>", lambda e: _tog_audio())

        # Subtitles row
        if sub_tracks:
            sr = tk.Frame(self._q_frame, bg=C_PANEL)
            sr.pack(fill="x", pady=(0, 4))
            tk.Label(sr, text="💬 Subs:", bg=C_PANEL, fg=C_MUTED,
                     font=("Segoe UI", 8, "bold"), width=8, anchor="w").pack(side="left")
            for t in sub_tracks:
                v = tk.BooleanVar(value=False)
                self._sub_cb_vars[t["code"]] = v
                self.sub_vars.append((t["code"], t["label"], v))
                self._make_mini_cb(sr, v, t["label"]).pack(side="left", padx=(0, 8))
            def _tog_subs():
                new = not all(v.get() for v in self._sub_cb_vars.values())
                for v in self._sub_cb_vars.values(): v.set(new)
            btn_s = tk.Label(sr, text="[all]", bg=C_PANEL, fg=C_ACCENT,
                             font=("Segoe UI", 7), cursor="hand2")
            btn_s.pack(side="left", padx=(4, 0))
            btn_s.bind("<Button-1>", lambda e: _tog_subs())

        if audio_tracks or sub_tracks:
            tk.Frame(self._q_frame, bg=C_BORDER, height=1).pack(fill="x", pady=(4, 6))

        # Quality rows
        if quals:
            hdr = tk.Frame(self._q_frame, bg=C_PANEL)
            hdr.pack(fill="x")
            tk.Label(hdr, text="   ", bg=C_PANEL, width=3).pack(side="left")
            for txt, w in [("Quality", 7), ("Resolution", 12), ("Bitrate", 11), ("Est. Size", 10), ("Runtime", 9)]:
                tk.Label(hdr, text=txt, bg=C_PANEL, fg=C_BORDER,
                         font=("Segoe UI", 8), width=w, anchor="w").pack(side="left")
            tk.Frame(self._q_frame, bg=C_BORDER, height=1).pack(fill="x", pady=(3, 3))

            for i, q in enumerate(quals):
                var = tk.BooleanVar(value=(i == 0))
                self._q_vars.append(var)
                _dur_s = getattr(self, "_dur", 0) or 0
                _h, _rem = divmod(int(_dur_s), 3600)
                _m, _s   = divmod(_rem, 60)
                _runtime = f"{_h}:{_m:02d}:{_s:02d}" if _h else f"{_m}:{_s:02d}"
                row = CheckRow(self._q_frame, var,
                               height_p=q["height"], width_p=q.get("width", 0),
                               mbps=q["mbps"], est_size=q.get("est_size", "?"),
                               runtime=_runtime,
                               is_top=(i == 0))
                row.pack(fill="x", pady=1)
        else:
            # HLS / no qualities
            var = tk.BooleanVar(value=True)
            self._q_vars.append(var)
            row = tk.Frame(self._q_frame, bg=C_PANEL)
            row.pack(fill="x", pady=4)
            cv = tk.Canvas(row, width=18, height=18, bg=C_PANEL, highlightthickness=0)
            cv.pack(side="left", padx=(6, 8), pady=6)
            def _draw_fb(v=var, c=cv):
                c.delete("all")
                c.create_rectangle(1, 1, 17, 17,
                    fill=C_ACCENT if v.get() else C_PANEL2,
                    outline=C_ACCENT if v.get() else C_BORDER)
                if v.get():
                    c.create_line(3, 9,  7, 13, fill="#fff", width=2, capstyle="round")
                    c.create_line(7, 13, 15,  5, fill="#fff", width=2, capstyle="round")
            _draw_fb()
            var.trace_add("write", lambda *a: _draw_fb())
            tk.Label(row, text="Best available (auto)", bg=C_PANEL, fg=C_TEXT,
                     font=("Consolas", 10), anchor="w").pack(side="left")
            row.bind("<Button-1>", lambda e, v=var: v.set(not v.get()))

    def _refresh_filename(self, *_):
        """Regenerate the filename preview based on the FIRST checked quality checkbox."""
        url = self.var_url.get().strip()
        if not url or not self.qualities:
            return
        # Find the highest checked quality (first True in _q_vars, which map 1-to-1 with self.qualities)
        q = None
        for i, bv in enumerate(self._q_vars):
            if bv.get() and i < len(self.qualities):
                q = self.qualities[i]
                break
        if q is None:
            q = self.qualities[0]   # fallback: no checkbox ticked → use best
        # Only use CHECKED audio tracks for filename
        checked_audio_codes = [code for code, bv in self._audio_cb_vars.items() if bv.get()]
        if not checked_audio_codes:
            checked_audio_codes = [a["code"] for a in self.audio_tracks]  # fallback: all
        audio_kbps = max(
            (a["max_kbps"] for a in self.audio_tracks if a["code"] in checked_audio_codes),
            default=max((a["max_kbps"] for a in self.audio_tracks), default=0))
        fname = make_filename(url, q["height"],
                              audio_codes=checked_audio_codes, audio_kbps=audio_kbps,
                              est_size_str=q.get("est_size"),
                              api_title=self.api_title or None)
        self.var_fname.set(fname)

    def _update_selectors(self, url, dur, drm_status, pssh):
        self._dur = dur          # store for quality rows
        # Rebuild the dynamic track/quality panel
        self._show_quals(self.qualities, self.audio_tracks, self.sub_tracks)

        # Wire each quality checkbox to live-refresh the filename
        for bv in self._q_vars:
            bv.trace_add("write", self._refresh_filename)

        # Update DRM label
        color = C_GREEN if "detected" in drm_status else C_CYAN
        self.lbl_drm.config(text=f"DRM: {drm_status}", fg=color)

        # Set initial filename from the first checked quality (top = highest, pre-selected)
        self._refresh_filename()
        self._log(f"[✓] {len(self.qualities)} quality | {len(self.audio_tracks)} audio | {len(self.sub_tracks)} subs\n")

    def _update_selectors_hls(self, url):
        self._show_quals([], [], [])   # shows "Best available (auto)" fallback row
        self.lbl_drm.config(text="DRM: unknown (HLS only)", fg=C_ORANGE)
        self.var_fname.set(make_filename(url, 0, api_title=self.api_title or None))

    def _do_download(self):
        url     = self.var_url.get().strip()
        out_dir = self.var_outdir.get().strip()
        fname   = self.var_fname.get().strip()
        if not url:    messagebox.showwarning("URL", "Enter a Zee5 URL"); return
        stream_url = self.mpd_url or self.m3u8_url
        if not stream_url: messagebox.showwarning("Stream", "Fetch content first"); return
        if not fname:  messagebox.showwarning("Filename", "Set output filename"); return
        self.cancel_flag.clear()
        self.btn_dl.config(state="disabled")
        self.var_progress.set(0)
        self.lbl_pct.config(text="0%")
        self.lbl_status.config(text="Starting...", fg=C_ORANGE)
        # Read quality checkboxes (multi-select CheckRow)
        selected_qs = [(i, q) for i, (q, bv) in enumerate(
            zip(self.qualities if self.qualities else [None] * len(self._q_vars), self._q_vars)
        ) if bv.get()]
        if not selected_qs:
            messagebox.showwarning("Nothing selected", "Check at least one quality."); return

        # Read audio checkboxes
        checked_audio = [code for code, bv in self._audio_cb_vars.items() if bv.get()]
        if checked_audio and len(checked_audio) < len(self._audio_cb_vars):
            self.cfg["audio_lang"] = ",".join(checked_audio)
        else:
            self.cfg["audio_lang"] = "all"   # all selected or none set → grab all

        # Read subtitle checkboxes
        checked_subs = [code for code, bv in self._sub_cb_vars.items() if bv.get()]
        if not checked_subs:
            self.cfg["sub_lang"] = "NONE"
        elif len(checked_subs) == len(self._sub_cb_vars) and self._sub_cb_vars:
            self.cfg["sub_lang"] = "ALL"
        else:
            self.cfg["sub_lang"] = ",".join(checked_subs)
        out_name = re.sub(r'\.mkv$','',fname,flags=re.IGNORECASE)
        qlabels = ", ".join(q.get('label','?') for _,q in selected_qs if q) or "?"
        self._log(f"\n[DL] {len(selected_qs)} quality/qualities selected: {qlabels} | audio={self.cfg['audio_lang']} | subs={self.cfg['sub_lang']}\n")
        tok = self.token or ""
        cfg = dict(self.cfg)
        cfg["cdm_path"] = self._cfg_vars.get("cdm_path", tk.StringVar()).get().strip() or cfg.get("cdm_path","")

        # Elapsed timer state
        _t_start    = [time.time()]
        _phase_txt  = ["Starting..."]
        _timer_alive = [True]

        def _tick_timer():
            if not _timer_alive[0]: return
            elapsed = int(time.time() - _t_start[0])
            h, rem  = divmod(elapsed, 3600)
            m, s    = divmod(rem, 60)
            ts = f"{h:02d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"
            phase   = _phase_txt[0]
            avg_pct = (sum(_pct.values()) / len(_pct)) if _pct else 0.0
            # show pct only while downloading; merging/decrypting are near-instant
            pct_str = f" {avg_pct:.0f}%" if phase == "Downloading" and avg_pct < 100 else ""
            _phase_colors = {"Downloading": C_ORANGE, "Merging": C_CYAN, "Decrypting": C_GREEN}
            fg = _phase_colors.get(phase, C_ORANGE)
            self.lbl_status.config(text=f"{phase}{pct_str}  ⏱ {ts}", fg=fg)
            if _timer_alive[0]:
                self.root.after(1000, _tick_timer)

        self.root.after(1000, _tick_timer)

        def _bg():
            drm_keys      = []
            lic_url_final = self.lic_url
            if self.mpd_url:
                self.root.after(0, lambda: self._log("[DRM] Checking stream for DRM...\n"))
                mpd_text, pssh, lic_from_mpd = extract_pssh_from_mpd_url(
                    self.mpd_url, log_cb=lambda m: self.root.after(0, lambda _m=m: self._log(_m)))
                if lic_from_mpd and not lic_url_final:
                    lic_url_final = lic_from_mpd
                if pssh:
                    self.root.after(0, lambda: self._log("[DRM] Fetching Widevine keys...\n"))
                    drm_keys = get_widevine_keys(
                        pssh, tok, self.platform_token, self.mpd_url,
                        cdm_path=cfg.get("cdm_path",""),
                        log_cb=lambda m: self.root.after(0, lambda _m=m: self._log(_m)),
                        license_url=lic_url_final,
                        nl_token=getattr(self, "nl_token", ""))
                    if not drm_keys:
                        self.root.after(0, lambda: self._log("[!] DRM key fetch failed\n"))

            _t_start[0] = time.time()

            total   = len(selected_qs)
            results = {}   # q_idx → (ok, out_path, label)
            import threading as _threading

            # Per-quality progress tracking
            _pct   = {}   # q_idx → float pct
            _speed = {}   # q_idx → speed str

            def _update_progress_bar():
                """Average pct across all active downloads."""
                if not _pct: return
                avg = sum(_pct.values()) / len(_pct)
                self.root.after(0, lambda: self.var_progress.set(avg))
                self.root.after(0, lambda _a=avg: self.lbl_pct.config(text=f"{_a:.0f}%"))

            def _make_cbs(q_idx, qlabel):
                prefix = f"[{qlabel}] "
                def progress_cb(pct, spd):
                    _pct[q_idx] = pct
                    if spd: _speed[q_idx] = spd
                    _update_progress_bar()
                    # show combined speed
                    total_spd = " | ".join(f"{_speed[k]}" for k in sorted(_speed) if _speed.get(k))
                    if total_spd:
                        self.root.after(0, lambda _s=total_spd: self.lbl_speed.config(text=_s))
                def log_cb(m):
                    # prefix each log line with quality label for clarity
                    lines = m.split('\n')
                    tagged = '\n'.join((prefix + l if l.strip() else l) for l in lines)
                    self.root.after(0, lambda _t=tagged: self._log(_t))
                def phase_cb(ph):
                    _labels = {
                        "downloading": "Downloading",
                        "muxing":      "Merging",
                        "decrypting":  "Decrypting",
                    }
                    _phase_txt[0] = _labels.get(ph, ph.title())
                return progress_cb, log_cb, phase_cb

            # Worker per quality
            # Snapshot checked audio at download-start time (not all tracks)
            _checked_audio = [code for code, bv in self._audio_cb_vars.items() if bv.get()]
            if not _checked_audio:
                _checked_audio = [a["code"] for a in self.audio_tracks]
            _audio_kbps = max(
                (a["max_kbps"] for a in self.audio_tracks if a["code"] in _checked_audio),
                default=max((a["max_kbps"] for a in self.audio_tracks), default=0))

            def _worker(q_idx, quality):
                if quality is None:
                    quality = {"height": 0, "mpd_video_idx": None}
                qlabel = quality.get("label", "?")
                h      = quality.get("height", 0)
                audio_codes = _checked_audio
                audio_kbps  = _audio_kbps
                # Unique filename per quality — bakes height into name
                q_fname = make_filename(
                    url, h,
                    audio_codes=audio_codes, audio_kbps=audio_kbps,
                    est_size_str=quality.get("est_size"),
                    api_title=self.api_title or None)
                q_out_name = re.sub(r'\.mkv$', '', q_fname, flags=re.IGNORECASE)
                progress_cb, log_cb, phase_cb = _make_cbs(q_idx, qlabel)
                _pct[q_idx] = 0.0
                log_cb(f"\n[DL] Starting {qlabel} → {q_fname}\n")
                ok, out_path = run_download(
                    stream_url=stream_url, out_dir=out_dir, out_name=q_out_name,
                    quality=quality, cfg=cfg, progress_cb=progress_cb,
                    log_cb=log_cb, cancel_flag=self.cancel_flag,
                    drm_keys=drm_keys, phase_cb=phase_cb)
                results[q_idx] = (ok, out_path, qlabel)
                _pct[q_idx] = 100.0 if ok else 0.0
                if ok:
                    self.root.after(0, lambda _p=out_path: self._log(f"\n[✓] Saved: {_p}\n"))
                else:
                    self.root.after(0, lambda _l=qlabel: self._log(f"\n[✗] Failed: {_l}\n"))

            # Launch all workers simultaneously
            workers = []
            for q_idx, quality in selected_qs:
                t = _threading.Thread(target=_worker, args=(q_idx, quality), daemon=True)
                workers.append(t)
                t.start()

            self.root.after(0, lambda: self._log(
                f"[DL] ⚡ {total} parallel download(s) started simultaneously\n"))

            # Wait for all to finish
            for t in workers:
                t.join()

            def _done():
                _timer_alive[0] = False
                self.btn_dl.config(state="normal")
                elapsed = int(time.time() - _t_start[0])
                h2, rem = divmod(elapsed, 3600)
                m2, s2  = divmod(rem, 60)
                ts = f"{h2:02d}:{m2:02d}:{s2:02d}" if h2 else f"{m2:02d}:{s2:02d}"
                ok_count = sum(1 for r in results.values() if r[0])
                if ok_count == total:
                    self.lbl_status.config(text=f"✓ Done! {ok_count}/{total} ({ts})", fg=C_GREEN)
                    saved = "\n".join(r[1] for r in results.values() if r[0] and r[1])
                    messagebox.showinfo("Done", f"All {ok_count} download(s) complete!\n\n{saved}")
                elif ok_count > 0:
                    self.lbl_status.config(text=f"⚠ {ok_count}/{total} done ({ts})", fg=C_ORANGE)
                    failed = ", ".join(r[2] for r in results.values() if not r[0])
                    messagebox.showwarning("Partial", f"{ok_count}/{total} succeeded.\nFailed: {failed}")
                else:
                    self.lbl_status.config(text=f"✗ Failed ({ts})", fg=C_RED)
                    messagebox.showerror("Failed", "All downloads failed.")
            self.root.after(0, _done)
        threading.Thread(target=_bg, daemon=True).start()

    def _do_cancel(self):
        self.cancel_flag.set()
        self.lbl_status.config(text="Cancelling...", fg=C_ORANGE)



#  ENTRY POINT


if __name__ == "__main__":
    root = tk.Tk()
    app = Zee5DownloaderApp(root)
    root.mainloop()
