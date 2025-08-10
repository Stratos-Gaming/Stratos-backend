from typing import Optional, Tuple, List
from django.conf import settings
from django.contrib.auth.models import User
from django.core.cache import cache
from jose import jwt
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework import exceptions
import requests

JWKS_CACHE_SECONDS = 6 * 60 * 60  # 6h

# ---- Helpers ---------------------------------------------------------------

def _normalize_issuer(iss: str) -> str:
    return iss if iss.endswith("/") else iss + "/"

def _jwks_cache_key(issuer: str) -> str:
    return f"auth0:jwks:{_normalize_issuer(issuer)}"

def _get_jwks(issuer: str):
    issuer = _normalize_issuer(issuer)
    key = _jwks_cache_key(issuer)
    jwks = cache.get(key)
    if not jwks:
        resp = requests.get(f"{issuer}.well-known/jwks.json", timeout=5)
        resp.raise_for_status()
        jwks = resp.json()
        cache.set(key, jwks, 6 * 60 * 60)  # 6h
    return jwks, issuer

def _refresh_jwks(issuer: str):
    issuer = _normalize_issuer(issuer)
    key = _jwks_cache_key(issuer)
    resp = requests.get(f"{issuer}.well-known/jwks.json", timeout=5)
    resp.raise_for_status()
    jwks = resp.json()
    cache.set(key, jwks, 6 * 60 * 60)
    return jwks, issuer

def _accepted_audiences_from_settings() -> List[str]:
    raw = (getattr(settings, "AUTH0_AUDIENCE", "") or "").strip()
    if not raw:
        return []
    accepted: List[str] = []
    for item in [s.strip() for s in raw.split(",") if s.strip()]:
        accepted.append(item)
        accepted.append(item.rstrip("/"))
        accepted.append(item.rstrip("/") + "/")
    # de-dup while preserving order
    seen = set()
    out = []
    for a in accepted:
        if a not in seen:
            out.append(a); seen.add(a)
    return out
class Auth0JWTAuthentication(BaseAuthentication):
    """
    Bearer token -> verify with Auth0 JWKS (RS256), return (User, claims).
    Creates/updates a local Django User + StratosUser on first valid request.
    """

    def authenticate(self, request) -> Optional[Tuple[User, dict]]:
        auth = get_authorization_header(request).split()
        if not auth or auth[0].lower() != b"bearer":
            return None

        token = auth[1].decode("utf-8")
        try:
            unverified_header = jwt.get_unverified_header(token)
            unverified_claims = jwt.get_unverified_claims(token)
        except Exception as exc:
            raise exceptions.AuthenticationFailed(f"Malformed token: {exc}")

        # Pick issuer: prefer token's iss, fallback to settings.AUTH0_ISSUER
        token_iss = unverified_claims.get("iss")
        issuer = _normalize_issuer(token_iss or getattr(settings, "AUTH0_ISSUER", "")) or None
        if not issuer:
            raise exceptions.AuthenticationFailed("Issuer not configured")

        jwks, issuer = _get_jwks(issuer)

        def select_key(keys):
            return next(
                (
                    {"kty": k.get("kty"), "kid": k.get("kid"), "use": k.get("use"), "n": k.get("n"), "e": k.get("e")}
                    for k in keys.get("keys", [])
                    if k.get("kid") == unverified_header.get("kid")
                ),
                None,
            )

        rsa_key = select_key(jwks)
        if not rsa_key:
            jwks, issuer = _refresh_jwks(issuer)
            rsa_key = select_key(jwks)
            if not rsa_key:
                raise exceptions.AuthenticationFailed("JWKS key not found (kid mismatch)")

        # Decode with issuer enforced; we'll validate audience manually to allow multiple
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=getattr(settings, "AUTH0_ALGORITHMS", ["RS256"]),
                options={"verify_aud": False},
                issuer=issuer,
            )
        except Exception as exc:
            raise exceptions.AuthenticationFailed(f"Token verification failed: {exc}")

        # Audience check (support list or string in token; allow multiple settings via comma)
        accepted = _accepted_audiences_from_settings()
        token_aud = payload.get("aud")
        if accepted:
            if isinstance(token_aud, str):
                if token_aud not in accepted:
                    raise exceptions.AuthenticationFailed("Invalid audience")
            elif isinstance(token_aud, (list, tuple)):
                if not set(accepted).intersection(token_aud):
                    raise exceptions.AuthenticationFailed("Invalid audience")
            else:
                raise exceptions.AuthenticationFailed("Audience missing")

        # Required claim
        sub = payload.get("sub")
        if not sub:
            raise exceptions.AuthenticationFailed("sub missing in token")

        # Namespaced claims (optional)
        ns = getattr(settings, "AUTH0_NS", None)
        def c(name, std=None):
            if ns:
                val = payload.get(f"{ns}/{name}")
                if val is not None:
                    return val
            return payload.get(std) if std else None

        email          = c("email", "email") or ""
        email_verified = bool(c("email_verified", "email_verified"))
        name           = c("name", "name") or ""
        given          = c("given_name", "given_name") or ""
        family         = c("family_name", "family_name") or ""
        picture        = c("picture", "picture") or ""

        # JIT create/update Django user
        user, created = User.objects.get_or_create(
            username=sub,
            defaults={"email": email, "first_name": given, "last_name": family, "is_active": True},
        )
        update_fields = []
        if email and user.email != email:
            user.email = email; update_fields.append("email")
        if given and user.first_name != given:
            user.first_name = given; update_fields.append("first_name")
        if family and user.last_name != family:
            user.last_name = family; update_fields.append("last_name")
        if update_fields:
            user.save(update_fields=update_fields)

        # Link / update your profile model
        from userModule.models import StratosUser  # adjust import
        su, _ = StratosUser.objects.get_or_create(user=user)

        changed = False
        # keep a stable 1↔1 link if you added this field (recommended)
        if hasattr(su, "auth0_sub") and getattr(su, "auth0_sub") != sub:
            su.auth0_sub = sub; changed = True
        if hasattr(su, "isEmailVerified") and su.isEmailVerified != email_verified:
            su.isEmailVerified = email_verified; changed = True
        if hasattr(su, "auth0_picture_url") and picture and su.auth0_picture_url != picture:
            su.auth0_picture_url = picture; changed = True

        # Only touch optional social ids if those fields exist
        if "google-oauth2|" in sub and hasattr(su, "google_id"):
            google_id = sub.split("|", 1)[1]
            if su.google_id != google_id:
                su.google_id = google_id; changed = True

        if "discord" in sub and hasattr(su, "discord_id"):
            parts = sub.split("|")
            discord_id = parts[-1] if parts else None
            if discord_id and su.discord_id != discord_id:
                su.discord_id = discord_id; changed = True

        if changed:
            su.save()

        # expose claims for permission checks
        request.auth = payload
        return user, payload
