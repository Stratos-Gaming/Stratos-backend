from typing import Tuple, Optional
from django.conf import settings
from django.contrib.auth.models import User
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework import exceptions
from jose import jwt
import requests
from django.core.cache import cache
from userModule.models import StratosUser

JWKS_CACHE_KEY = "auth0_jwks"
JWKS_CACHE_SECONDS = 6 * 60 * 60  # 6h

def _get_jwks():
    jwks = cache.get(JWKS_CACHE_KEY)
    if not jwks:
        url = f"{settings.AUTH0_ISSUER}.well-known/jwks.json"
        jwks = requests.get(url, timeout=5).json()
        cache.set(JWKS_CACHE_KEY, jwks, JWKS_CACHE_SECONDS)
    return jwks

class Auth0JWTAuthentication(BaseAuthentication):
    """
    Bearer token -> verify with Auth0 JWKS (RS256), return (User, claims).
    Creates a local Django User + StratosUser on first request (no password),
    keeping your OneToOne profile model.
    """

    def authenticate(self, request) -> Optional[Tuple[User, dict]]:
        auth = get_authorization_header(request).split()
        if not auth or auth[0].lower() != b"bearer":
            return None

        token = auth[1].decode("utf-8")
        unverified = jwt.get_unverified_header(token)
        jwks = _get_jwks()

        rsa_key = next(
            (
                {
                    "kty": k["kty"],
                    "kid": k["kid"],
                    "use": k["use"],
                    "n": k["n"],
                    "e": k["e"],
                }
                for k in jwks["keys"]
                if k["kid"] == unverified["kid"]
            ),
            None,
        )
        if not rsa_key:
            raise exceptions.AuthenticationFailed("Invalid token header (kid)")

        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=settings.AUTH0_ALGORITHMS,
                audience=settings.AUTH0_AUDIENCE,
                issuer=settings.AUTH0_ISSUER,
            )
        except Exception as exc:
            raise exceptions.AuthenticationFailed(f"Token verification failed: {exc}")

        # JIT-sync local user
        sub = payload.get("sub")  # e.g., auth0|abc or google-oauth2|123
        email = payload.get("email", "")
        if not sub:
            raise exceptions.AuthenticationFailed("sub missing in token")

        user, created = User.objects.get_or_create(
            username=sub,
            defaults={"email": email or "", "is_active": True},
        )
        if created or not hasattr(user, "stratos_user"):
            # Keep your profile table populated
            StratosUser.objects.get_or_create(user=user)

        # Optional: refresh email on every request
        if email and user.email != email:
            user.email = email
            user.save(update_fields=["email"])

        # Attach claims for scope checks
        request.auth = payload
        return user, payload
