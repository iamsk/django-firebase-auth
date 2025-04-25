"""
Handle the authentication of the user.
Using google authentication (with application)
Using firebase authentication (with web)
"""
import datetime

import firebase_admin.auth
from django.contrib.auth.models import User
from django.utils import timezone
from google.auth import jwt

from abstract_auth.abstract_auth import AbstractAuthentication, InvalidAuthToken
from django_firebase_auth.models import UserFirebaseProfile


class FirebaseAuthentication(AbstractAuthentication):
    token_post_index_name = "firebase_auth_token"

    def authenticate(self, request):
        auth_header = request.META.get("HTTP_AUTHORIZATION") or ""
        id_token = request.data.get(self.token_post_index_name) or auth_header.split(" ").pop()
        if not id_token:
            # return AnonymousUser, None
            return None
        try:
            decoded_token = jwt.decode(id_token, verify=False)
        except ValueError as e:
            raise InvalidAuthToken() from e
        is_expired = datetime.datetime.fromtimestamp(decoded_token["exp"]) < datetime.datetime.now()
        if is_expired:
            raise InvalidAuthToken("Authorization token is expired")
        try:
            authenticated_user = self._verify_token(id_token)
        except ValueError as e:
            raise InvalidAuthToken() from e
        username = f"firebase_{authenticated_user['uid']}"
        defaults = {"username": username}
        user: User = User.objects.get_or_create(
            email=f"{authenticated_user['uid']}@askpic.com",
            defaults=defaults,
        )[0]
        user.last_login = timezone.now()
        user.save(update_fields=["last_login"])
        return user, None

    def _get_or_create_profile(self, user, uid, avatar: str):
        return UserFirebaseProfile.objects.update_or_create(
            user=user,
            defaults={
                "uid": uid,
                "photo_url": avatar,
            },
        )[0]

    def _verify_token(self, id_token):
        return firebase_admin.auth.verify_id_token(
            id_token, check_revoked=True, clock_skew_seconds=5
        )
