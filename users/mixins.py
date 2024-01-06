from django.db import IntegrityError, transaction
from django.contrib.auth import get_user_model
from namegen.namegen import generate_username


User = get_user_model()


class UserCreateMixin:
    def create(self, validated_data):
        try:
            user = self.perform_create(validated_data)
        except IntegrityError:
            self.fail("cannot_create_user")

        return user

    def perform_create(self, validated_data):
        with transaction.atomic():
            if validated_data.get("username"):
                user = User.objects.create_user(
                    **validated_data,
                    username=validated_data.get("username"),
                    is_active=True
                )
            else:
                user = User.objects.create_user(
                    **validated_data, is_active=True, username=generate_username()
                )
        return user
