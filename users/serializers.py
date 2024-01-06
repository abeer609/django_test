from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .otp_serializers import LoginTokenObtainPairSerializer
from .models import File
from django.contrib.auth import get_user_model
from .mixins import UserCreateMixin

User = get_user_model()


class SimpleUserSerializer(serializers.ModelSerializer):
    date_joined = serializers.DateTimeField(read_only=True)

    class Meta:
        model = User
        fields = [
            "id",
            "username",
            "first_name",
            "last_name",
            "email",
            "is_admin",
            "date_joined",
        ]


class RegisterAdminSerializer(serializers.Serializer):
    email = serializers.EmailField(
        validators=[
            UniqueValidator(
                queryset=User.objects.all(), message="this email already exists!"
            )
        ]
    )


class FileSerializer(serializers.ModelSerializer):
    owner: SimpleUserSerializer = SimpleUserSerializer(read_only=True)

    class Meta:
        model = File
        fields = ["id", "file", "owner", "created_at"]

    def create(self, validated_data):
        user_id = self.context.get("user_id")
        return File.objects.create(**validated_data, owner_id=user_id)


class CreateUserSerializer(UserCreateMixin, serializers.ModelSerializer):
    username = serializers.CharField(
        required=False,
        validators=[
            UniqueValidator(
                queryset=User.objects.all(), message="username already exists"
            )
        ],
        help_text="This field is optional. If not provided random username will be generated",
    )

    class Meta:
        model = User
        fields = ["id", "username", "password"]
        extra_kwargs = {"password": {"write_only": True}}

    def validate(self, attrs):
        user = User(**attrs)
        password = attrs.get("password")
        try:
            validate_password(password, user)
        except ValidationError as e:
            serializer_error = serializers.as_serializer_error(e)
            raise serializers.ValidationError(
                {"password": serializer_error["non_field_errors"]}
            )
        return attrs


class CustomLoginTokenObtainPairSerializer(LoginTokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token["email"] = user.email
        return token
