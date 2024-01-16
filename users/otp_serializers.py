from django.contrib.auth.models import update_last_login
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken
from users.models import User
from .utils import OTPServices


class AuthEmailSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, email):
        try:
            self.user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("Email doesn't exist")
        return email


class AuthOTPSerializer(AuthEmailSerializer):
    otp = serializers.CharField(write_only=True)

    def validate(self, attrs):
        valid = OTPServices.validate_otp(**attrs)

        if not valid:
            raise AuthenticationFailed("OTP verification failed")
        return attrs
        # try:
        #     user = User.objects.get(**attrs)
        # except User.DoesNotExist:
        #     raise AuthenticationFailed("OTP verification failed")
        # now = datetime.datetime.utcnow().replace(tzinfo=utc)
        # will_expire = user.otp_created + datetime.timedelta(
        #     seconds=settings.OTP_LIFESPAN
        # )
        # expired = will_expire <= now
        # if expired:
        #     raise AuthenticationFailed("OTP has expired")


class TokenObtainSerializer(AuthOTPSerializer):
    @classmethod
    def get_token(cls, user):
        return cls.token_class.for_user(user)


# class RegisterTokenObtainPairSerializer(TokenObtainSerializer):
#     token_class = RefreshToken

#     def validate(self, attrs):
#         super().validate(attrs)
#         return attrs


class LoginTokenObtainPairSerializer(TokenObtainSerializer):
    token_class = RefreshToken

    def validate(self, attrs):
        super().validate(attrs)
        data = {}
        refresh = self.get_token(self.user)
        data["email"] = attrs.get("email")
        data["refresh"] = str(refresh)
        data["access"] = str(refresh.access_token)

        if api_settings.UPDATE_LAST_LOGIN:
            update_last_login(None, self.user)
        return data


class ResendOTPSerializer(AuthEmailSerializer):
    pass


class LoginSerializer(AuthEmailSerializer):
    default_error_messages = {
        "no_active_account": "no active account found with this email"
    }

    def validate(self, attrs):
        if not api_settings.USER_AUTHENTICATION_RULE(self.user):
            raise AuthenticationFailed(
                self.error_messages["no_active_account"],
                "no_active_account",
            )
        return attrs
