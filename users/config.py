from rest_framework_simplejwt.settings import (
    USER_SETTINGS,
    IMPORT_STRINGS,
    DEFAULTS,
    APISettings,
)

DEFAULTS[
    "TOKEN_OBTAIN_SERIALIZER"
] = "users.otp_serializers.LoginTokenObtainPairSerializer"

api_settings = APISettings(USER_SETTINGS, DEFAULTS, IMPORT_STRINGS)
