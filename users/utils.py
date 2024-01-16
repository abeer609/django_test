import pyotp
from django.core.mail import send_mail, BadHeaderError
from django.conf import settings
from base64 import b32encode


class OTPServices:
    @staticmethod
    def generate_otp(email: str) -> str:
        secret = b32encode(email.encode()).decode()
        totp = pyotp.TOTP(secret, interval=settings.OTP_LIFESPAN)
        return totp.now()

    @staticmethod
    def validate_otp(email, otp):
        secret = b32encode(email.encode()).decode()
        totp = pyotp.TOTP(secret, interval=settings.OTP_LIFESPAN)
        return totp.verify(otp)

    @staticmethod
    def send_otp(email, otp):
        try:
            send_mail(
                "Login with the otp",
                f"your otp is {otp}\nvalid for {settings.OTP_LIFESPAN} seconds",
                "sifat@sifat.com",
                [email],
            )
        except BadHeaderError:
            pass
