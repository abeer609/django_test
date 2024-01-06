import pyotp
from django.core.mail import send_mail, BadHeaderError
from django.conf import settings


class OTPServices:
    def generate_otp(self):
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret, interval=60)
        return totp.now()

    def send_otp(self, email, otp):
        try:
            send_mail(
                "Login with the otp",
                f"your otp is {otp}\nvalid until {settings.OTP_LIFESPAN} seconds",
                "sifat@sifat.com",
                [email],
            )
        except BadHeaderError:
            pass
