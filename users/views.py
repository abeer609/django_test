from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet
from rest_framework_simplejwt.authentication import JWTAuthentication
from .config import api_settings
from django.utils.module_loading import import_string


from .otp_serializers import (
    AuthOTPVerifySerializer,
    LoginSerializer,
    ResendOTPSerializer,
)
from .models import File, User
from .utils import OTPServices

from .permissions import IsAdminUser
from .serializers import (
    CreateUserSerializer,
    FileSerializer,
    RegisterAdminSerializer,
    SimpleUserSerializer,
)
from rest_framework_simplejwt.views import TokenObtainPairView


class ChildUserLogin(TokenObtainPairView):
    """
    User login. Takes username and password and return JWT token
    """

    _serializer_class = "rest_framework_simplejwt.serializers.TokenObtainPairSerializer"


# TODO: craete separate app as well as eager the load user
class FileViewSet(ModelViewSet):
    serializer_class = FileSerializer
    permission_classes = [IsAuthenticated]
    queryset = File.objects.all()
    authentication_classes = [JWTAuthentication]

    def get_queryset(self):
        user: User = self.request.user
        if not user.is_admin:
            return File.objects.filter(owner=user).select_related("owner")
        return File.objects.all()

    def get_serializer_context(self) -> dict:
        return {"user_id": self.request.user.id, "request": self.request}


class MyPagination(PageNumberPagination):
    page_size = 50


class UserViewSet(ModelViewSet):
    queryset = User.objects.all()
    pagination_class = MyPagination
    permission_classes = [IsAdminUser]
    authentication_classes = [JWTAuthentication]

    def get_serializer_class(self):
        if self.action == "create":
            return CreateUserSerializer
        return SimpleUserSerializer


class LoginView(GenericAPIView, OTPServices):
    """
    Takes an email and send OTP. User can't login into their account without activating their account. To activate account use /auth/admin/activate/ endpoint
    """

    serializer_class = LoginSerializer

    def post(self, request, format=None):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = User.objects.get(email=serializer.validated_data.get("email"))
        otp = self.generate_otp()
        user.otp = otp
        user.save()
        self.send_otp(user.email, user.otp)
        return Response({"message": "an OTP has sent to your your email"})


class VerifyOTPBase(GenericAPIView):
    permission_classes = ()
    authentication_classes = ()

    def get_serializer_class(self):
        try:
            # getting token obtain serializer from settings, provided by rest_framework_simplejwt
            return import_string(api_settings.TOKEN_OBTAIN_SERIALIZER)
        except ImportError:
            msg = "Could not import serializer '%s'" % self._serializer_class
            raise ImportError(msg)


class VerifyOTPView(VerifyOTPBase):
    def post(self, request, format=None):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        response = {}
        response["access"] = serializer.validated_data.get("access")
        response["refresh"] = serializer.validated_data.get("refresh")
        return Response(response, status=status.HTTP_200_OK)


class RegisterAdmin(GenericAPIView, OTPServices):
    serializer_class = None
    user_model = None

    # def generate_username(self):
    #     return f"admin_{nanoid.generate(size=12)}"

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # creating admin user. username is set to given email and password is set to unusable password.
        # https://docs.djangoproject.com/en/5.0/ref/contrib/auth/#django.contrib.auth.models.UserManager

        user = self.user_model.objects.create_user(
            **serializer.validated_data,
            username=serializer.validated_data.get("email"),
            is_admin=True,
            otp=self.generate_otp(),
        )

        self.send_otp(user.email, user.otp)
        return Response({"message": "an OTP has sent to your your email"})


class AdminRegistrationView(RegisterAdmin):
    serializer_class = RegisterAdminSerializer
    user_model = User


class VerifyAdminRegistrationOTPView(VerifyOTPBase):
    """
    Activate the Admin user by OTP verification. After OTP verification pair of JWT token will be returned.
    """

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = User.objects.get(email=serializer.validated_data.get("email"))
        if not user.is_active:
            user.is_active = True
            user.save()
        response = {}
        response["access"] = serializer.validated_data.get("access")
        response["refresh"] = serializer.validated_data.get("refresh")

        return Response(response, status=status.HTTP_200_OK)


class ActivateAdminView(GenericAPIView):
    """
    Takes email and OTP code and activate admin account.
    """

    serializer_class = AuthOTPVerifySerializer
    permission_classes = ()
    authentication_classes = ()

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data.get("email")
        print(email)
        user = User.objects.get(email=email)
        if not user.is_active:
            user.is_active = True
            user.save()

        return Response(
            {"detail": "your account has successfully activated"},
            status=status.HTTP_200_OK,
        )


class ResendOTPView(GenericAPIView, OTPServices):
    serializer_class = ResendOTPSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = User.objects.get(email=serializer.validated_data["email"])
        otp = self.generate_otp()
        user.otp = otp
        user.save()
        self.send_otp(user.email, user.otp)
        return Response({"message": "an OTP has sent to your your email"})
