from django.urls import path
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView
from users.views import (
    ChildUserLogin,
    FileViewSet,
    UserViewSet,
    LoginView,
    VerifyAdminRegistrationOTPView,
    VerifyOTPView,
    AdminRegistrationView,
    ActivateAdminView,
    ResendOTPView,
)


router = DefaultRouter()

router.register("files", FileViewSet, "file")
router.register("users", UserViewSet, "my-users")


urlpatterns = [
    path("auth/admin/register/", AdminRegistrationView.as_view()),
    path("auth/admin/verify/", VerifyAdminRegistrationOTPView.as_view()),
    path("auth/admin/activate/", ActivateAdminView.as_view()),
    path("auth/admin/login/", LoginView.as_view()),
    path("auth/otp/resend/", ResendOTPView.as_view()),
    path("auth/otp/verify/", VerifyOTPView.as_view()),
    path("auth/users/login/", ChildUserLogin.as_view()),
    path("auth/token/refresh/", TokenRefreshView.as_view()),
] + router.urls
