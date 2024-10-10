from django.urls import path
from . import views
from .views import PasswordResetRequestView, SignUpView, OTPVerificationView, LoginView, RequestResetPasswordView, ResetPasswordConfirmView, RequestNewPasswordResetView, SignOutView, RefreshTokenView

urlpatterns = [
    #path('',views.HelloAuthView.as_view(),name='hello_auth'),
    #path('signUp/',views.UserCreateView.as_view(),name='signUp'),
    path('signUp/', SignUpView.as_view(), name='sign_up'),
    path('verify-email/', OTPVerificationView.as_view(), name='verify_otp'),
    path('request-new-verification-email/',PasswordResetRequestView.as_view(),name='new otp'),
    path('signin/',LoginView.as_view(),name='login'),
    path('request-password-reset/',RequestResetPasswordView.as_view(),name='request reset password'),
    path('password-reset/',ResetPasswordConfirmView.as_view(),name='reset password'),
    path('request-new-password-reset/',RequestNewPasswordResetView.as_view(),name='request reset password'),
    path('signout/',SignOutView.as_view(),name='sign out'),
    path('refresh-token/',RefreshTokenView.as_view(),name='sign out'),

]