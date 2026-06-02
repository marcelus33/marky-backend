import logging
import random
import string
from datetime import timedelta

from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from drf_spectacular.utils import extend_schema
from post_office import mail
from rest_framework import generics
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import (
    TokenRefreshView, )

from marky_backend import settings
from users.serializers import UserRegisterSerializer, UserLoginSerializer, VerifyEmailSerializer, \
    PasswordRecoverySerializer, PasswordChangeSerializer, ResendVerificationSerializer, UserSerializer

User = get_user_model()
logger = logging.getLogger(__name__)


@extend_schema(tags=['Auth'])
class RegisterView(generics.CreateAPIView):
    serializer_class = UserRegisterSerializer
    permission_classes = [AllowAny]
    throttle_scope = 'auth'

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            with transaction.atomic():
                user = serializer.save()

                business_group = Group.objects.filter(name='business').first()
                if business_group:
                    business_group.user_set.add(user)

                verification_code = ''.join(random.choices(string.digits, k=6))
                user.verification_code = verification_code
                user.verification_code_expires_at = timezone.now() + timedelta(minutes=15)
                user.save(update_fields=['verification_code', 'verification_code_expires_at'])

                verification_link = f"{settings.FRONTEND_URL}/verify-email/"
                mail.send(
                    user.email,
                    settings.DEFAULT_FROM_EMAIL,
                    template='verify_email',
                    context={
                        'verification_link': verification_link,
                        'verification_code': verification_code
                    },
                )
        except Exception as e:
            logger.exception("Error during user registration")
            return Response(
                {"error": "Ha ocurrido un error inesperado durante el registro."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        return Response(
            {"message": "Cuenta creada con éxito. Se ha enviado una verificación a su email.",
             "user": UserSerializer(user).data,
             },
            status=status.HTTP_201_CREATED
        )


@extend_schema(tags=['Auth'])
class LoginView(generics.GenericAPIView):
    serializer_class = UserLoginSerializer
    permission_classes = [AllowAny]
    throttle_scope = 'auth'

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        user = authenticate(username=username, password=password)

        if user is None:
            raise AuthenticationFailed(_("Invalid credentials"))

        if not user.is_verified:
            raise AuthenticationFailed(_("User not verified"))

        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user': UserSerializer(user).data
        })


@extend_schema(tags=['Auth'])
class CustomTokenRefreshView(TokenRefreshView):
    permission_classes = [AllowAny]


@extend_schema(tags=['Auth'])
class VerifyEmailView(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = VerifyEmailSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        verification_code = serializer.validated_data['verification_code']

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"message": "Código inválido."}, status=status.HTTP_400_BAD_REQUEST)

        if user.is_verified:
            return Response({"detail": "Este usuario ya se encuentra verificado."}, status=status.HTTP_400_BAD_REQUEST)

        now = timezone.now()
        if (user.verification_code != verification_code
                or user.verification_code_expires_at is None
                or user.verification_code_expires_at < now):
            return Response({"message": "Código inválido o expirado."}, status=status.HTTP_400_BAD_REQUEST)

        user.is_verified = True
        user.verification_code = None
        user.verification_code_expires_at = None
        user.save(update_fields=['is_verified', 'verification_code', 'verification_code_expires_at'])

        return Response({"message": "Correo verificado con éxito."}, status=status.HTTP_200_OK)


@extend_schema(tags=['Auth'])
class ResendVerificationView(generics.GenericAPIView):
    permission_classes = [AllowAny]
    throttle_scope = 'resend'
    serializer_class = ResendVerificationSerializer

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]

        try:
            user = User.objects.get(email=email)
        except ObjectDoesNotExist:
            return Response(
                {"message": "Se ha enviado un nuevo correo de verificación."},
                status=status.HTTP_200_OK
            )

        if user.is_verified:
            return Response(
                {"detail": "Este usuario ya se encuentra verificado."},
                status=status.HTTP_400_BAD_REQUEST
            )

        verification_code = ''.join(random.choices(string.digits, k=6))
        user.verification_code = verification_code
        user.verification_code_expires_at = timezone.now() + timedelta(minutes=15)
        user.save(update_fields=['verification_code', 'verification_code_expires_at'])

        verification_link = f"{settings.FRONTEND_URL}/verify-email/"
        mail.send(
            user.email,
            settings.DEFAULT_FROM_EMAIL,
            template='verify_email',
            context={'verification_link': verification_link, 'verification_code': verification_code},
        )

        return Response(
            {"message": "Se ha enviado un nuevo correo de verificación."},
            status=status.HTTP_200_OK
        )


@extend_schema(tags=['Auth'])
class PasswordRecoveryView(generics.GenericAPIView):
    permission_classes = [AllowAny]
    throttle_scope = 'recovery'
    serializer_class = PasswordRecoverySerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
        return Response({"message": "Se ha enviado un correo de recuperación."}, status=status.HTTP_200_OK)


@extend_schema(tags=['Auth'])
class PasswordChangeView(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = PasswordChangeSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"message": "La contraseña fue cambiada con éxito."}, status=status.HTTP_200_OK)
