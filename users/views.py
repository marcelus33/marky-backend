import random
import string
from datetime import timedelta

from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from django.utils.translation import gettext_lazy as _
from drf_spectacular.utils import extend_schema
from post_office import mail
from rest_framework import generics
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken, UntypedToken
from rest_framework_simplejwt.views import (
    TokenRefreshView, )

from marky_backend import settings
from users.serializers import UserRegisterSerializer, UserLoginSerializer, VerifyEmailSerializer, \
    PasswordRecoverySerializer, PasswordChangeSerializer, ResendVerificationSerializer, UserSerializer

User = get_user_model()


@extend_schema(tags=['Auth'])
class RegisterView(generics.CreateAPIView):
    serializer_class = UserRegisterSerializer
    permission_classes = [AllowAny]

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

                refresh = RefreshToken.for_user(user)
                access_token = refresh.access_token
                access_token.set_exp(lifetime=timedelta(minutes=15))
                access_token['verification_code'] = verification_code
                access_token_str = str(access_token)
                # TODO change hardcoded link
                verification_link = f"http://localhost:3000/verify-email/{access_token_str}"

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
            return Response(
                {"error": f"{str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        return Response(
            {"message": "Cuenta creada con éxito. Se ha enviado una verificación a su email.",
             "user": UserSerializer(user).data,
             "verification_link": access_token_str,
             },
            status=status.HTTP_201_CREATED
        )


@extend_schema(tags=['Auth'])
class LoginView(generics.GenericAPIView):
    serializer_class = UserLoginSerializer
    permission_classes = [AllowAny]

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
    pass


@extend_schema(tags=['Auth'])
class VerifyEmailView(generics.GenericAPIView):
    serializer_class = VerifyEmailSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        token = serializer.validated_data['token']
        verification_code = serializer.validated_data['verification_code']

        try:
            access_token = UntypedToken(token)

            token_code = access_token['verification_code']
            if verification_code == token_code:
                user_id = access_token['user_id']
                user = User.objects.get(id=user_id)
                user.is_verified = True
                user.save()

                return Response({"message": "Correo verificado con éxito."}, status=status.HTTP_200_OK)
            else:
                return Response({"message": "Código inválido."}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(tags=['Auth'])
class ResendVerificationView(generics.GenericAPIView):
    permission_classes = [AllowAny]
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

        # Generar un nuevo código de verificación
        verification_code = ''.join(random.choices(string.digits, k=6))

        # Generar un nuevo token con 15 minutos de vigencia
        refresh = RefreshToken.for_user(user)
        access_token = refresh.access_token
        access_token.set_exp(lifetime=timedelta(minutes=15))
        access_token['verification_code'] = verification_code

        # TODO: change hardcoded link
        verification_link = f"http://localhost:3000/verify-email/{str(access_token)}"

        mail.send(
            user.email,
            settings.DEFAULT_FROM_EMAIL,
            template='verify_email',
            context={'verification_link': verification_link, 'verification_code': verification_code},
            # priority='now',
        )

        return Response(
            {"message": "Se ha enviado un nuevo correo de verificación."},
            status=status.HTTP_200_OK
        )


@extend_schema(tags=['Auth'])
class PasswordRecoveryView(generics.GenericAPIView):
    serializer_class = PasswordRecoverySerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
        return Response({"message": "Se ha enviado un correo de recuperación."}, status=status.HTTP_200_OK)


@extend_schema(tags=['Auth'])
class PasswordChangeView(generics.GenericAPIView):
    serializer_class = PasswordChangeSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"message": "La contraseña fue cambiada con éxito."}, status=status.HTTP_200_OK)
