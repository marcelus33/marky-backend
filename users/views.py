import random
import string
from datetime import timedelta

from django.contrib.auth import authenticate, get_user_model
from django.db import transaction
from marky_backend import settings
from post_office import mail
from rest_framework import generics
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken, UntypedToken
from users.serializers import UserRegisterSerializer, UserLoginSerializer, VerifyEmailSerializer, \
    PasswordRecoverySerializer, PasswordChangeSerializer

User = get_user_model()


class RegisterView(generics.CreateAPIView):
    serializer_class = UserRegisterSerializer
    permission_classes = [AllowAny]

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        # Generate a 6-digit verification code
        verification_code = ''.join(random.choices(string.digits, k=6))

        # Generate a token with an expiration time of 15 minutes
        refresh = RefreshToken.for_user(user)
        access_token = refresh.access_token
        access_token.set_exp(lifetime=timedelta(minutes=15))
        access_token['verification_code'] = verification_code

        # TODO: change hardcoded url
        verification_link = f"http://localhost:3000/verify-email/{str(access_token)}"

        mail.send(
            user.email,
            settings.DEFAULT_FROM_EMAIL,
            template='verify_email',
            context={'verification_link': verification_link, 'verification_code': verification_code},
            # priority='now',
        )

        return Response(
            {"message": "User registered successfully. A verification email has been sent."},
            status=status.HTTP_201_CREATED
        )


class LoginView(generics.GenericAPIView):
    serializer_class = UserLoginSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        user = authenticate(username=username, password=password)

        if user is not None:
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            })
        return Response({"error": "Invalid credentials"}, status=400)


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


class PasswordRecoveryView(generics.GenericAPIView):
    serializer_class = PasswordRecoverySerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"message": "Se ha enviado un correo de recuperación."}, status=status.HTTP_200_OK)


class PasswordChangeView(generics.GenericAPIView):
    serializer_class = PasswordChangeSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"message": "La contraseña fue cambiada con éxito."}, status=status.HTTP_200_OK)
