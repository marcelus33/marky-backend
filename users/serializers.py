from marky_backend import settings
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from post_office import mail
User = get_user_model()


class UserRegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'business_name', 'phone_number']


class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()


class VerifyEmailSerializer(serializers.Serializer):
    token = serializers.CharField(required=True)
    verification_code = serializers.CharField(required=True)

    def validate_verification_code(self, value):
        # You can add logic here to validate the verification code if needed
        if len(value) != 6 or not value.isdigit():
            raise serializers.ValidationError("Verification code must be a 6-digit number.")
        return value


class PasswordRecoverySerializer(serializers.Serializer):
    email = serializers.EmailField()

    def save(self):
        email = self.validated_data['email']
        user = User.objects.get(email=email)
        if not user:
            return
        # Generate a token
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        # Here, you would send the email with the token
        self.send_recovery_email(user, token, uid)

    def send_recovery_email(self, user, token, uid):
        # TODO: change hardcoded url
        verification_link = f"http://localhost:3000/reset-password/{uid}/{token}/"

        mail.send(
            user.email,
            settings.DEFAULT_FROM_EMAIL,
            template='password_recovery',
            context={'verification_link': verification_link},
            # priority='now',
        )


class PasswordChangeSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        uid = attrs['uid']
        token = attrs['token']
        try:
            user_id = urlsafe_base64_decode(uid).decode()
            user = User.objects.get(pk=user_id)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            attrs['user'] = user
            return attrs
        raise serializers.ValidationError("Token o ID de Usuario inválido.")

    def save(self):
        user = self.validated_data['user']
        new_password = self.validated_data['new_password']
        user.set_password(new_password)
        user.save()
