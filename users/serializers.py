from marky_backend import settings
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from post_office import mail
User = get_user_model()


class UserRegisterSerializer(serializers.ModelSerializer):
    business_name = serializers.CharField(max_length=22)

    class Meta:
        model = User
        fields = ['email', 'password', 'business_name', 'phone_number']

    def validate_business_name(self, value):
        value = value.strip()
        if not value:
            raise serializers.ValidationError("Este campo es requerido.")
        return value

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Este correo ya está registrado.")
        return value

    def create(self, validated_data):
        password = validated_data.pop("password", None)

        email = validated_data.get("email")
        validated_data["username"] = email

        user = User(**validated_data)
        if password:
            try:
                validate_password(password, user)
            except DjangoValidationError as e:
                raise serializers.ValidationError({"password": list(e.messages)})
            user.set_password(password)
        user.save()

        return user


class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()


class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ['id', 'business_name', 'email', 'phone_number', 'has_configuration']


class VerifyEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    verification_code = serializers.CharField(required=True)

    def validate_verification_code(self, value):
        if len(value) != 6 or not value.isdigit():
            raise serializers.ValidationError("El código de verificación debe ser un número de 6 dígitos.")
        return value


class ResendVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()


class PasswordRecoverySerializer(serializers.Serializer):
    email = serializers.EmailField()

    def save(self):
        email = self.validated_data['email']
        user = User.objects.filter(email=email).first()
        if not user:
            return
        # Generate a token
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        # Here, you would send the email with the token
        self.send_recovery_email(user, token, uid)

    def send_recovery_email(self, user, token, uid):
        from django.conf import settings as django_settings
        verification_link = f"{django_settings.FRONTEND_URL}/reset-password/{uid}/{token}/"

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
        try:
            validate_password(new_password, user)
        except DjangoValidationError as e:
            raise serializers.ValidationError({"new_password": list(e.messages)})
        user.set_password(new_password)
        user.save()
