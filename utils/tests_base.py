from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import override_settings
from rest_framework.test import APITestCase, APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from business.models import BusinessProfile, Currency

User = get_user_model()


@override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend')
class MarkyAPITestCase(APITestCase):
    """
    Base class for all Marky API tests.

    Provides:
    - business_group, primary_currency, secondary_currency as class-level fixtures
    - make_user() classmethod to create a verified business user + profile
    - auth_client() to get a JWT-authenticated APIClient for a given user
    """

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.business_group, _ = Group.objects.get_or_create(name='business')
        cls.primary_currency = Currency.objects.create(name='US Dollar', code='USD')
        cls.secondary_currency = Currency.objects.create(name='Guarani', code='PYG')

    @classmethod
    def make_user(cls, username, email, password='TestPass123!', is_verified=True, with_profile=True):
        """Create a user in the business group, optionally with a BusinessProfile."""
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            is_verified=is_verified,
        )
        cls.business_group.user_set.add(user)
        profile = None
        if with_profile:
            profile = BusinessProfile.objects.create(
                user=user,
                business_id=username,
                primary_currency=cls.primary_currency,
            )
        return user, profile

    def auth_client(self, user):
        """Return an APIClient with a valid JWT Bearer token for the given user."""
        client = APIClient()
        refresh = RefreshToken.for_user(user)
        client.credentials(HTTP_AUTHORIZATION=f'Bearer {str(refresh.access_token)}')
        return client
