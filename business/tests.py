from django.test import TestCase
from utils.tests_base import MarkyAPITestCase
from business.management.commands.seed import Command
from business.models import Currency, BusinessProfile


class TestBusinessProfileTenancy(MarkyAPITestCase):

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.user_a, cls.profile_a = cls.make_user('biz_a', 'biz_a@test.com')
        cls.user_b, cls.profile_b = cls.make_user('biz_b', 'biz_b@test.com')

    def test_user_can_retrieve_own_profile(self):
        client = self.auth_client(self.user_a)
        response = client.get(f'/api/v1/business/business_profile/{self.profile_a.id}/')
        self.assertEqual(response.status_code, 200)

    def test_user_cannot_retrieve_other_profile(self):
        client = self.auth_client(self.user_a)
        response = client.get(f'/api/v1/business/business_profile/{self.profile_b.id}/')
        self.assertEqual(response.status_code, 404)

    def test_unauthenticated_request_returns_401(self):
        response = self.client.get(f'/api/v1/business/business_profile/{self.profile_a.id}/')
        self.assertEqual(response.status_code, 401)

    def test_superuser_can_retrieve_any_profile(self):
        from django.contrib.auth import get_user_model
        User = get_user_model()
        superuser = User.objects.create_superuser(
            username='super', email='super@test.com', password='TestPass123!',
        )
        client = self.auth_client(superuser)
        response = client.get(f'/api/v1/business/business_profile/{self.profile_a.id}/')
        self.assertEqual(response.status_code, 200)


class TestBusinessProfileCreateExchangeDirection(MarkyAPITestCase):
    """Regression test: BusinessProfileWriteSerializer must not silently
    default is_primary_to_secondary to True on creation."""

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.user, _ = cls.make_user('biz_new', 'biz_new@test.com', with_profile=False)

    def test_create_without_is_primary_to_secondary_is_rejected(self):
        client = self.auth_client(self.user)
        response = client.post('/api/v1/business/business_profile/', {
            'business_id': 'biz-new',
            'primary_currency': self.primary_currency.id,
        }, format='json')
        self.assertEqual(response.status_code, 400)
        self.assertIn('is_primary_to_secondary', response.data)

    def test_create_persists_explicit_direction_false(self):
        client = self.auth_client(self.user)
        response = client.post('/api/v1/business/business_profile/', {
            'business_id': 'biz-new',
            'primary_currency': self.primary_currency.id,
            'secondary_currency': self.secondary_currency.id,
            'exchange_rate': '6000',
            'is_primary_to_secondary': False,
        }, format='json')
        self.assertEqual(response.status_code, 201)
        profile = BusinessProfile.objects.get(business_id='biz-new')
        self.assertFalse(profile.is_primary_to_secondary)

    def test_partial_update_without_is_primary_to_secondary_still_works(self):
        client = self.auth_client(self.user)
        create_response = client.post('/api/v1/business/business_profile/', {
            'business_id': 'biz-new',
            'primary_currency': self.primary_currency.id,
            'is_primary_to_secondary': True,
        }, format='json')
        self.assertEqual(create_response.status_code, 201)
        profile_id = BusinessProfile.objects.get(business_id='biz-new').id

        response = client.patch(
            f'/api/v1/business/business_profile/{profile_id}/',
            {'business_id': 'biz-new-renamed'},
            format='json',
        )
        self.assertEqual(response.status_code, 200)


class TestSeedCurrencyNames(TestCase):
    """Regression test for the Asana ticket 'Step 3 ... Ajuste de textos':
    currency names must be the full display name shown in the frontend
    dropdown, not the abbreviated form."""

    def test_seed_creates_currencies_with_full_names(self):
        Command()._seed_currencies()
        self.assertEqual(Currency.objects.get(code='PYG').name, 'Guaraní Paraguayo')
        self.assertEqual(Currency.objects.get(code='VES').name, 'Bolívar Venezolano')
        self.assertEqual(Currency.objects.get(code='USD').name, 'Dólar Americano')
