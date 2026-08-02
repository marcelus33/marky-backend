from django.test import TestCase
from utils.tests_base import MarkyAPITestCase
from business.management.commands.seed import Command
from business.models import Currency


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


class TestSeedCurrencyNames(TestCase):
    """Regression test for the Asana ticket 'Step 3 ... Ajuste de textos':
    currency names must be the full display name shown in the frontend
    dropdown, not the abbreviated form."""

    def test_seed_creates_currencies_with_full_names(self):
        Command()._seed_currencies()
        self.assertEqual(Currency.objects.get(code='PYG').name, 'Guaraní Paraguayo')
        self.assertEqual(Currency.objects.get(code='VES').name, 'Bolívar Venezolano')
        self.assertEqual(Currency.objects.get(code='USD').name, 'Dólar Americano')
