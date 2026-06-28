from utils.tests_base import MarkyAPITestCase


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
