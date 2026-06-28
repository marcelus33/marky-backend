from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.utils import timezone

from utils.tests_base import MarkyAPITestCase

User = get_user_model()


class TestRegister(MarkyAPITestCase):

    @patch('users.views.mail.send')
    def test_register_creates_unverified_user(self, mock_mail):
        response = self.client.post('/api/v1/users/register/', {
            'username': 'newuser',
            'email': 'newuser@test.com',
            'password': 'TestPass123!',
            'business_name': 'My Business',
        })
        self.assertEqual(response.status_code, 201)
        user = User.objects.get(email='newuser@test.com')
        self.assertFalse(user.is_verified)
        self.assertIsNotNone(user.verification_code)

    @patch('users.views.mail.send')
    def test_register_adds_user_to_business_group(self, mock_mail):
        self.client.post('/api/v1/users/register/', {
            'username': 'groupuser',
            'email': 'groupuser@test.com',
            'password': 'TestPass123!',
            'business_name': 'My Business',
        })
        user = User.objects.get(email='groupuser@test.com')
        self.assertTrue(user.groups.filter(name='business').exists())

    @patch('users.views.mail.send')
    def test_register_sends_verification_email(self, mock_mail):
        self.client.post('/api/v1/users/register/', {
            'username': 'emailuser',
            'email': 'emailuser@test.com',
            'password': 'TestPass123!',
            'business_name': 'My Business',
        })
        mock_mail.assert_called_once()

    def test_register_duplicate_email_returns_400(self):
        User.objects.create_user(
            username='existing', email='existing@test.com', password='TestPass123!',
        )
        response = self.client.post('/api/v1/users/register/', {
            'username': 'other',
            'email': 'existing@test.com',
            'password': 'TestPass123!',
            'business_name': 'My Business',
        })
        self.assertEqual(response.status_code, 400)


class TestEmailVerification(MarkyAPITestCase):

    def _make_unverified_user(self, username='unverified', email='unverified@test.com'):
        user = User.objects.create_user(
            username=username, email=email, password='TestPass123!', is_verified=False,
        )
        user.verification_code = '123456'
        user.verification_code_expires_at = timezone.now() + timedelta(minutes=15)
        user.save(update_fields=['verification_code', 'verification_code_expires_at'])
        return user

    def test_valid_code_verifies_user(self):
        user = self._make_unverified_user()
        response = self.client.post('/api/v1/users/verify-email/', {
            'email': user.email,
            'verification_code': '123456',
        })
        self.assertEqual(response.status_code, 200)
        user.refresh_from_db()
        self.assertTrue(user.is_verified)

    def test_wrong_code_returns_400(self):
        user = self._make_unverified_user('unv2', 'unv2@test.com')
        response = self.client.post('/api/v1/users/verify-email/', {
            'email': user.email,
            'verification_code': '000000',
        })
        self.assertEqual(response.status_code, 400)
        user.refresh_from_db()
        self.assertFalse(user.is_verified)

    def test_expired_code_returns_400(self):
        user = self._make_unverified_user('unv3', 'unv3@test.com')
        user.verification_code_expires_at = timezone.now() - timedelta(minutes=1)
        user.save(update_fields=['verification_code_expires_at'])
        response = self.client.post('/api/v1/users/verify-email/', {
            'email': user.email,
            'verification_code': '123456',
        })
        self.assertEqual(response.status_code, 400)

    def test_already_verified_user_returns_400(self):
        user, _ = self.make_user('already_ver', 'already_ver@test.com')
        response = self.client.post('/api/v1/users/verify-email/', {
            'email': user.email,
            'verification_code': '123456',
        })
        self.assertEqual(response.status_code, 400)

    def test_nonexistent_email_returns_400(self):
        response = self.client.post('/api/v1/users/verify-email/', {
            'email': 'ghost@test.com',
            'verification_code': '123456',
        })
        self.assertEqual(response.status_code, 400)


class TestLogin(MarkyAPITestCase):

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.verified_user, _ = cls.make_user('login_user', 'login@test.com')
        cls.unverified_user = User.objects.create_user(
            username='unverified_login', email='unverified_login@test.com',
            password='TestPass123!', is_verified=False,
        )

    def test_verified_user_receives_tokens(self):
        response = self.client.post('/api/v1/users/login/', {
            'username': 'login_user',
            'password': 'TestPass123!',
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_unverified_user_cannot_login(self):
        response = self.client.post('/api/v1/users/login/', {
            'username': 'unverified_login',
            'password': 'TestPass123!',
        })
        self.assertEqual(response.status_code, 401)

    def test_wrong_password_returns_401(self):
        response = self.client.post('/api/v1/users/login/', {
            'username': 'login_user',
            'password': 'WrongPassword!',
        })
        self.assertEqual(response.status_code, 401)


class TestResendVerification(MarkyAPITestCase):

    @patch('users.views.mail.send')
    def test_unverified_user_receives_new_code(self, mock_mail):
        user = User.objects.create_user(
            username='resend_user', email='resend@test.com',
            password='TestPass123!', is_verified=False,
        )
        old_code = '000000'
        user.verification_code = old_code
        user.save(update_fields=['verification_code'])

        response = self.client.post('/api/v1/users/resend-verification/', {'email': user.email})
        self.assertEqual(response.status_code, 200)
        user.refresh_from_db()
        self.assertNotEqual(user.verification_code, old_code)
        mock_mail.assert_called_once()

    @patch('users.views.mail.send')
    def test_nonexistent_email_returns_200_without_leaking(self, mock_mail):
        # Security: always return 200 regardless of whether email exists
        response = self.client.post('/api/v1/users/resend-verification/', {'email': 'ghost@test.com'})
        self.assertEqual(response.status_code, 200)
        mock_mail.assert_not_called()

    def test_already_verified_user_returns_400(self):
        user, _ = self.make_user('resend_verified', 'resend_verified@test.com')
        response = self.client.post('/api/v1/users/resend-verification/', {'email': user.email})
        self.assertEqual(response.status_code, 400)
