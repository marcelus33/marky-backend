from django.contrib.auth import get_user_model

from utils.tests_base import MarkyAPITestCase
from .models import Notification, NotificationRecipient
from .services import notify

User = get_user_model()


class TestNotificationService(MarkyAPITestCase):

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.user_a, cls.profile_a = cls.make_user('tenant_a', 'tenant_a@test.com')
        cls.user_b, cls.profile_b = cls.make_user('tenant_b', 'tenant_b@test.com')

    def test_notify_fans_out_to_all_recipients(self):
        notify([self.user_a, self.user_b], 'Title', 'Message')
        self.assertEqual(NotificationRecipient.objects.filter(user=self.user_a).count(), 1)
        self.assertEqual(NotificationRecipient.objects.filter(user=self.user_b).count(), 1)
        self.assertEqual(Notification.objects.count(), 1)

    def test_marking_read_for_one_user_does_not_affect_the_other(self):
        notify([self.user_a, self.user_b], 'Title', 'Message')
        recipient_a = NotificationRecipient.objects.get(user=self.user_a)
        recipient_a.is_read = True
        recipient_a.save()

        recipient_b = NotificationRecipient.objects.get(user=self.user_b)
        self.assertFalse(recipient_b.is_read)


class TestNotificationTenancy(MarkyAPITestCase):

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.user_a, cls.profile_a = cls.make_user('tenant_a', 'tenant_a@test.com')
        cls.user_b, cls.profile_b = cls.make_user('tenant_b', 'tenant_b@test.com')
        cls.notification_a = notify([cls.user_a], 'For A', 'Message A')
        cls.notification_b = notify([cls.user_b], 'For B', 'Message B')
        cls.recipient_a = NotificationRecipient.objects.get(notification=cls.notification_a, user=cls.user_a)
        cls.recipient_b = NotificationRecipient.objects.get(notification=cls.notification_b, user=cls.user_b)

    def test_list_returns_only_own_notifications(self):
        client = self.auth_client(self.user_a)
        response = client.get('/api/v1/notifications/')
        ids = [n['id'] for n in response.data['results']]
        self.assertIn(self.recipient_a.id, ids)
        self.assertNotIn(self.recipient_b.id, ids)

    def test_mark_other_user_notification_read_returns_404(self):
        client = self.auth_client(self.user_a)
        response = client.post(f'/api/v1/notifications/{self.recipient_b.id}/read/')
        self.assertEqual(response.status_code, 404)

    def test_user_with_no_notifications_gets_empty_list(self):
        user_c, _ = self.make_user('tenant_c', 'tenant_c@test.com')
        client = self.auth_client(user_c)
        response = client.get('/api/v1/notifications/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['results'], [])
        self.assertEqual(response.data['unread_count'], 0)

    def test_unauthenticated_request_returns_401(self):
        response = self.client.get('/api/v1/notifications/')
        self.assertEqual(response.status_code, 401)

    def test_non_business_user_can_still_list_own_notifications(self):
        # Notifications are user-scoped, not business-scoped, so a user outside
        # the 'business' group is not blocked the way products/business views block them.
        plain_user = User.objects.create_user(
            username='plain_user', email='plain@test.com', password='TestPass123!', is_verified=True,
        )
        notify([plain_user], 'For plain user', 'Message')
        client = self.auth_client(plain_user)
        response = client.get('/api/v1/notifications/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['results']), 1)


class TestNotificationReadFlow(MarkyAPITestCase):

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.user, cls.profile = cls.make_user('tenant_a', 'tenant_a@test.com')
        notify([cls.user], 'First', 'Message 1')
        notify([cls.user], 'Second', 'Message 2')
        notify([cls.user], 'Third', 'Message 3')

    def test_unread_count_in_envelope(self):
        client = self.auth_client(self.user)
        response = client.get('/api/v1/notifications/')
        self.assertEqual(response.data['unread_count'], 3)

    def test_mark_one_read_decrements_unread_count(self):
        client = self.auth_client(self.user)
        recipient_id = NotificationRecipient.objects.filter(user=self.user).first().id
        response = client.post(f'/api/v1/notifications/{recipient_id}/read/')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data['is_read'])

        response = client.get('/api/v1/notifications/')
        self.assertEqual(response.data['unread_count'], 2)

    def test_marking_read_twice_is_idempotent(self):
        client = self.auth_client(self.user)
        recipient_id = NotificationRecipient.objects.filter(user=self.user).first().id
        client.post(f'/api/v1/notifications/{recipient_id}/read/')
        response = client.post(f'/api/v1/notifications/{recipient_id}/read/')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data['is_read'])

    def test_is_read_query_param_filters(self):
        client = self.auth_client(self.user)
        recipient_id = NotificationRecipient.objects.filter(user=self.user).first().id
        client.post(f'/api/v1/notifications/{recipient_id}/read/')

        response = client.get('/api/v1/notifications/?is_read=false')
        self.assertEqual(len(response.data['results']), 2)

        response = client.get('/api/v1/notifications/?is_read=true')
        self.assertEqual(len(response.data['results']), 1)

    def test_read_all_marks_everything_read_and_returns_count(self):
        client = self.auth_client(self.user)
        response = client.post('/api/v1/notifications/read-all/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['updated'], 3)

        response = client.get('/api/v1/notifications/')
        self.assertEqual(response.data['unread_count'], 0)

    def test_read_all_is_idempotent(self):
        client = self.auth_client(self.user)
        client.post('/api/v1/notifications/read-all/')
        response = client.post('/api/v1/notifications/read-all/')
        self.assertEqual(response.data['updated'], 0)
