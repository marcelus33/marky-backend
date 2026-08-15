from django.db import transaction

from .models import Notification, NotificationRecipient


def notify(users, title, message, link=''):
    """Create one notification and fan it out to `users`. The single seam for all future triggers."""
    with transaction.atomic():
        notification = Notification.objects.create(title=title, message=message, link=link)
        NotificationRecipient.objects.bulk_create(
            [NotificationRecipient(notification=notification, user=user) for user in users]
        )
    return notification
