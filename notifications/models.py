from django.conf import settings
from django.db import models


class Notification(models.Model):
    title = models.CharField(max_length=255)
    message = models.TextField()
    link = models.CharField(
        max_length=255, blank=True, default='',
        help_text="Ruta relativa del frontend a la que navega la notificación, ej. /product/42"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    recipients = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        through='NotificationRecipient',
        related_name='notifications',
    )

    class Meta:
        verbose_name = "Notification"
        verbose_name_plural = "Notifications"
        ordering = ['-created_at']

    def __str__(self):
        return self.title


class NotificationRecipient(models.Model):
    notification = models.ForeignKey(Notification, on_delete=models.CASCADE, related_name='deliveries')
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='notification_deliveries'
    )
    is_read = models.BooleanField(default=False)
    read_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "Notification Recipient"
        verbose_name_plural = "Notification Recipients"
        unique_together = ('notification', 'user')
        indexes = [models.Index(fields=['user', 'is_read'])]

    def __str__(self):
        return f"{self.notification_id} -> {self.user_id}"
