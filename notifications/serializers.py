from rest_framework import serializers

from .models import NotificationRecipient


class NotificationSerializer(serializers.ModelSerializer):
    title = serializers.CharField(source='notification.title', read_only=True)
    message = serializers.CharField(source='notification.message', read_only=True)
    link = serializers.CharField(source='notification.link', read_only=True)
    created_at = serializers.DateTimeField(source='notification.created_at', read_only=True)

    class Meta:
        model = NotificationRecipient
        fields = ['id', 'title', 'message', 'link', 'created_at', 'is_read', 'read_at']
        read_only_fields = fields


class MarkAllReadResponseSerializer(serializers.Serializer):
    updated = serializers.IntegerField()
