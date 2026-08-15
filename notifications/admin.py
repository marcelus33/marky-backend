from django.contrib import admin

from .models import Notification, NotificationRecipient


class NotificationRecipientInline(admin.TabularInline):
    model = NotificationRecipient
    autocomplete_fields = ('user',)
    extra = 1


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ('id', 'title', 'link', 'created_at')
    search_fields = ('title', 'message')
    inlines = [NotificationRecipientInline]


@admin.register(NotificationRecipient)
class NotificationRecipientAdmin(admin.ModelAdmin):
    list_display = ('id', 'notification', 'user', 'is_read', 'read_at')
    list_filter = ('is_read',)
    search_fields = ('user__username', 'user__email', 'notification__title')
