from django.utils import timezone
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter
from rest_framework import mixins, viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response

from .models import NotificationRecipient
from .pagination import NotificationPagination
from .serializers import NotificationSerializer, MarkAllReadResponseSerializer


@extend_schema_view(
    list=extend_schema(
        parameters=[
            OpenApiParameter(name='is_read', description='Filter by read state', required=False, type=OpenApiTypes.BOOL),
        ]
    )
)
@extend_schema(tags=['Notifications'])
class NotificationViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    serializer_class = NotificationSerializer
    pagination_class = NotificationPagination

    def get_queryset(self):
        queryset = NotificationRecipient.objects.filter(
            user=self.request.user
        ).select_related('notification').order_by('-notification__created_at', '-id')

        if self.action == 'list':
            is_read = self.request.query_params.get('is_read')
            if is_read is not None:
                queryset = queryset.filter(is_read=is_read.lower() == 'true')

        return queryset

    @action(detail=True, methods=['post'], url_path='read')
    def read(self, request, pk=None):
        recipient = self.get_object()
        if not recipient.is_read:
            recipient.is_read = True
            recipient.read_at = timezone.now()
            recipient.save(update_fields=['is_read', 'read_at'])
        return Response(self.get_serializer(recipient).data)

    @extend_schema(request=None, responses={200: MarkAllReadResponseSerializer})
    @action(detail=False, methods=['post'], url_path='read-all')
    def read_all(self, request):
        updated = self.get_queryset().filter(is_read=False).update(is_read=True, read_at=timezone.now())
        return Response(MarkAllReadResponseSerializer({'updated': updated}).data, status=status.HTTP_200_OK)
