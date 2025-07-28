from django.db import transaction, models
from drf_spectacular.utils import extend_schema
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from .models import ProductCategory
from .serializers import (
    ProductCategoryBasicSerializer,
    ProductCategoryWithProductsSerializer,
    PromotionSerializer,
    ProductCategoryOrderUpdateSerializer
)


@extend_schema(tags=['Products'])
class ProductCategoryViewSet(viewsets.ModelViewSet):
    serializer_class = ProductCategoryBasicSerializer
    queryset = ProductCategory.objects.all()

    def get_queryset(self):
        user = self.request.user
        if user.is_authenticated and hasattr(user, 'business_profile'):
            return ProductCategory.objects.filter(business=user.business_profile)
        return ProductCategory.objects.none()

    def perform_create(self, serializer):
        business = self.request.user.business_profile
        max_order = ProductCategory.objects.filter(business=business).aggregate(models.Max('order'))['order__max'] or 0
        serializer.save(business=business, order=max_order + 1)

    @extend_schema(
        request=ProductCategoryOrderUpdateSerializer,
        responses={200: None}
    )
    @action(detail=False, methods=['post'])
    def update_order(self, request):
        # TODO: let's see if we can optimize this w/bulk update
        categories_data = request.data.get('categories', [])

        try:
            with transaction.atomic():
                for category_data in categories_data:
                    ProductCategory.objects.filter(id=category_data['id']).update(order=category_data['order'])
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'status': 'Order updated successfully'}, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'], serializer_class=PromotionSerializer)
    def add_promotion(self, request, pk=None):
        category = self.get_object()
        serializer = self.get_serializer(category, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['get'], serializer_class=ProductCategoryWithProductsSerializer)
    def with_products(self, request):
        queryset = self.get_queryset()
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)
