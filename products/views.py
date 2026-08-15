import logging

from django.db import transaction, models
from django_filters import rest_framework as filters

logger = logging.getLogger(__name__)
from drf_spectacular.utils import extend_schema, OpenApiParameter, extend_schema_view
from drf_spectacular.types import OpenApiTypes
from rest_framework import viewsets, status
from rest_framework.decorators import action
import json
from rest_framework.parsers import MultiPartParser, FormParser
from drf_nested_forms.parsers import NestedMultiPartParser
from rest_framework.response import Response
from rest_framework import serializers
from utils.permissions import IsBusinessOrSuperAdmin
from .filters import ProductCategoryFilter, product_has_active_promotion_q
from .promotions import INACTIVE
from .models import ProductCategory, ProductVariant, ProductAddon
from .models import Product
from .services import handle_expired_promotions_for_business
from .serializers import (
    ProductCategoryBasicSerializer,
    ProductCategoryWithProductsSerializer,
    ProductSerializer,
    ProductInputSerializer,
    PromotionSerializer,
    ProductCategoryOrderUpdateSerializer,
    ProductLiteSerializer
)


@extend_schema_view(
    list=extend_schema(
        parameters=[
            OpenApiParameter(name='name', description='Filter by category name (case-insensitive)', required=False, type=OpenApiTypes.STR),
        ]
    ),
    with_products=extend_schema(
        parameters=[
            OpenApiParameter(name='name', description='Filter by category name (case-insensitive)', required=False, type=OpenApiTypes.STR),
            OpenApiParameter(name='ids', description='Filter by a comma-separated list of category IDs', required=False, type=OpenApiTypes.STR),
            OpenApiParameter(name='has_promotion', description='Filter for categories with active promotions', required=False, type=OpenApiTypes.BOOL),
        ]
    )
)
@extend_schema(tags=['Products'])
class ProductCategoryViewSet(viewsets.ModelViewSet):
    permission_classes = [IsBusinessOrSuperAdmin]
    serializer_class = ProductCategoryBasicSerializer
    queryset = ProductCategory.objects.all()

    def get_base_queryset(self):
        user = self.request.user
        if user.is_authenticated and hasattr(user, 'business_profile'):
            handle_expired_promotions_for_business(user.business_profile)
            return ProductCategory.objects.filter(business=user.business_profile)
        return ProductCategory.objects.none()

    def get_queryset(self):
        queryset = self.get_base_queryset()

        if self.action == 'list':
            name = self.request.query_params.get('name')
            if name:
                queryset = queryset.filter(name__icontains=name)

        return queryset

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name='name',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description='Filter categories by name (case-insensitive partial match)'
            )
        ]
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)

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
        except Exception:
            logger.exception("Error updating category order for user %s", request.user.id)
            return Response({'error': 'Ha ocurrido un error inesperado.'}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'status': 'Order updated successfully'}, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'], serializer_class=PromotionSerializer)
    def add_promotion(self, request, pk=None):
        category = self.get_object()
        serializer = self.get_serializer(category, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @extend_schema(
        responses=ProductCategoryWithProductsSerializer(many=True),
        # Swagger will infer parameters from ProductCategoryFilter
    )
    @action(detail=False, methods=['get'], serializer_class=ProductCategoryWithProductsSerializer)
    def with_products(self, request):
        base_qs = self.get_base_queryset()
        category_filter = ProductCategoryFilter(request.GET, queryset=base_qs)
        filtered_qs = category_filter.qs
        has_promotion = bool(category_filter.form.cleaned_data.get('has_promotion'))

        if has_promotion:
            products_count = Product.objects.filter(category__in=filtered_qs).filter(
                product_has_active_promotion_q()
            ).count()
            # Only the products that are actually on promotion should be shown within each category
            filtered_qs = filtered_qs.prefetch_related(
                models.Prefetch('products', queryset=Product.objects.filter(product_has_active_promotion_q()))
            )
        else:
            products_count = filtered_qs.aggregate(total_products=models.Count('products'))['total_products']

        page = self.paginate_queryset(filtered_qs)
        if page is not None:
            serializer = self.get_serializer(page, many=True, context={'request': request})
            serialized_data = serializer.data

            # Now, handle products without a category
            products_without_category = Product.objects.filter(category__isnull=True, business=self.request.user.business_profile)
            if has_promotion:
                products_without_category = products_without_category.filter(product_has_active_promotion_q())
            if products_without_category.exists():
                uncategorized_products_serializer = ProductLiteSerializer(products_without_category, many=True, context={'request': request})
                no_category_data = {
                    'id': None,
                    'name': 'Sin categoría',
                    'icon': 'fa-question-circle',
                    'multibuy_option': None,
                    'discount_percentage': 0,
                    'promotion_starts_at': None,
                    'promotion_ends_at': None,
                    'promotion_status': INACTIVE,
                    'products': uncategorized_products_serializer.data
                }
                serialized_data.append(no_category_data)

            paginated_response = self.get_paginated_response(serialized_data)
            paginated_response.data['products_count'] = products_count
            return paginated_response

        serializer = self.get_serializer(filtered_qs, many=True, context={'request': request})
        serialized_data = serializer.data

        # Also handle for non-paginated response
        products_without_category = Product.objects.filter(category__isnull=True, business=self.request.user.business_profile)
        if has_promotion:
            products_without_category = products_without_category.filter(product_has_active_promotion_q())
        if products_without_category.exists():
            uncategorized_products_serializer = ProductLiteSerializer(products_without_category, many=True, context={'request': request})
            no_category_data = {
                'id': None,
                'name': 'Sin categoría',
                'icon': 'fa-question-circle',
                'multibuy_option': None,
                'discount_percentage': 0,
                'promotion_starts_at': None,
                'promotion_ends_at': None,
                'promotion_status': INACTIVE,
                'products': uncategorized_products_serializer.data
            }
            serialized_data.append(no_category_data)

        return Response({
            'products_count': products_count,
            'results': serialized_data
        })


@extend_schema(tags=['Products'])
class ProductViewSet(viewsets.ModelViewSet):
    permission_classes = [IsBusinessOrSuperAdmin]
    queryset = Product.objects.all()
    parser_classes = (NestedMultiPartParser, FormParser)

    def get_serializer_class(self):
        if self.action in ['create', 'update', 'partial_update']:
            return ProductInputSerializer
        return ProductSerializer

    def get_queryset(self):
        user = self.request.user
        if user.is_authenticated and hasattr(user, 'business_profile'):
            handle_expired_promotions_for_business(user.business_profile)
            return Product.objects.filter(business=user.business_profile)
        return Product.objects.none()

    def perform_create(self, serializer):
        serializer.save(business=self.request.user.business_profile)
