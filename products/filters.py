from django.db.models import Q, Exists, OuterRef
from django.utils import timezone
from django_filters import rest_framework as filters
from .models import ProductCategory, Product


class NumberInFilter(filters.BaseInFilter, filters.NumberFilter):
    pass


class ProductCategoryFilter(filters.FilterSet):
    name = filters.CharFilter(lookup_expr='icontains')
    ids = NumberInFilter(field_name='id', lookup_expr='in')
    has_promotion = filters.BooleanFilter(method='filter_has_promotion')

    class Meta:
        model = ProductCategory
        fields = ['name', 'ids', 'has_promotion']

    def filter_has_promotion(self, queryset, name, value):
        now = timezone.now()

        # Promotion conditions for a direct promotion on the category or product
        promotion_conditions = (
            Q(multibuy_option__isnull=False) | Q(discount_percentage__gt=0)
        ) & (
            Q(promotion_starts_at__isnull=True) | Q(promotion_starts_at__lte=now)
        ) & (
            Q(promotion_ends_at__isnull=True) | Q(promotion_ends_at__gte=now)
        )

        # Subquery to check for products with promotions within the category
        products_with_promotions = Product.objects.filter(
            category=OuterRef('pk')
        ).filter(promotion_conditions)

        if value:
            # Filter for categories that either have a promotion themselves or have products with promotions
            return queryset.filter(
                promotion_conditions | Q(Exists(products_with_promotions))
            ).distinct()
        return queryset
