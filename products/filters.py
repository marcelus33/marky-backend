from django.db.models import Q, Exists, OuterRef
from django.utils import timezone
from django_filters import rest_framework as filters
from .models import ProductCategory, Product


class NumberInFilter(filters.BaseInFilter, filters.NumberFilter):
    pass


def _promotion_active_q(now, prefix=''):
    """Q object for 'has a direct, currently-active promotion', on the given model/relation prefix."""
    multibuy = f'{prefix}multibuy_option'
    discount = f'{prefix}discount_percentage'
    starts = f'{prefix}promotion_starts_at'
    ends = f'{prefix}promotion_ends_at'
    return (
        Q(**{f'{multibuy}__isnull': False}) | Q(**{f'{discount}__gt': 0})
    ) & (
        Q(**{f'{starts}__isnull': True}) | Q(**{f'{starts}__lte': now})
    ) & (
        Q(**{f'{ends}__isnull': True}) | Q(**{f'{ends}__gte': now})
    )


def product_has_active_promotion_q(now=None):
    """Q object (for the Product model) matching products effectively on promotion:
    a promotion on the product itself, or an active promotion inherited from its category.
    Mirrors ProductLiteSerializer.get_multibuy_option/get_discount_percentage.
    """
    if now is None:
        now = timezone.now()
    return _promotion_active_q(now) | _promotion_active_q(now, prefix='category__')


class ProductCategoryFilter(filters.FilterSet):
    name = filters.CharFilter(lookup_expr='icontains')
    ids = NumberInFilter(field_name='id', lookup_expr='in')
    has_promotion = filters.BooleanFilter(method='filter_has_promotion')

    class Meta:
        model = ProductCategory
        fields = ['name', 'ids', 'has_promotion']

    def filter_has_promotion(self, queryset, name, value):
        now = timezone.now()
        promotion_conditions = _promotion_active_q(now)

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
