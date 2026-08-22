from decimal import Decimal

from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from notifications.services import notify

NAME_TRUNCATE_LIMIT = 20


def _truncate_name(name, limit=NAME_TRUNCATE_LIMIT):
    if len(name) <= limit:
        return name
    return name[:limit] + '...'


def _expired_promotion_candidates(model, business, now):
    return model.objects.filter(
        business=business,
        promotion_ends_at__isnull=False,
        promotion_ends_at__lte=now,
    ).filter(Q(multibuy_option__isnull=False) | Q(discount_percentage__gt=0))


def _deactivate_expired(queryset, now):
    """Clear the 4 promo fields for each candidate, yielding only the ones this call actually claimed.

    The `promotion_ends_at=obj.promotion_ends_at` clause is an optimistic-concurrency
    pivot: it only matches if nobody else has already cleared/changed the row, so a
    concurrent caller racing on the same object can never both "win" and double-notify.
    """
    model = queryset.model
    for obj in queryset:
        with transaction.atomic():
            updated = model.objects.filter(
                pk=obj.pk, promotion_ends_at=obj.promotion_ends_at,
            ).update(
                multibuy_option=None,
                discount_percentage=Decimal('0'),
                promotion_starts_at=None,
                promotion_ends_at=None,
            )
        if updated:
            yield obj


def handle_expired_promotions_for_business(business, now=None):
    """Clear expired promotions for this business's products/categories and notify once each."""
    from .models import Product, ProductCategory

    now = now or timezone.now()
    recipients = [business.user]

    products = _expired_promotion_candidates(Product, business, now)
    for product in _deactivate_expired(products, now):
        notify(
            users=recipients,
            title='Promoción finalizada',
            message=f'La promoción del producto "{_truncate_name(product.name)}" ha finalizado.',
            link=f'/product/edit/{product.id}?section=destacar',
        )

    categories = _expired_promotion_candidates(ProductCategory, business, now)
    for category in _deactivate_expired(categories, now):
        notify(
            users=recipients,
            title='Promoción finalizada',
            message=f'La promoción de la categoría "{_truncate_name(category.name)}" ha finalizado.',
            link=f'/home?promoCategory={category.id}',
        )
