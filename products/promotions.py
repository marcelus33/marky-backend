"""Single source of truth for "is this promotion active" logic.

Both `Product` and `ProductCategory` carry the same 4 promo fields
(`multibuy_option`, `discount_percentage`, `promotion_starts_at`,
`promotion_ends_at`). This module computes a derived, read-only status from
those fields instead of storing one, and resolves category-vs-product
promotion inheritance as a single atomic bundle so a discount from one
source is never paired with dates from the other.

Window semantics here intentionally match `filters.py::_promotion_active_q`
(each bound evaluated independently) rather than the old per-serializer
`_is_date_range_active` helpers, which treated a one-sided window as always
active. `products/filters.py` docs this as the canonical definition of
"active promotion" — keep the two in sync.
"""
from django.utils import timezone

ACTIVE = 'active'
SCHEDULED = 'scheduled'
EXPIRED = 'expired'
INACTIVE = 'inactive'


def has_promotion_configured(multibuy_option, discount_percentage):
    return bool(multibuy_option) or (discount_percentage is not None and discount_percentage > 0)


def compute_promotion_status(multibuy_option, discount_percentage, starts_at, ends_at, now=None):
    """Return 'active' | 'scheduled' | 'expired' | 'inactive' for one set of promo fields.

    - inactive: no multibuy option and no positive discount configured at all.
    - expired: an end date is set and has passed.
    - scheduled: a start date is set and hasn't arrived yet.
    - active: configured, and not excluded by either of the above.
    """
    if not has_promotion_configured(multibuy_option, discount_percentage):
        return INACTIVE

    now = now or timezone.now()

    if ends_at is not None and now >= ends_at:
        return EXPIRED

    if starts_at is not None and now < starts_at:
        return SCHEDULED

    return ACTIVE


def resolve_effective_promotion(product, now=None):
    """Return the promo bundle that should be shown for a Product, honoring
    category-overrides-product inheritance as one atomic unit.

    Returns a dict with 'source' ('category' | 'product'), 'status', and the
    4 promo fields all drawn from the same source — never a category
    discount paired with the product's own dates or vice versa.
    """
    now = now or timezone.now()

    category = getattr(product, 'category', None)
    if category is not None:
        category_status = compute_promotion_status(
            category.multibuy_option, category.discount_percentage,
            category.promotion_starts_at, category.promotion_ends_at, now,
        )
        if category_status in (ACTIVE, SCHEDULED):
            return {
                'source': 'category',
                'status': category_status,
                'multibuy_option': category.multibuy_option,
                'discount_percentage': category.discount_percentage,
                'promotion_starts_at': category.promotion_starts_at,
                'promotion_ends_at': category.promotion_ends_at,
            }

    product_status = compute_promotion_status(
        product.multibuy_option, product.discount_percentage,
        product.promotion_starts_at, product.promotion_ends_at, now,
    )
    return {
        'source': 'product',
        'status': product_status,
        'multibuy_option': product.multibuy_option,
        'discount_percentage': product.discount_percentage,
        'promotion_starts_at': product.promotion_starts_at,
        'promotion_ends_at': product.promotion_ends_at,
    }
