from datetime import timedelta
from decimal import Decimal
from types import SimpleNamespace

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase
from django.utils import timezone

from utils.tests_base import MarkyAPITestCase
from products.filters import ProductCategoryFilter
from products.models import Product, ProductCategory, ProductVariant, ProductAddon

User = get_user_model()


# ---------------------------------------------------------------------------
# Unit tests — no database, test model methods in isolation
# ---------------------------------------------------------------------------

def _make_bp(primary_currency=object(), secondary_currency=None, exchange_rate=None, is_primary_to_secondary=True):
    """Return a minimal business-profile-like namespace for currency tests."""
    return SimpleNamespace(
        primary_currency=primary_currency,
        secondary_currency=secondary_currency,
        exchange_rate=exchange_rate,
        is_primary_to_secondary=is_primary_to_secondary,
    )


class TestProductCurrencyArithmetic(SimpleTestCase):

    def test_primary_to_secondary_multiplies_by_rate(self):
        product = Product(price=Decimal('10.00'))
        bp = _make_bp(secondary_currency=object(), exchange_rate=Decimal('5000'), is_primary_to_secondary=True)
        primary, secondary, _, __ = product.get_primary_secondary_amounts(bp)
        self.assertEqual(primary, Decimal('10.00'))
        self.assertEqual(secondary, Decimal('50000.00'))

    def test_secondary_to_primary_divides_by_rate(self):
        product = Product(price=Decimal('10.00'))
        bp = _make_bp(secondary_currency=object(), exchange_rate=Decimal('2'), is_primary_to_secondary=False)
        _, secondary, _, __ = product.get_primary_secondary_amounts(bp)
        self.assertEqual(secondary, Decimal('5.00'))

    def test_rate_zero_returns_none_for_secondary(self):
        product = Product(price=Decimal('10.00'))
        bp = _make_bp(secondary_currency=object(), exchange_rate=Decimal('0'), is_primary_to_secondary=False)
        _, secondary, _, __ = product.get_primary_secondary_amounts(bp)
        self.assertIsNone(secondary)

    def test_no_secondary_currency_returns_none(self):
        product = Product(price=Decimal('10.00'))
        bp = _make_bp(secondary_currency=None, exchange_rate=Decimal('5000'))
        _, secondary, _, sec_cur = product.get_primary_secondary_amounts(bp)
        self.assertIsNone(secondary)
        self.assertIsNone(sec_cur)

    def test_no_exchange_rate_returns_none(self):
        product = Product(price=Decimal('10.00'))
        bp = _make_bp(secondary_currency=object(), exchange_rate=None)
        _, secondary, _, __ = product.get_primary_secondary_amounts(bp)
        self.assertIsNone(secondary)

    def test_none_price_uses_zero(self):
        product = Product(price=None)
        bp = _make_bp(secondary_currency=object(), exchange_rate=Decimal('5000'), is_primary_to_secondary=True)
        primary, secondary, _, __ = product.get_primary_secondary_amounts(bp)
        self.assertEqual(primary, Decimal('0'))
        self.assertEqual(secondary, Decimal('0'))

    def test_no_primary_currency_returns_all_none(self):
        product = Product(price=Decimal('10.00'))
        bp = _make_bp(primary_currency=None)
        result = product.get_primary_secondary_amounts(bp)
        self.assertEqual(result, (None, None, None, None))

    def test_decimal_precision_maintained(self):
        product = Product(price=Decimal('0.01'))
        bp = _make_bp(secondary_currency=object(), exchange_rate=Decimal('3'), is_primary_to_secondary=True)
        _, secondary, _, __ = product.get_primary_secondary_amounts(bp)
        self.assertIsInstance(secondary, Decimal)
        self.assertEqual(secondary, Decimal('0.03'))


class TestProductVariantCurrencyArithmetic(SimpleTestCase):

    def test_primary_to_secondary_multiplies_by_rate(self):
        variant = ProductVariant(price=Decimal('5.00'))
        bp = _make_bp(secondary_currency=object(), exchange_rate=Decimal('4'), is_primary_to_secondary=True)
        primary, secondary, _, __ = variant.get_primary_secondary_amounts(bp)
        self.assertEqual(primary, Decimal('5.00'))
        self.assertEqual(secondary, Decimal('20.00'))

    def test_rate_zero_returns_none_for_secondary(self):
        variant = ProductVariant(price=Decimal('5.00'))
        bp = _make_bp(secondary_currency=object(), exchange_rate=Decimal('0'), is_primary_to_secondary=False)
        _, secondary, _, __ = variant.get_primary_secondary_amounts(bp)
        self.assertIsNone(secondary)

    def test_no_secondary_currency_returns_none(self):
        variant = ProductVariant(price=Decimal('5.00'))
        bp = _make_bp(secondary_currency=None, exchange_rate=Decimal('4'))
        _, secondary, _, __ = variant.get_primary_secondary_amounts(bp)
        self.assertIsNone(secondary)

    def test_no_primary_currency_returns_all_none(self):
        variant = ProductVariant(price=Decimal('5.00'))
        bp = _make_bp(primary_currency=None)
        result = variant.get_primary_secondary_amounts(bp)
        self.assertEqual(result, (None, None, None, None))


class TestProductAddonCurrencyArithmetic(SimpleTestCase):

    def test_primary_to_secondary_multiplies_by_rate(self):
        addon = ProductAddon(price=Decimal('2.50'))
        bp = _make_bp(secondary_currency=object(), exchange_rate=Decimal('4'), is_primary_to_secondary=True)
        primary, secondary, _, __ = addon.get_primary_secondary_amounts(bp)
        self.assertEqual(primary, Decimal('2.50'))
        self.assertEqual(secondary, Decimal('10.00'))

    def test_rate_zero_returns_none_for_secondary(self):
        addon = ProductAddon(price=Decimal('2.50'))
        bp = _make_bp(secondary_currency=object(), exchange_rate=Decimal('0'), is_primary_to_secondary=False)
        _, secondary, _, __ = addon.get_primary_secondary_amounts(bp)
        self.assertIsNone(secondary)

    def test_no_secondary_currency_returns_none(self):
        addon = ProductAddon(price=Decimal('2.50'))
        bp = _make_bp(secondary_currency=None, exchange_rate=Decimal('4'))
        _, secondary, _, __ = addon.get_primary_secondary_amounts(bp)
        self.assertIsNone(secondary)

    def test_no_primary_currency_returns_all_none(self):
        addon = ProductAddon(price=Decimal('2.50'))
        bp = _make_bp(primary_currency=None)
        result = addon.get_primary_secondary_amounts(bp)
        self.assertEqual(result, (None, None, None, None))


# ---------------------------------------------------------------------------
# Integration tests — database required
# ---------------------------------------------------------------------------

class TestPromotionFilter(MarkyAPITestCase):

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.user, cls.profile = cls.make_user('promo_user', 'promo@test.com')
        now = timezone.now()

        cls.cat_multibuy = ProductCategory.objects.create(
            business=cls.profile, name='Multibuy', icon='icon', multibuy_option='2x1',
        )
        cls.cat_discount = ProductCategory.objects.create(
            business=cls.profile, name='Discount', icon='icon', discount_percentage=Decimal('10.00'),
        )
        cls.cat_future = ProductCategory.objects.create(
            business=cls.profile, name='Future', icon='icon',
            discount_percentage=Decimal('10.00'),
            promotion_starts_at=now + timedelta(days=1),
        )
        cls.cat_expired = ProductCategory.objects.create(
            business=cls.profile, name='Expired', icon='icon',
            discount_percentage=Decimal('10.00'),
            promotion_ends_at=now - timedelta(days=1),
        )
        cls.cat_child_promo = ProductCategory.objects.create(
            business=cls.profile, name='Child Promo', icon='icon',
        )
        Product.objects.create(
            name='Promo Child', description='Desc', price=Decimal('10.00'),
            business=cls.profile, category=cls.cat_child_promo,
            discount_percentage=Decimal('15.00'),
        )
        cls.cat_child_expired = ProductCategory.objects.create(
            business=cls.profile, name='Child Expired', icon='icon',
        )
        Product.objects.create(
            name='Expired Child', description='Desc', price=Decimal('10.00'),
            business=cls.profile, category=cls.cat_child_expired,
            discount_percentage=Decimal('15.00'),
            promotion_ends_at=now - timedelta(days=1),
        )
        cls.cat_no_promo = ProductCategory.objects.create(
            business=cls.profile, name='No Promo', icon='icon',
        )

    def _filter(self, value):
        qs = ProductCategory.objects.filter(business=self.profile)
        return set(ProductCategoryFilter({'has_promotion': value}, queryset=qs).qs.values_list('id', flat=True))

    def test_multibuy_category_included(self):
        self.assertIn(self.cat_multibuy.id, self._filter('true'))

    def test_discount_category_included(self):
        self.assertIn(self.cat_discount.id, self._filter('true'))

    def test_future_start_date_excluded(self):
        self.assertNotIn(self.cat_future.id, self._filter('true'))

    def test_past_end_date_excluded(self):
        self.assertNotIn(self.cat_expired.id, self._filter('true'))

    def test_child_product_with_active_promo_includes_category(self):
        self.assertIn(self.cat_child_promo.id, self._filter('true'))

    def test_child_product_with_expired_promo_excludes_category(self):
        self.assertNotIn(self.cat_child_expired.id, self._filter('true'))

    def test_no_promo_category_excluded(self):
        self.assertNotIn(self.cat_no_promo.id, self._filter('true'))

    def test_false_value_returns_all_categories_unfiltered(self):
        all_ids = self._filter('false')
        self.assertIn(self.cat_no_promo.id, all_ids)
        self.assertIn(self.cat_multibuy.id, all_ids)


class TestProductTenancy(MarkyAPITestCase):

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.user_a, cls.profile_a = cls.make_user('tenant_a', 'tenant_a@test.com')
        cls.user_b, cls.profile_b = cls.make_user('tenant_b', 'tenant_b@test.com')
        cls.user_no_profile, _ = cls.make_user('no_profile', 'no_profile@test.com', with_profile=False)

        cls.product_a = Product.objects.create(
            name='Product A', description='Desc', price=Decimal('10.00'), business=cls.profile_a,
        )
        cls.product_b = Product.objects.create(
            name='Product B', description='Desc', price=Decimal('20.00'), business=cls.profile_b,
        )

    def test_list_returns_only_own_products(self):
        client = self.auth_client(self.user_a)
        response = client.get('/api/v1/products/products/')
        ids = [p['id'] for p in response.data['results']]
        self.assertIn(self.product_a.id, ids)
        self.assertNotIn(self.product_b.id, ids)

    def test_retrieve_other_user_product_returns_404(self):
        client = self.auth_client(self.user_a)
        response = client.get(f'/api/v1/products/products/{self.product_b.id}/')
        self.assertEqual(response.status_code, 404)

    def test_update_other_user_product_returns_404(self):
        client = self.auth_client(self.user_a)
        response = client.patch(
            f'/api/v1/products/products/{self.product_b.id}/',
            {'name': 'Hacked'},
            format='json',
        )
        self.assertEqual(response.status_code, 404)

    def test_delete_other_user_product_returns_404(self):
        client = self.auth_client(self.user_a)
        response = client.delete(f'/api/v1/products/products/{self.product_b.id}/')
        self.assertEqual(response.status_code, 404)

    def test_user_without_business_profile_gets_empty_list(self):
        client = self.auth_client(self.user_no_profile)
        response = client.get('/api/v1/products/products/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['results'], [])

    def test_unauthenticated_request_returns_401(self):
        response = self.client.get('/api/v1/products/products/')
        self.assertEqual(response.status_code, 401)

    def test_non_business_user_returns_403(self):
        plain_user = User.objects.create_user(
            username='plain_user', email='plain@test.com', password='TestPass123!', is_verified=True,
        )
        client = self.auth_client(plain_user)
        response = client.get('/api/v1/products/products/')
        self.assertEqual(response.status_code, 403)


class TestProductCategoryTenancy(MarkyAPITestCase):

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.user_a, cls.profile_a = cls.make_user('cat_tenant_a', 'cat_a@test.com')
        cls.user_b, cls.profile_b = cls.make_user('cat_tenant_b', 'cat_b@test.com')

        cls.cat_a = ProductCategory.objects.create(
            business=cls.profile_a, name='Cat A', icon='icon',
        )
        cls.cat_b = ProductCategory.objects.create(
            business=cls.profile_b, name='Cat B', icon='icon',
        )

    def test_list_returns_only_own_categories(self):
        client = self.auth_client(self.user_a)
        response = client.get('/api/v1/products/product-categories/')
        ids = [c['id'] for c in response.data['results']]
        self.assertIn(self.cat_a.id, ids)
        self.assertNotIn(self.cat_b.id, ids)

    def test_retrieve_other_user_category_returns_404(self):
        client = self.auth_client(self.user_a)
        response = client.get(f'/api/v1/products/product-categories/{self.cat_b.id}/')
        self.assertEqual(response.status_code, 404)

    def test_update_other_user_category_returns_404(self):
        client = self.auth_client(self.user_a)
        response = client.patch(
            f'/api/v1/products/product-categories/{self.cat_b.id}/',
            {'name': 'Hacked'},
            format='json',
        )
        self.assertEqual(response.status_code, 404)
