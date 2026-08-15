from datetime import timedelta
from decimal import Decimal
from types import SimpleNamespace

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import SimpleTestCase
from django.utils import timezone
from rest_framework import serializers

from utils.tests_base import MarkyAPITestCase
from products.filters import ProductCategoryFilter
from products.models import Product, ProductCategory, ProductVariant, ProductAddon
from products.validators import validate_media_extension, validate_media_size
from products.promotions import (
    compute_promotion_status,
    resolve_effective_promotion,
    ACTIVE,
    SCHEDULED,
    EXPIRED,
    INACTIVE,
)

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


class TestWithProductsPromotionFilter(MarkyAPITestCase):
    """Covers the with_products endpoint: when has_promotion=true, only categories that
    qualify should be returned, and only the products actually on promotion within them
    (own promo, or inherited from an active category-level promo) should be shown."""

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.user, cls.profile = cls.make_user('promo_endpoint_user', 'promo_endpoint@test.com')

        # Category with no promotion of its own, but a mix of promoted/unpromoted products.
        cls.cat_mixed = ProductCategory.objects.create(
            business=cls.profile, name='Galletas', icon='icon',
        )
        cls.promoted_product = Product.objects.create(
            name='Promoted', description='Desc', price=Decimal('3.00'),
            business=cls.profile, category=cls.cat_mixed, discount_percentage=Decimal('30.00'),
        )
        cls.unpromoted_product_1 = Product.objects.create(
            name='Unpromoted 1', description='Desc', price=Decimal('2.00'),
            business=cls.profile, category=cls.cat_mixed,
        )
        cls.unpromoted_product_2 = Product.objects.create(
            name='Unpromoted 2', description='Desc', price=Decimal('2.00'),
            business=cls.profile, category=cls.cat_mixed,
        )

        # Category with its own active promotion: every product in it inherits the promo.
        cls.cat_promo = ProductCategory.objects.create(
            business=cls.profile, name='Bebidas', icon='icon', discount_percentage=Decimal('10.00'),
        )
        cls.inherited_product = Product.objects.create(
            name='Inherited', description='Desc', price=Decimal('5.00'),
            business=cls.profile, category=cls.cat_promo,
        )

        # Category with no promotion at all: should be excluded entirely.
        cls.cat_none = ProductCategory.objects.create(
            business=cls.profile, name='Sin promo', icon='icon',
        )
        Product.objects.create(
            name='No promo product', description='Desc', price=Decimal('1.00'),
            business=cls.profile, category=cls.cat_none,
        )

    def test_only_promoted_products_shown_in_mixed_category(self):
        client = self.auth_client(self.user)
        response = client.get('/api/v1/products/product-categories/with_products/', {'has_promotion': 'true'})
        self.assertEqual(response.status_code, 200)

        results = {cat['name']: cat for cat in response.data['results']}
        self.assertNotIn('Sin promo', results)

        mixed_product_ids = {p['id'] for p in results['Galletas']['products']}
        self.assertEqual(mixed_product_ids, {self.promoted_product.id})

    def test_all_products_shown_when_category_has_active_promotion(self):
        client = self.auth_client(self.user)
        response = client.get('/api/v1/products/product-categories/with_products/', {'has_promotion': 'true'})

        results = {cat['name']: cat for cat in response.data['results']}
        promo_product_ids = {p['id'] for p in results['Bebidas']['products']}
        self.assertEqual(promo_product_ids, {self.inherited_product.id})

    def test_products_count_reflects_only_promoted_products(self):
        client = self.auth_client(self.user)
        response = client.get('/api/v1/products/product-categories/with_products/', {'has_promotion': 'true'})
        # promoted_product (Galletas) + inherited_product (Bebidas) = 2
        self.assertEqual(response.data['products_count'], 2)

    def test_without_filter_all_products_shown(self):
        client = self.auth_client(self.user)
        response = client.get('/api/v1/products/product-categories/with_products/')
        results = {cat['name']: cat for cat in response.data['results']}
        mixed_product_ids = {p['id'] for p in results['Galletas']['products']}
        self.assertEqual(
            mixed_product_ids,
            {self.promoted_product.id, self.unpromoted_product_1.id, self.unpromoted_product_2.id},
        )


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


class TestProductInputSerializerTenancy(MarkyAPITestCase):

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.user_a, cls.profile_a = cls.make_user('input_tenant_a', 'input_tenant_a@test.com')
        cls.user_b, cls.profile_b = cls.make_user('input_tenant_b', 'input_tenant_b@test.com')

        cls.cat_a = ProductCategory.objects.create(business=cls.profile_a, name='Cat A', icon='icon')
        cls.cat_b = ProductCategory.objects.create(business=cls.profile_b, name='Cat B', icon='icon')

        cls.favorite_b = Product.objects.create(
            name='Secret Favorite', description='Desc', price=Decimal('10.00'),
            business=cls.profile_b, category=cls.cat_b, stopper='FAVORITE',
        )

    def test_cannot_assign_product_to_another_tenants_category(self):
        client = self.auth_client(self.user_a)
        response = client.post(
            '/api/v1/products/products/',
            {
                'name': 'New Product', 'description': 'Desc', 'price': '5.00',
                'category': self.cat_b.id, 'stopper': 'FAVORITE',
            },
            format='multipart',
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn('category', response.data)
        # Must be rejected before the FAVORITE-conflict check ever runs, so
        # tenant B's product name can never reach tenant A's response.
        self.assertNotIn('Secret Favorite', str(response.data))


class TestProductFavoriteStopperConstraint(MarkyAPITestCase):
    """DB-level backstop for the FAVORITE-per-category uniqueness rule.

    The serializer's read-then-write check has a TOCTOU gap under concurrent
    requests; a DB constraint guarantees the invariant regardless of races.
    """

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.user, cls.profile = cls.make_user('constraint_tenant', 'constraint_tenant@test.com')
        cls.category = ProductCategory.objects.create(business=cls.profile, name='Cat', icon='icon')

    def test_second_favorite_in_same_category_raises_integrity_error(self):
        from django.db import IntegrityError

        Product.objects.create(
            name='First Favorite', description='Desc', price=Decimal('10.00'),
            business=self.profile, category=self.category, stopper='FAVORITE',
        )
        with self.assertRaises(IntegrityError):
            Product.objects.create(
                name='Second Favorite', description='Desc', price=Decimal('20.00'),
                business=self.profile, category=self.category, stopper='FAVORITE',
            )

    def test_multiple_non_favorite_products_allowed_in_same_category(self):
        Product.objects.create(
            name='Regular 1', description='Desc', price=Decimal('10.00'),
            business=self.profile, category=self.category,
        )
        Product.objects.create(
            name='Regular 2', description='Desc', price=Decimal('20.00'),
            business=self.profile, category=self.category,
        )
        self.assertEqual(Product.objects.filter(category=self.category).count(), 2)

    def test_favorite_allowed_in_different_categories(self):
        other_category = ProductCategory.objects.create(business=self.profile, name='Other', icon='icon')
        Product.objects.create(
            name='Favorite 1', description='Desc', price=Decimal('10.00'),
            business=self.profile, category=self.category, stopper='FAVORITE',
        )
        Product.objects.create(
            name='Favorite 2', description='Desc', price=Decimal('20.00'),
            business=self.profile, category=other_category, stopper='FAVORITE',
        )
        self.assertEqual(Product.objects.filter(stopper='FAVORITE').count(), 2)

    def test_race_past_serializer_check_still_returns_validation_error_not_500(self):
        """Simulate the TOCTOU window: two requests both pass validate() because
        neither commit is visible to the other yet, so the DB constraint is the
        only thing standing between them. The second create() call should turn
        the resulting IntegrityError into a clean DRF ValidationError, not a 500.
        """
        from products.serializers import ProductInputSerializer

        Product.objects.create(
            name='First Favorite', description='Desc', price=Decimal('10.00'),
            business=self.profile, category=self.category, stopper='FAVORITE',
        )

        serializer = ProductInputSerializer()
        with self.assertRaises(serializers.ValidationError):
            serializer.create({
                'name': 'Second Favorite', 'description': 'Desc', 'price': Decimal('20.00'),
                'business': self.profile, 'category': self.category, 'stopper': 'FAVORITE',
            })


class TestProductRecommendedStopperConstraint(MarkyAPITestCase):
    """DB-level backstop for the RECOMMENDED-per-category uniqueness rule.

    Mirrors TestProductFavoriteStopperConstraint: the serializer's
    read-then-write check has a TOCTOU gap under concurrent requests; a DB
    constraint guarantees the invariant regardless of races.
    """

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.user, cls.profile = cls.make_user('recommended_tenant', 'recommended_tenant@test.com')
        cls.category = ProductCategory.objects.create(business=cls.profile, name='Cat', icon='icon')

    def test_second_recommended_in_same_category_raises_integrity_error(self):
        from django.db import IntegrityError

        Product.objects.create(
            name='First Recommended', description='Desc', price=Decimal('10.00'),
            business=self.profile, category=self.category, stopper='RECOMMENDED',
        )
        with self.assertRaises(IntegrityError):
            Product.objects.create(
                name='Second Recommended', description='Desc', price=Decimal('20.00'),
                business=self.profile, category=self.category, stopper='RECOMMENDED',
            )

    def test_multiple_non_recommended_products_allowed_in_same_category(self):
        Product.objects.create(
            name='Regular 1', description='Desc', price=Decimal('10.00'),
            business=self.profile, category=self.category,
        )
        Product.objects.create(
            name='Regular 2', description='Desc', price=Decimal('20.00'),
            business=self.profile, category=self.category,
        )
        self.assertEqual(Product.objects.filter(category=self.category).count(), 2)

    def test_recommended_allowed_in_different_categories(self):
        other_category = ProductCategory.objects.create(business=self.profile, name='Other', icon='icon')
        Product.objects.create(
            name='Recommended 1', description='Desc', price=Decimal('10.00'),
            business=self.profile, category=self.category, stopper='RECOMMENDED',
        )
        Product.objects.create(
            name='Recommended 2', description='Desc', price=Decimal('20.00'),
            business=self.profile, category=other_category, stopper='RECOMMENDED',
        )
        self.assertEqual(Product.objects.filter(stopper='RECOMMENDED').count(), 2)

    def test_favorite_and_recommended_can_coexist_in_same_category(self):
        """The stopper field itself already prevents a product from being both
        FAVORITE and RECOMMENDED at once; this confirms the two constraints
        don't interfere with each other when different products in the same
        category hold different stopper values."""
        Product.objects.create(
            name='The Favorite', description='Desc', price=Decimal('10.00'),
            business=self.profile, category=self.category, stopper='FAVORITE',
        )
        Product.objects.create(
            name='The Recommended', description='Desc', price=Decimal('20.00'),
            business=self.profile, category=self.category, stopper='RECOMMENDED',
        )
        self.assertEqual(Product.objects.filter(category=self.category).count(), 2)

    def test_race_past_serializer_check_still_returns_validation_error_not_500(self):
        """Simulate the TOCTOU window: two requests both pass validate() because
        neither commit is visible to the other yet, so the DB constraint is the
        only thing standing between them. The second create() call should turn
        the resulting IntegrityError into a clean DRF ValidationError, not a 500.
        """
        from products.serializers import ProductInputSerializer

        Product.objects.create(
            name='First Recommended', description='Desc', price=Decimal('10.00'),
            business=self.profile, category=self.category, stopper='RECOMMENDED',
        )

        serializer = ProductInputSerializer()
        with self.assertRaises(serializers.ValidationError):
            serializer.create({
                'name': 'Second Recommended', 'description': 'Desc', 'price': Decimal('20.00'),
                'business': self.profile, 'category': self.category, 'stopper': 'RECOMMENDED',
            })


class TestProductMediaValidators(SimpleTestCase):

    def test_oversized_image_rejected(self):
        f = SimpleUploadedFile('photo.jpg', b'x' * (5 * 1024 * 1024 + 1), content_type='image/jpeg')
        with self.assertRaises(ValidationError):
            validate_media_size(f)

    def test_image_at_exactly_max_size_accepted(self):
        f = SimpleUploadedFile('photo.jpg', b'x' * (5 * 1024 * 1024), content_type='image/jpeg')
        validate_media_size(f)  # should not raise

    def test_oversized_video_rejected(self):
        f = SimpleUploadedFile('clip.mp4', b'x' * (80 * 1024 * 1024 + 1), content_type='video/mp4')
        with self.assertRaises(ValidationError):
            validate_media_size(f)

    def test_video_at_exactly_max_size_accepted(self):
        f = SimpleUploadedFile('clip.mp4', b'x' * (80 * 1024 * 1024), content_type='video/mp4')
        validate_media_size(f)  # should not raise

    def test_small_video_not_held_to_image_limit(self):
        # A 6MB video is over the image cap but well under the video cap —
        # confirms size limits are chosen by extension, not a single shared cap.
        f = SimpleUploadedFile('clip.webm', b'x' * (6 * 1024 * 1024), content_type='video/webm')
        validate_media_size(f)  # should not raise

    def test_disallowed_extension_rejected(self):
        f = SimpleUploadedFile('malware.exe', b'x', content_type='application/octet-stream')
        with self.assertRaises(ValidationError):
            validate_media_extension(f)

    def test_disallowed_video_extension_rejected(self):
        f = SimpleUploadedFile('clip.avi', b'x', content_type='video/x-msvideo')
        with self.assertRaises(ValidationError):
            validate_media_extension(f)

    def test_each_allowed_extension_accepted(self):
        for ext, content_type in [
            ('.jpg', 'image/jpeg'), ('.jpeg', 'image/jpeg'), ('.png', 'image/png'),
            ('.webp', 'image/webp'), ('.mp4', 'video/mp4'), ('.mov', 'video/quicktime'),
            ('.webm', 'video/webm'),
        ]:
            f = SimpleUploadedFile(f'file{ext}', b'x', content_type=content_type)
            validate_media_extension(f)  # should not raise


class TestProductMediaUploadAPI(MarkyAPITestCase):

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.user, cls.profile = cls.make_user('media_tenant', 'media_tenant@test.com')

    def _create_payload(self, file_):
        return {
            'name': 'Product With Media', 'description': 'Desc', 'price': '10.00',
            'media[0][file]': file_, 'media[0][media_type]': 'image', 'media[0][order]': '0',
        }

    def test_oversized_image_rejected_by_api(self):
        client = self.auth_client(self.user)
        big_file = SimpleUploadedFile(
            'photo.jpg', b'x' * (5 * 1024 * 1024 + 1), content_type='image/jpeg',
        )
        response = client.post(
            '/api/v1/products/products/', self._create_payload(big_file), format='multipart',
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(Product.objects.filter(name='Product With Media').exists())

    def test_disallowed_extension_rejected_by_api(self):
        client = self.auth_client(self.user)
        bad_file = SimpleUploadedFile('malware.exe', b'x', content_type='application/octet-stream')
        response = client.post(
            '/api/v1/products/products/', self._create_payload(bad_file), format='multipart',
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(Product.objects.filter(name='Product With Media').exists())

    def test_valid_image_accepted_by_api(self):
        client = self.auth_client(self.user)
        good_file = SimpleUploadedFile('photo.jpg', b'x' * 1024, content_type='image/jpeg')
        response = client.post(
            '/api/v1/products/products/', self._create_payload(good_file), format='multipart',
        )
        self.assertEqual(response.status_code, 201)


class TestProductStopperIntegrityErrorBackstop(MarkyAPITestCase):
    """update()'s IntegrityError backstop (previously missing entirely — only
    create() had one) and the disambiguation that keeps an unrelated
    IntegrityError from being mislabeled as a stopper conflict in either
    method.
    """

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.user, cls.profile = cls.make_user('backstop_tenant', 'backstop_tenant@test.com')
        cls.category = ProductCategory.objects.create(business=cls.profile, name='Cat', icon='icon')

    def test_update_race_past_serializer_check_still_returns_validation_error_not_500(self):
        """Mirrors the equivalent create() race test: two updates both pass
        validate() before either commits, so the DB constraint is the only
        thing standing between them. update() must turn the resulting
        IntegrityError into a clean ValidationError, not a 500.
        """
        from products.serializers import ProductInputSerializer

        Product.objects.create(
            name='First Recommended', description='Desc', price=Decimal('10.00'),
            business=self.profile, category=self.category, stopper='RECOMMENDED',
        )
        other = Product.objects.create(
            name='Not Recommended Yet', description='Desc', price=Decimal('20.00'),
            business=self.profile, category=self.category,
        )

        serializer = ProductInputSerializer()
        with self.assertRaises(serializers.ValidationError):
            serializer.update(other, {'stopper': 'RECOMMENDED'})

    def test_create_unrelated_integrity_error_is_not_mislabeled_as_stopper_conflict(self):
        """If create() hits an IntegrityError that isn't actually a stopper
        conflict (e.g. a concurrently-deleted category causing an FK
        violation), it must propagate as-is rather than being reported as a
        fake 'Ya existe un Recomendado...' conflict."""
        from unittest.mock import patch
        from django.db import IntegrityError
        from products.serializers import ProductInputSerializer

        serializer = ProductInputSerializer()
        with patch(
            'products.serializers.Product.objects.create',
            side_effect=IntegrityError('unrelated constraint violation'),
        ):
            with self.assertRaises(IntegrityError):
                serializer.create({
                    'name': 'X', 'description': 'Desc', 'price': Decimal('10.00'),
                    'business': self.profile, 'category': self.category, 'stopper': 'RECOMMENDED',
                })

    def test_update_unrelated_integrity_error_is_not_mislabeled_as_stopper_conflict(self):
        """Same guarantee as above, for update()."""
        from unittest.mock import patch
        from django.db import IntegrityError
        from products.serializers import ProductInputSerializer

        product = Product.objects.create(
            name='X', description='Desc', price=Decimal('10.00'),
            business=self.profile, category=self.category,
        )

        serializer = ProductInputSerializer()
        with patch(
            'products.models.Product.save',
            side_effect=IntegrityError('unrelated constraint violation'),
        ):
            with self.assertRaises(IntegrityError):
                serializer.update(product, {'name': 'Y'})


# ---------------------------------------------------------------------------
# Promotion single-source-of-truth (Asana #8) — products/promotions.py and
# its wiring into ProductInputSerializer / ProductLiteSerializer / ProductSerializer.
# ---------------------------------------------------------------------------

class TestPromotionStatus(SimpleTestCase):
    """Pure unit tests for compute_promotion_status — no DB needed."""

    def test_inactive_when_nothing_configured(self):
        self.assertEqual(
            compute_promotion_status(None, Decimal('0'), None, None), INACTIVE,
        )

    def test_active_multibuy_only_no_dates(self):
        self.assertEqual(
            compute_promotion_status('2x1', Decimal('0'), None, None), ACTIVE,
        )

    def test_active_discount_only_no_dates(self):
        self.assertEqual(
            compute_promotion_status(None, Decimal('10.00'), None, None), ACTIVE,
        )

    def test_scheduled_when_start_in_future(self):
        now = timezone.now()
        self.assertEqual(
            compute_promotion_status(None, Decimal('10.00'), now + timedelta(days=1), None, now=now),
            SCHEDULED,
        )

    def test_expired_when_end_in_past(self):
        now = timezone.now()
        self.assertEqual(
            compute_promotion_status(None, Decimal('10.00'), None, now - timedelta(days=1), now=now),
            EXPIRED,
        )

    def test_active_within_window(self):
        now = timezone.now()
        self.assertEqual(
            compute_promotion_status(
                None, Decimal('10.00'), now - timedelta(hours=1), now + timedelta(hours=1), now=now,
            ),
            ACTIVE,
        )

    def test_expired_wins_even_if_window_is_otherwise_inverted(self):
        # Defensive: a passed end date means expired regardless of the start.
        now = timezone.now()
        self.assertEqual(
            compute_promotion_status(
                None, Decimal('10.00'), now - timedelta(days=2), now - timedelta(days=1), now=now,
            ),
            EXPIRED,
        )


class TestResolveEffectivePromotion(SimpleTestCase):
    """Category-vs-product bundling must never mix a category discount with
    the product's own dates or vice versa — the ticket's headline root cause."""

    def _category(self, multibuy_option=None, discount_percentage=Decimal('0'), starts_at=None, ends_at=None):
        return SimpleNamespace(
            multibuy_option=multibuy_option, discount_percentage=discount_percentage,
            promotion_starts_at=starts_at, promotion_ends_at=ends_at,
        )

    def _product(self, category=None, multibuy_option=None, discount_percentage=Decimal('0'),
                 starts_at=None, ends_at=None):
        return SimpleNamespace(
            category=category, multibuy_option=multibuy_option, discount_percentage=discount_percentage,
            promotion_starts_at=starts_at, promotion_ends_at=ends_at,
        )

    def test_active_category_promo_wins_over_product(self):
        now = timezone.now()
        category = self._category(
            discount_percentage=Decimal('20.00'),
            starts_at=now - timedelta(hours=1), ends_at=now + timedelta(hours=1),
        )
        product = self._product(
            category=category, discount_percentage=Decimal('5.00'),
            starts_at=now - timedelta(days=10), ends_at=now - timedelta(days=9),
        )

        bundle = resolve_effective_promotion(product, now=now)

        self.assertEqual(bundle['source'], 'category')
        self.assertEqual(bundle['status'], ACTIVE)
        self.assertEqual(bundle['discount_percentage'], Decimal('20.00'))
        self.assertEqual(bundle['promotion_starts_at'], category.promotion_starts_at)
        self.assertEqual(bundle['promotion_ends_at'], category.promotion_ends_at)

    def test_expired_category_falls_back_to_products_own_active_promo(self):
        now = timezone.now()
        category = self._category(discount_percentage=Decimal('20.00'), ends_at=now - timedelta(days=1))
        product = self._product(category=category, discount_percentage=Decimal('5.00'))

        bundle = resolve_effective_promotion(product, now=now)

        self.assertEqual(bundle['source'], 'product')
        self.assertEqual(bundle['status'], ACTIVE)
        self.assertEqual(bundle['discount_percentage'], Decimal('5.00'))

    def test_no_category_uses_product_own_bundle(self):
        product = self._product(category=None, discount_percentage=Decimal('5.00'))
        bundle = resolve_effective_promotion(product)
        self.assertEqual(bundle['source'], 'product')
        self.assertEqual(bundle['status'], ACTIVE)

    def test_scheduled_category_still_wins_over_product(self):
        now = timezone.now()
        category = self._category(discount_percentage=Decimal('20.00'), starts_at=now + timedelta(days=1))
        product = self._product(category=category, discount_percentage=Decimal('5.00'))

        bundle = resolve_effective_promotion(product, now=now)

        self.assertEqual(bundle['source'], 'category')
        self.assertEqual(bundle['status'], SCHEDULED)

    def test_inactive_category_falls_back_to_product(self):
        category = self._category()  # nothing configured
        product = self._product(category=category, discount_percentage=Decimal('5.00'))

        bundle = resolve_effective_promotion(product)

        self.assertEqual(bundle['source'], 'product')
        self.assertEqual(bundle['status'], ACTIVE)


class TestPromotionStatusFilterConsistency(MarkyAPITestCase):
    """compute_promotion_status() and filters.py::_promotion_active_q must
    agree on which window combinations count as 'currently active' — they're
    independently implemented, and the serializer side already drifted from
    the filter once (see products/promotions.py's module docstring)."""

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.user, cls.profile = cls.make_user('consistency_user', 'consistency@test.com')

    def test_status_agrees_with_orm_filter_across_date_combinations(self):
        now = timezone.now()
        matrix = [
            ('no_dates', None, None),
            ('future_start_only', now + timedelta(days=1), None),
            ('past_start_only', now - timedelta(days=1), None),
            ('future_end_only', None, now + timedelta(days=1)),
            ('past_end_only', None, now - timedelta(days=1)),
            ('within_window', now - timedelta(hours=1), now + timedelta(hours=1)),
            ('future_window', now + timedelta(days=1), now + timedelta(days=2)),
            ('past_window', now - timedelta(days=2), now - timedelta(days=1)),
        ]

        for label, starts_at, ends_at in matrix:
            with self.subTest(label=label):
                category = ProductCategory.objects.create(
                    business=self.profile, name=f'Cat {label}', icon='icon',
                    discount_percentage=Decimal('10.00'),
                    promotion_starts_at=starts_at, promotion_ends_at=ends_at,
                )
                status = compute_promotion_status(
                    category.multibuy_option, category.discount_percentage,
                    category.promotion_starts_at, category.promotion_ends_at, now=now,
                )
                matched_by_filter = ProductCategoryFilter(
                    {'has_promotion': 'true'},
                    queryset=ProductCategory.objects.filter(pk=category.pk),
                ).qs.exists()

                # has_promotion=true means "currently benefits from a promo
                # right now" — a scheduled (future-start) promo correctly
                # does not match it, so only ACTIVE should agree with the filter.
                self.assertEqual(
                    status == ACTIVE, matched_by_filter,
                    f'{label}: compute_promotion_status={status} but filter matched={matched_by_filter}',
                )


class TestProductInputSerializerPromotion(MarkyAPITestCase):
    """Regression coverage for the ticket's headline bug: an unrelated-field
    save must never touch promo config, and an explicit clear must actually
    clear it (including the multipart empty-string-vs-NULL quirk)."""

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.user, cls.profile = cls.make_user('promo_input_user', 'promo_input@test.com')

    def _create_promo_product(self, **overrides):
        now = timezone.now()
        defaults = dict(
            name='Promo Product', description='Desc', price=Decimal('10.00'),
            business=self.profile,
            discount_percentage=Decimal('25.00'),
            promotion_starts_at=now - timedelta(hours=1),
            promotion_ends_at=now + timedelta(days=1),
        )
        defaults.update(overrides)
        return Product.objects.create(**defaults)

    def test_update_without_promotion_fields_leaves_them_untouched(self):
        product = self._create_promo_product()
        starts_at, ends_at = product.promotion_starts_at, product.promotion_ends_at
        client = self.auth_client(self.user)

        response = client.patch(
            f'/api/v1/products/products/{product.id}/', {'price': '15.00'}, format='multipart',
        )

        self.assertEqual(response.status_code, 200)
        product.refresh_from_db()
        self.assertEqual(product.price, Decimal('15.00'))
        self.assertEqual(product.discount_percentage, Decimal('25.00'))
        self.assertEqual(product.promotion_starts_at, starts_at)
        self.assertEqual(product.promotion_ends_at, ends_at)

    def test_multibuy_option_empty_string_normalizes_to_null(self):
        product = Product.objects.create(
            name='Multibuy Product', description='Desc', price=Decimal('10.00'),
            business=self.profile, multibuy_option='2x1',
        )
        client = self.auth_client(self.user)

        response = client.patch(
            f'/api/v1/products/products/{product.id}/', {'multibuy_option': ''}, format='multipart',
        )

        self.assertEqual(response.status_code, 200)
        product.refresh_from_db()
        self.assertIsNone(product.multibuy_option)

    def test_clearing_dates_via_empty_string_nulls_them(self):
        product = self._create_promo_product()
        client = self.auth_client(self.user)

        response = client.patch(
            f'/api/v1/products/products/{product.id}/',
            {'promotion_starts_at': '', 'promotion_ends_at': ''},
            format='multipart',
        )

        self.assertEqual(response.status_code, 200)
        product.refresh_from_db()
        self.assertIsNone(product.promotion_starts_at)
        self.assertIsNone(product.promotion_ends_at)

    def test_promotion_end_before_start_rejected_on_create(self):
        client = self.auth_client(self.user)
        now = timezone.now()

        response = client.post(
            '/api/v1/products/products/',
            {
                'name': 'Bad Window', 'description': 'Desc', 'price': '10.00',
                'discount_percentage': '10.00',
                'promotion_starts_at': (now + timedelta(days=1)).isoformat(),
                'promotion_ends_at': now.isoformat(),
            },
            format='multipart',
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn('promotion_ends_at', response.data)

    def test_partial_update_start_only_validates_against_existing_end(self):
        product = self._create_promo_product()
        client = self.auth_client(self.user)

        response = client.patch(
            f'/api/v1/products/products/{product.id}/',
            {'promotion_starts_at': (product.promotion_ends_at + timedelta(days=1)).isoformat()},
            format='multipart',
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn('promotion_ends_at', response.data)

    def test_expired_promotion_survives_unrelated_update(self):
        """The 'no auto-teardown' decision: an already-expired promo's
        config must not be rejected or cleared by an unrelated save — that's
        ticket #6's job, not #8's."""
        now = timezone.now()
        product = self._create_promo_product(
            promotion_starts_at=now - timedelta(days=2),
            promotion_ends_at=now - timedelta(days=1),
        )
        client = self.auth_client(self.user)

        response = client.patch(
            f'/api/v1/products/products/{product.id}/', {'price': '20.00'}, format='multipart',
        )

        self.assertEqual(response.status_code, 200)
        product.refresh_from_db()
        self.assertEqual(product.discount_percentage, Decimal('25.00'))
        self.assertIsNotNone(product.promotion_starts_at)
        self.assertIsNotNone(product.promotion_ends_at)


class TestPromotionStatusInResponses(MarkyAPITestCase):
    """API-level regression tests for promotion_status and the
    category-discount-with-product-dates bug (ticket #8's headline symptom)."""

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.user, cls.profile = cls.make_user('promo_status_user', 'promo_status@test.com')

    def test_expired_promotion_status_is_expired_but_fields_kept(self):
        now = timezone.now()
        product = Product.objects.create(
            name='Expired Promo', description='Desc', price=Decimal('10.00'),
            business=self.profile,
            discount_percentage=Decimal('30.00'),
            promotion_starts_at=now - timedelta(days=2),
            promotion_ends_at=now - timedelta(days=1),
        )
        client = self.auth_client(self.user)

        response = client.get(f'/api/v1/products/products/{product.id}/')

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['promotion_status'], EXPIRED)
        # Kept as history — no auto-teardown, that's ticket #6's job.
        product.refresh_from_db()
        self.assertEqual(product.discount_percentage, Decimal('30.00'))
        self.assertIsNotNone(product.promotion_starts_at)
        self.assertIsNotNone(product.promotion_ends_at)

    def test_category_promo_active_uses_category_dates_not_product_dates(self):
        now = timezone.now()
        category = ProductCategory.objects.create(
            business=self.profile, name='Cat Promo', icon='icon',
            discount_percentage=Decimal('40.00'),
            promotion_starts_at=now - timedelta(hours=1),
            promotion_ends_at=now + timedelta(hours=1),
        )
        Product.objects.create(
            name='Inherits Category Promo', description='Desc', price=Decimal('10.00'),
            business=self.profile, category=category,
            # Product's OWN promo dates are stale/expired — the resolved
            # dates shown to the card/quick modal must be the category's.
            discount_percentage=Decimal('5.00'),
            promotion_starts_at=now - timedelta(days=10),
            promotion_ends_at=now - timedelta(days=9),
        )
        category.refresh_from_db()
        client = self.auth_client(self.user)

        response = client.get(
            '/api/v1/products/product-categories/with_products/', {'ids': str(category.id)},
        )

        self.assertEqual(response.status_code, 200)
        [returned_product] = response.data['results'][0]['products']
        self.assertEqual(returned_product['promotion_status'], ACTIVE)
        self.assertEqual(returned_product['discount_percentage'], Decimal('40.00'))
        self.assertEqual(returned_product['promotion_starts_at'], category.promotion_starts_at)
        self.assertEqual(returned_product['promotion_ends_at'], category.promotion_ends_at)

    def test_category_expired_falls_back_to_product_own_active_promo(self):
        now = timezone.now()
        category = ProductCategory.objects.create(
            business=self.profile, name='Cat Expired', icon='icon',
            discount_percentage=Decimal('40.00'),
            promotion_ends_at=now - timedelta(days=1),
        )
        Product.objects.create(
            name='Own Active Promo', description='Desc', price=Decimal('10.00'),
            business=self.profile, category=category,
            discount_percentage=Decimal('5.00'),
        )
        client = self.auth_client(self.user)

        response = client.get(
            '/api/v1/products/product-categories/with_products/', {'ids': str(category.id)},
        )

        [returned_product] = response.data['results'][0]['products']
        self.assertEqual(returned_product['promotion_status'], ACTIVE)
        self.assertEqual(returned_product['discount_percentage'], Decimal('5.00'))
