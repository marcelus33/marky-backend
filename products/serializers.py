from rest_framework import serializers
from django.db import transaction, IntegrityError
from django.utils import timezone
from decimal import Decimal

from .models import Product, ProductCategory, ProductVariant, ProductAddon, ProductMedia


class ProductPriceMixin:
    """Provide helper methods used to compute/format primary/secondary prices.
    Field declarations (SerializerMethodField) must live on the concrete
    serializer classes so DRF will register them properly.
    """

    def _get_business_profile(self, obj):
        request = self.context.get('request')
        if request and hasattr(request.user, 'business_profile'):
            return request.user.business_profile
        # Try direct business attribute (Product)
        bp = getattr(obj, 'business', None)
        if bp:
            return bp

        # Fallback for related objects (ProductVariant, ProductAddon) which have a product
        product = getattr(obj, 'product', None)
        if product is not None:
            return getattr(product, 'business', None)

        return None

    def _format_currency_amount(self, amount, code):
        """Format Decimal amount like: 'USD 1.000.000,00'"""
        from decimal import Decimal, ROUND_HALF_UP

        if amount is None:
            return None

        if not isinstance(amount, Decimal):
            try:
                amount = Decimal(str(amount))
            except Exception:
                return None

        quantized = amount.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
        # Use grouping with commas then convert to dots for thousands and comma for decimals
        s = f"{quantized:.2f}"
        integer_part, decimal_part = s.split('.')
        integer_with_commas = f"{int(integer_part):,}"  # '1,000,000'
        integer_with_dots = integer_with_commas.replace(',', '.')
        return f"{code} {integer_with_dots},{decimal_part}"

    def _is_date_range_active(self, start, end):
        """Return True if the date range is considered active for now.

        Business rule: only check the date range if both start and end are set. If either
        is missing, the date restriction is ignored (treated as active).
        """
        if not start or not end:
            return True
        now = timezone.now()
        return start <= now <= end

    def _get_effective_discount_percentage(self, obj):
        """Return the effective Decimal discount percentage for a product,
        preferring category discount when active, else product discount.
        Returns Decimal('0') when no active discount exists.
        """
        cat = getattr(obj, 'category', None)
        # Prefer category value when present and active
        if cat and getattr(cat, 'discount_percentage', None) is not None and cat.discount_percentage > 0:
            if self._is_date_range_active(cat.promotion_starts_at, cat.promotion_ends_at):
                return cat.discount_percentage

        # Fallback to product discount
        if getattr(obj, 'discount_percentage', None) is not None and obj.discount_percentage > 0:
            if self._is_date_range_active(obj.promotion_starts_at, obj.promotion_ends_at):
                return obj.discount_percentage

        return Decimal('0')

    def _get_discounted_amounts(self, obj):
        """Return (discounted_primary, discounted_secondary, primary_currency, secondary_currency).

        If there is no active discount or currencies/amounts are missing, returns
        (None, None, None, None) or (None, None, primary_currency, secondary_currency)
        as appropriate.
        """
        bp = self._get_business_profile(obj)
        if not bp:
            return None, None, None, None

        primary_amount, secondary_amount, primary_currency, secondary_currency = obj.get_primary_secondary_amounts(bp)

        if primary_amount is None or primary_currency is None:
            return None, None, None, None

        percent = self._get_effective_discount_percentage(obj)
        if not percent or percent <= 0:
            return None, None, primary_currency, secondary_currency

        # Clamp percent between 0 and 100
        if percent < 0:
            percent = Decimal('0')
        if percent > Decimal('100'):
            percent = Decimal('100')

        factor = (Decimal('100') - percent) / Decimal('100')

        try:
            discounted_primary = primary_amount * factor
        except Exception:
            discounted_primary = None

        discounted_secondary = None
        if secondary_amount is not None:
            try:
                discounted_secondary = secondary_amount * factor
            except Exception:
                discounted_secondary = None

        return discounted_primary, discounted_secondary, primary_currency, secondary_currency

    def get_primary_price(self, obj):
        bp = self._get_business_profile(obj)
        if not bp:
            return None
        primary_amount, _, primary_currency, _ = obj.get_primary_secondary_amounts(bp)
        if primary_amount is None or primary_currency is None:
            return None
        return self._format_currency_amount(primary_amount, primary_currency.code)

    def get_primary_price_with_discount(self, obj):
        discounted_primary, _, primary_currency, _ = self._get_discounted_amounts(obj)
        if discounted_primary is None or primary_currency is None:
            return None
        return self._format_currency_amount(discounted_primary, primary_currency.code)

    def get_secondary_price(self, obj):
        bp = self._get_business_profile(obj)
        if not bp:
            return None
        _, secondary_amount, _, secondary_currency = obj.get_primary_secondary_amounts(bp)
        if secondary_amount is None or secondary_currency is None:
            return None
        return self._format_currency_amount(secondary_amount, secondary_currency.code)

    def get_secondary_price_with_discount(self, obj):
        _, discounted_secondary, _, secondary_currency = self._get_discounted_amounts(obj)
        if discounted_secondary is None or secondary_currency is None:
            return None
        return self._format_currency_amount(discounted_secondary, secondary_currency.code)


class ProductMediaSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProductMedia
        fields = ['id', 'file', 'media_type', 'order']


class ProductMediaInputSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(required=False)
    file = serializers.FileField(required=False, allow_null=True)
    _delete = serializers.BooleanField(required=False, default=False)

    class Meta:
        model = ProductMedia
        fields = ['id', 'file', 'media_type', 'order', '_delete']

    def to_internal_value(self, data):
        if "_delete" in data and isinstance(data["_delete"], str):
            data["_delete"] = data["_delete"].lower() in ("true", "1")
        return super().to_internal_value(data)


class ProductAddonSerializer(ProductPriceMixin, serializers.ModelSerializer):
    primary_price = serializers.SerializerMethodField()
    secondary_price = serializers.SerializerMethodField()

    class Meta:
        model = ProductAddon
        fields = '__all__'


class ProductAddonInputSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(required=False)
    _delete = serializers.BooleanField(required=False, default=False)

    class Meta:
        model = ProductAddon
        fields = ['id', 'name', 'price', '_delete']


class ProductVariantSerializer(ProductPriceMixin, serializers.ModelSerializer):
    primary_price = serializers.SerializerMethodField()
    secondary_price = serializers.SerializerMethodField()

    class Meta:
        model = ProductVariant
        fields = '__all__'


class ProductVariantInputSerializer(serializers.ModelSerializer):
    image = serializers.ImageField(required=False)
    id = serializers.IntegerField(required=False)
    _delete = serializers.BooleanField(required=False, default=False)

    class Meta:
        model = ProductVariant
        fields = ['id', 'name', 'price', 'description', 'image', '_delete']


class ProductCategoryLiteSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProductCategory
        fields = ['id', 'name']


class ProductCategoryBasicSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProductCategory
        fields = [
            'id', 'name', 'icon', 'multibuy_option', 'discount_percentage',
            'promotion_starts_at', 'promotion_ends_at', 'is_available'
        ]


class ProductSerializer(ProductPriceMixin, serializers.ModelSerializer):
    primary_price = serializers.SerializerMethodField()
    secondary_price = serializers.SerializerMethodField()
    primary_price_with_discount = serializers.SerializerMethodField()
    secondary_price_with_discount = serializers.SerializerMethodField()
    variants = ProductVariantSerializer(many=True, read_only=True)
    addons = ProductAddonSerializer(many=True, read_only=True)
    media = ProductMediaSerializer(many=True, read_only=True)
    category = ProductCategoryLiteSerializer(read_only=True)
    # Category promotion fields (read-only, sourced from related ProductCategory)
    category_multibuy_option = serializers.CharField(source='category.multibuy_option', read_only=True, allow_null=True)
    category_discount_percentage = serializers.DecimalField(source='category.discount_percentage', max_digits=5, decimal_places=2, read_only=True)
    category_promotion_starts_at = serializers.DateTimeField(source='category.promotion_starts_at', read_only=True, allow_null=True)
    category_promotion_ends_at = serializers.DateTimeField(source='category.promotion_ends_at', read_only=True, allow_null=True)

    class Meta:
        model = Product
        fields = [
            'id', 'name', 'description', 'price', 'category', 'is_active',
            'category_multibuy_option', 'category_discount_percentage', 'category_promotion_starts_at', 'category_promotion_ends_at',
            'stopper', 'multibuy_option', 'discount_percentage', 'is_available',
            'promotion_starts_at', 'promotion_ends_at', 'business',
            'variants', 'addons', 'media',
            # Human-readable prices for the business context
            'primary_price', 'secondary_price',
            # Human-readable discounted prices
            'primary_price_with_discount', 'secondary_price_with_discount'
        ]


class ProductLiteSerializer(ProductPriceMixin, serializers.ModelSerializer):
    isFavorite = serializers.SerializerMethodField()
    isRecommended = serializers.SerializerMethodField()
    image = serializers.SerializerMethodField()
    # Promotion fields: prefer category values when present and active, otherwise fall back to product
    multibuy_option = serializers.SerializerMethodField()
    discount_percentage = serializers.SerializerMethodField()
    primary_price = serializers.SerializerMethodField()
    secondary_price = serializers.SerializerMethodField()
    # promotion_starts_at = serializers.SerializerMethodField()
    # promotion_ends_at = serializers.SerializerMethodField()

    class Meta:
        model = Product
        fields = ['id', 'name', 'description', 'price', 'isFavorite', 'isRecommended', 'image',
                  'multibuy_option', 'discount_percentage', 'promotion_starts_at', 'promotion_ends_at', 'is_available',
                  'primary_price', 'secondary_price']

    def _get_business_profile(self, obj):
        request = self.context.get('request')
        if request and hasattr(request.user, 'business_profile'):
            return request.user.business_profile
        return getattr(obj, 'business', None)

    def _format_currency_amount(self, amount, code):
        """Format Decimal amount like: 'USD 1.000.000,00'"""
        from decimal import Decimal, ROUND_HALF_UP

        if amount is None:
            return None

        if not isinstance(amount, Decimal):
            try:
                amount = Decimal(str(amount))
            except Exception:
                return None

        quantized = amount.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
        # Use grouping with commas then convert to dots for thousands and comma for decimals
        s = f"{quantized:.2f}"
        integer_part, decimal_part = s.split('.')
        integer_with_commas = f"{int(integer_part):,}"  # '1,000,000'
        integer_with_dots = integer_with_commas.replace(',', '.')
        return f"{code} {integer_with_dots},{decimal_part}"

    def get_primary_price(self, obj):
        bp = self._get_business_profile(obj)
        if not bp:
            return None
        primary_amount, _, primary_currency, _ = obj.get_primary_secondary_amounts(bp)
        if primary_amount is None or primary_currency is None:
            return None
        return self._format_currency_amount(primary_amount, primary_currency.code)

    def get_secondary_price(self, obj):
        bp = self._get_business_profile(obj)
        if not bp:
            return None
        _, secondary_amount, _, secondary_currency = obj.get_primary_secondary_amounts(bp)
        if secondary_amount is None or secondary_currency is None:
            return None
        return self._format_currency_amount(secondary_amount, secondary_currency.code)

    def get_isFavorite(self, obj):
        return obj.stopper == 'FAVORITE'

    def get_isRecommended(self, obj):
        return obj.stopper == 'RECOMMENDED'

    def get_image(self, obj):
        request = self.context.get('request')
        media = obj.media.filter(media_type=ProductMedia.IMAGE).first()
        if media and request:
            return request.build_absolute_uri(media.file.url)
        elif media:
            return media.file.url
        return None

    def _is_date_range_active(self, start, end):
        """Return True if the date range is considered active for now.

        Business rule: only check the date range if both start and end are set. If either
        is missing, the date restriction is ignored (treated as active).
        """
        if not start or not end:
            return True
        now = timezone.now()
        return start <= now <= end

    def get_multibuy_option(self, obj):
        # Prefer category value when present and active
        cat = getattr(obj, 'category', None)
        if cat and cat.multibuy_option:
            if self._is_date_range_active(cat.promotion_starts_at, cat.promotion_ends_at):
                return cat.multibuy_option

        # Fallback to product value when present and active
        if obj.multibuy_option:
            if self._is_date_range_active(obj.promotion_starts_at, obj.promotion_ends_at):
                return obj.multibuy_option

        return None

    def get_discount_percentage(self, obj):
        cat = getattr(obj, 'category', None)
        # Treat a category discount as present if greater than 0
        if cat and cat.discount_percentage is not None and cat.discount_percentage > 0:
            if self._is_date_range_active(cat.promotion_starts_at, cat.promotion_ends_at):
                return cat.discount_percentage

        # Fallback to product discount
        if obj.discount_percentage is not None and obj.discount_percentage > 0:
            if self._is_date_range_active(obj.promotion_starts_at, obj.promotion_ends_at):
                return obj.discount_percentage

        return Decimal('0')

    # def get_promotion_starts_at(self, obj):
    #     cat = getattr(obj, 'category', None)
    #     if cat and (cat.promotion_starts_at or cat.promotion_ends_at):
    #         if self._is_date_range_active(cat.promotion_starts_at, cat.promotion_ends_at):
    #             return cat.promotion_starts_at
    #
    #     if obj.promotion_starts_at or obj.promotion_ends_at:
    #         if self._is_date_range_active(obj.promotion_starts_at, obj.promotion_ends_at):
    #             return obj.promotion_starts_at
    #
    #     return None
    #
    # def get_promotion_ends_at(self, obj):
    #     cat = getattr(obj, 'category', None)
    #     if cat and (cat.promotion_starts_at or cat.promotion_ends_at):
    #         if self._is_date_range_active(cat.promotion_starts_at, cat.promotion_ends_at):
    #             return cat.promotion_ends_at
    #
    #     if obj.promotion_starts_at or obj.promotion_ends_at:
    #         if self._is_date_range_active(obj.promotion_starts_at, obj.promotion_ends_at):
    #             return obj.promotion_ends_at
    #
    #     return None


class ProductCategoryWithProductsSerializer(serializers.ModelSerializer):
    products = ProductLiteSerializer(many=True, read_only=True)

    class Meta:
        model = ProductCategory
        fields = [
            'id', 'name', 'icon', 'multibuy_option', 'discount_percentage',
            'promotion_starts_at', 'promotion_ends_at', 'is_available', 'products'
        ]


class PromotionSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProductCategory
        fields = ['multibuy_option', 'discount_percentage', 'promotion_starts_at', 'promotion_ends_at']


class ProductCategoryOrderSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    order = serializers.IntegerField()


class ProductCategoryOrderUpdateSerializer(serializers.Serializer):
    categories = ProductCategoryOrderSerializer(many=True)


class ProductInputSerializer(serializers.ModelSerializer):
    variants = ProductVariantInputSerializer(many=True, required=False)
    addons = ProductAddonInputSerializer(many=True, required=False)
    media = ProductMediaInputSerializer(many=True, required=False)
    is_promotion_active = serializers.BooleanField(write_only=True, required=False)
    promotion_option = serializers.CharField(write_only=True, required=False, allow_null=True, allow_blank=True)
    countdown_active = serializers.BooleanField(write_only=True, required=False)
    description = serializers.CharField(max_length=300)
    category = serializers.PrimaryKeyRelatedField(
        queryset=ProductCategory.objects.none(), required=False, allow_null=True
    )

    class Meta:
        model = Product
        fields = [
            'name', 'description', 'price', 'category', 'is_active',
            'stopper', 'multibuy_option', 'discount_percentage',
            'promotion_starts_at', 'promotion_ends_at',
            'variants', 'addons', 'media', 'is_available',
            'is_promotion_active', 'promotion_option', 'countdown_active'
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        request = self.context.get('request')
        if request is not None and hasattr(request.user, 'business_profile'):
            self.fields['category'].queryset = ProductCategory.objects.filter(
                business=request.user.business_profile
            )

    def to_internal_value(self, data):
        if 'is_promotion_active' in data:
            is_promotion_active = data.get('is_promotion_active')
            promotion_option = data.get('promotion_option')
            countdown_active = data.get('countdown_active')

            if not is_promotion_active:
                data['multibuy_option'] = None
                data['discount_percentage'] = 0
                data['promotion_starts_at'] = None
                data['promotion_ends_at'] = None
            else:
                if promotion_option == 'descuento':
                    data['multibuy_option'] = None
                elif promotion_option == 'oferta':
                    data['discount_percentage'] = 0
                
                if not countdown_active:
                    data['promotion_starts_at'] = None
                    data['promotion_ends_at'] = None

        return super().to_internal_value(data)

    def validate(self, attrs):
        stopper = attrs.get('stopper', getattr(self.instance, 'stopper', None))
        category = attrs.get('category', getattr(self.instance, 'category', None))

        if stopper == 'FAVORITE' and category is not None:
            conflicting = Product.objects.filter(category=category, stopper='FAVORITE')
            if self.instance is not None:
                conflicting = conflicting.exclude(pk=self.instance.pk)
            existing = conflicting.first()
            if existing is not None:
                raise serializers.ValidationError({
                    'error': (
                        f'"{existing.name}" ya es el Favorito del mes en esta categoría. '
                        'Quita esa etiqueta antes de asignarla a otro producto.'
                    )
                })

        return attrs

    @transaction.atomic
    def create(self, validated_data):
        variants_data = validated_data.pop('variants', [])
        addons_data = validated_data.pop('addons', [])
        media_data = validated_data.pop('media', [])
        validated_data.pop('is_promotion_active', None)
        validated_data.pop('promotion_option', None)
        validated_data.pop('countdown_active', None)

        try:
            product = Product.objects.create(**validated_data)
        except IntegrityError:
            raise serializers.ValidationError({
                'error': (
                    'Ya existe un Favorito del mes en esta categoría. '
                    'Quita esa etiqueta antes de asignarla a otro producto.'
                )
            })

        for variant_data in variants_data:
            if '_delete' in variant_data:
                variant_data.pop('_delete')
            ProductVariant.objects.create(product=product, **variant_data)

        for addon_data in addons_data:
            if '_delete' in addon_data:
                addon_data.pop('_delete')
            ProductAddon.objects.create(product=product, **addon_data)

        for media_item in media_data:
            if '_delete' in media_item:
                media_item.pop('_delete')
            ProductMedia.objects.create(product=product, **media_item)

        return product

    @transaction.atomic
    def update(self, instance, validated_data):
        variants_data = validated_data.pop('variants', [])
        addons_data = validated_data.pop('addons', [])
        media_data = validated_data.pop('media', [])
        validated_data.pop('is_promotion_active', None)
        validated_data.pop('promotion_option', None)
        validated_data.pop('countdown_active', None)

        instance = super().update(instance, validated_data)

        # Helper to process related objects generically
        def process_related(model_class, existing_qs, items_data, create_fields_map=None):
            """
            model_class: ProductVariant, ProductMedia, etc.
            existing_qs: instance.variants.all()
            items_data: list of dicts from validated_data (or None)
            create_fields_map: optional function to map incoming dict -> create kwargs
            """
            if items_data is None:
                # If frontend didn't send anything for this relation, do nothing
                return

            keep_ids = []
            for item in items_data:
                item_id = item.get('id', None)
                should_delete = item.get('_delete', False)

                if item_id:
                    # Existing object: fetch and update or delete
                    try:
                        obj = existing_qs.get(id=item_id)
                    except model_class.DoesNotExist:
                        continue

                    if should_delete:
                        obj.delete()
                        continue

                    # Update allowed fields — avoid overwriting file field with None
                    update_data = {k: v for k, v in item.items() if k not in ('id', '_delete')}

                    # If file/image present, assign it
                    for k, v in update_data.items():
                        if v is not None:
                            setattr(obj, k, v)
                    obj.save()
                    keep_ids.append(obj.id)
                else:
                    # New item (no id): create
                    create_kwargs = {k: v for k, v in item.items() if k != '_delete'}
                    create_kwargs['product'] = instance
                    new_obj = model_class.objects.create(**create_kwargs)
                    keep_ids.append(new_obj.id)

            # Optionally: If you want strict behavior to remove any existing objects not in keep_ids:
            # existing_qs.exclude(id__in=keep_ids).delete()

        # Process each relation
        process_related(ProductVariant, instance.variants, variants_data)
        process_related(ProductAddon, instance.addons, addons_data)
        process_related(ProductMedia, instance.media, media_data)

        return instance


