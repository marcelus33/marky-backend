from rest_framework import serializers
from django.db import transaction
from .models import Product, ProductCategory, ProductVariant, ProductAddon, ProductMedia


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
        print("Raw _delete value:", data.get("_delete"))
        if "_delete" in data and isinstance(data["_delete"], str):
            data["_delete"] = data["_delete"].lower() in ("true", "1")
        return super().to_internal_value(data)


class ProductAddonSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProductAddon
        fields = '__all__'


class ProductAddonInputSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProductAddon
        fields = ['name', 'price']


class ProductVariantSerializer(serializers.ModelSerializer):
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
            'promotion_starts_at', 'promotion_ends_at'
        ]


class ProductSerializer(serializers.ModelSerializer):
    variants = ProductVariantSerializer(many=True, read_only=True)
    addons = ProductAddonSerializer(many=True, read_only=True)
    media = ProductMediaSerializer(many=True, read_only=True)
    category = ProductCategoryLiteSerializer(read_only=True)

    class Meta:
        model = Product
        fields = [
            'id', 'name', 'description', 'price', 'category', 'is_active',
            'stopper', 'multibuy_option', 'discount_percentage',
            'promotion_starts_at', 'promotion_ends_at', 'business',
            'variants', 'addons', 'media'
        ]


class ProductLiteSerializer(serializers.ModelSerializer):
    isFavorite = serializers.SerializerMethodField()
    image = serializers.SerializerMethodField()

    class Meta:
        model = Product
        fields = ['id', 'name', 'price', 'isFavorite', 'image']

    def get_isFavorite(self, obj):
        return obj.stopper == 'FAVORITE'

    def get_image(self, obj):
        request = self.context.get('request')
        media = obj.media.filter(media_type=ProductMedia.IMAGE).first()
        if media and request:
            return request.build_absolute_uri(media.file.url)
        elif media:
            return media.file.url
        return None


class ProductCategoryWithProductsSerializer(serializers.ModelSerializer):
    products = ProductLiteSerializer(many=True, read_only=True)

    class Meta:
        model = ProductCategory
        fields = [
            'id', 'name', 'icon', 'multibuy_option', 'discount_percentage',
            'promotion_starts_at', 'promotion_ends_at', 'products'
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

    class Meta:
        model = Product
        fields = [
            'name', 'description', 'price', 'category', 'is_active',
            'stopper', 'multibuy_option', 'discount_percentage',
            'promotion_starts_at', 'promotion_ends_at',
            'variants', 'addons', 'media',
            'is_promotion_active', 'promotion_option', 'countdown_active'
        ]

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

    @transaction.atomic
    def create(self, validated_data):
        variants_data = validated_data.pop('variants', [])
        addons_data = validated_data.pop('addons', [])
        media_data = validated_data.pop('media', [])
        validated_data.pop('is_promotion_active', None)
        validated_data.pop('promotion_option', None)
        validated_data.pop('countdown_active', None)

        product = Product.objects.create(**validated_data)

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


