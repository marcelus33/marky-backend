from rest_framework import serializers
from .models import Product, ProductCategory, ProductVariant, ProductAddon, ProductMedia


class ProductMediaSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProductMedia
        fields = '__all__'


class ProductAddonSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProductAddon
        fields = '__all__'


class ProductVariantSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProductVariant
        fields = '__all__'


class ProductSerializer(serializers.ModelSerializer):
    variants = ProductVariantSerializer(many=True, read_only=True)
    addons = ProductAddonSerializer(many=True, read_only=True)
    media = ProductMediaSerializer(many=True, read_only=True)

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
        media = obj.media.filter(media_type=ProductMedia.IMAGE).first()
        if media:
            return media.file.url
        return None


class ProductCategoryBasicSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProductCategory
        fields = [
            'id', 'name', 'icon', 'multibuy_option', 'discount_percentage',
            'promotion_starts_at', 'promotion_ends_at'
        ]


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
