from django.db import models
from business.models import BusinessProfile


class MultiBuyType(models.TextChoices):
    TWO_FOR_ONE = "2x1", "2x1"
    THREE_FOR_TWO = "3x2", "3x2"


class ProductCategory(models.Model):
    business = models.ForeignKey(BusinessProfile, on_delete=models.CASCADE, related_name='product_categories')
    name = models.CharField(max_length=255)
    icon = models.CharField(max_length=50)
    order = models.IntegerField(default=1)
    # promotion
    multibuy_option = models.CharField(
        max_length=10,
        choices=MultiBuyType.choices,
        null=True,
        blank=True,
        help_text="Oferta tipo 2x1, 3x2, etc."
    )
    discount_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    promotion_starts_at = models.DateTimeField(null=True, blank=True)
    promotion_ends_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = "Product Category"
        verbose_name_plural = "Product Categories"
        ordering = ['order']


class Product(models.Model):
    STOPPER_CHOICES = [
        ('FAVORITE', 'Favorito del mes'),
        ('RECOMMENDED', 'Recomendado'),
    ]

    name = models.CharField(max_length=255)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    category = models.ForeignKey(ProductCategory, on_delete=models.CASCADE, related_name='products')
    is_active = models.BooleanField(default=True)
    stopper = models.CharField(
        max_length=20,
        choices=STOPPER_CHOICES,
        null=True,
        blank=True,
        help_text="Tipo de stopper activo (opcional)"
    )
    # promotion
    multibuy_option = models.CharField(
        max_length=10,
        choices=MultiBuyType.choices,
        null=True,
        blank=True,
        help_text="Oferta tipo 2x1, 3x2, etc."
    )
    discount_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    promotion_starts_at = models.DateTimeField(null=True, blank=True)
    promotion_ends_at = models.DateTimeField(null=True, blank=True)
    #
    business = models.ForeignKey(BusinessProfile, on_delete=models.CASCADE, related_name='products')

    def __str__(self):
        return self.name

    def has_stopper(self):
        return self.stopper is not None


class ProductVariant(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='variants')
    name = models.CharField(max_length=255)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    description = models.TextField(blank=True, null=True)
    image = models.ImageField(upload_to='product_variants/', blank=True, null=True)

    def __str__(self):
        return f'{self.product.name} - {self.name}'


class ProductAddon(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='addons')
    name = models.CharField(max_length=255)
    price = models.DecimalField(max_digits=10, decimal_places=2)

    def __str__(self):
        return f'{self.product.name} - {self.name}'


class ProductMedia(models.Model):
    IMAGE = 'image'
    VIDEO = 'video'

    MEDIA_TYPE_CHOICES = [
        (IMAGE, 'Image'),
        (VIDEO, 'Video'),
    ]

    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='media')
    file = models.FileField(upload_to='product_media/')
    media_type = models.CharField(max_length=10, choices=MEDIA_TYPE_CHOICES, default=IMAGE)

    def __str__(self):
        return f'{self.product.name} - {self.media_type}'
