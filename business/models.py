from django.db import models
from django.contrib.auth import get_user_model
from cities_light.models import City

User = get_user_model()


class BusinessCategory(models.Model):
    name = models.CharField(max_length=255, unique=True)

    class Meta:
        verbose_name = 'Business Category'
        verbose_name_plural = 'Business Categories'

    def __str__(self):
        return self.name


class Currency(models.Model):
    name = models.CharField(max_length=100)
    code = models.CharField(max_length=10, unique=True)  # e.g. "USD", "PYG", "VES"

    class Meta:
        verbose_name = 'Currency'
        verbose_name_plural = 'Currencies'

    def __str__(self):
        return f"{self.name} ({self.code})"


class BusinessProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='business_profile')
    business_id = models.SlugField(max_length=100, unique=True)
    categories = models.ManyToManyField(BusinessCategory, related_name='business_categories')
    city = models.ForeignKey(City, on_delete=models.SET_NULL, null=True, blank=True)

    primary_currency = models.ForeignKey(Currency, on_delete=models.PROTECT, related_name='primary_businesses')
    secondary_currency = models.ForeignKey(Currency, on_delete=models.SET_NULL,
                                           null=True, blank=True, related_name='secondary_businesses')

    exchange_rate = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    # Indicates the direction of the exchange:
    # True: exchange_rate is interpreted as "1 primary currency unit equals exchange_rate secondary currency units"
    # False: exchange_rate is interpreted as "1 secondary currency unit equals exchange_rate primary currency units"
    is_primary_to_secondary = models.BooleanField(default=True)

    BUSINESS_TYPE_CHOICES = (
        ('commercial', 'Comercial'),
        ('entrepreneur', 'Emprendedor'),
    )
    business_type = models.CharField(
        max_length=20,
        choices=BUSINESS_TYPE_CHOICES,
        default='commercial',
        help_text="Tipo de negocio"
    )

    management_methods = models.JSONField(blank=True, null=True)  # medios_gestion_cuenta
    display_methods = models.JSONField(blank=True, null=True)  # medios_mostrar_cuenta

    class Meta:
        verbose_name = 'Business Profile'
        verbose_name_plural = 'Business Profiles'

    def __str__(self):
        return f"{self.business_id} - {self.user}"
