from rest_framework import serializers
from business.models import BusinessCategory, Currency, BusinessProfile
from cities_light.models import City, Country
from django.contrib.auth import get_user_model

User = get_user_model()


class BusinessProfileWriteSerializer(serializers.ModelSerializer):
    categories = serializers.PrimaryKeyRelatedField(queryset=BusinessCategory.objects.all(), many=True, required=False)
    city = serializers.PrimaryKeyRelatedField(queryset=City.objects.all(), required=False)
    primary_currency = serializers.PrimaryKeyRelatedField(queryset=Currency.objects.all())
    secondary_currency = serializers.PrimaryKeyRelatedField(queryset=Currency.objects.all(), required=False)

    class Meta:
        model = BusinessProfile
        fields = [
            'business_id', 'categories', 'city', 'business_type',
            'primary_currency', 'secondary_currency', 'exchange_rate',
            'is_primary_to_secondary',
        ]


class BusinessProfileListSerializer(serializers.ModelSerializer):
    class Meta:
        model = BusinessProfile
        fields = ['id', 'user', 'business_id']
        read_only_fields = fields


class BusinessProfileDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = BusinessProfile
        fields = ['user', 'business_id', 'categories', 'city',
                  'primary_currency', 'secondary_currency', 'exchange_rate', ]
        read_only_fields = fields


class BusinessCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = BusinessCategory
        fields = ['id', 'name']


class CurrencySerializer(serializers.ModelSerializer):
    class Meta:
        model = Currency
        fields = ['id', 'name', 'code']


class CitySerializer(serializers.ModelSerializer):
    class Meta:
        model = City
        fields = ['id', 'name', 'country']


class CountrySerializer(serializers.ModelSerializer):
    class Meta:
        model = Country
        fields = ['id', 'name']
