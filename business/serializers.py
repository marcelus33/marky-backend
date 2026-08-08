from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers
from business.models import BusinessCategory, Currency, BusinessProfile, SocialMediaLink, BranchAttribute
from .validators import validate_image_size, validate_image_extension
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


class SocialMediaLinkSerializer(serializers.ModelSerializer):
    platform_display = serializers.CharField(source='get_platform_display', read_only=True)
    
    class Meta:
        model = SocialMediaLink
        fields = ['id', 'platform', 'platform_display', 'url']
        
    def create(self, validated_data):
        # Get the business from the context (will be set in the view)
        business = self.context['business']
        validated_data['business'] = business
        return super().create(validated_data)
        
    def update(self, instance, validated_data):
        # Ensure business cannot be changed during update
        validated_data.pop('business', None)
        return super().update(instance, validated_data)


class SocialMediaLinkBulkUpdateSerializer(serializers.Serializer):
    """
    Serializer for bulk updating social media links.
    Accepts platform names as field names with URLs as values.
    """
    facebook = serializers.URLField(required=False, allow_blank=False, help_text="Facebook page URL")
    instagram = serializers.URLField(required=False, allow_blank=False, help_text="Instagram profile URL")
    whatsapp = serializers.CharField(required=False, allow_blank=False, help_text="WhatsApp number or URL")
    website = serializers.URLField(required=False, allow_blank=False, help_text="Website URL")
    
    def validate(self, data):
        """
        Validate that at least one platform is provided and all URLs are valid.
        """
        if not data:
            raise serializers.ValidationError("At least one social media platform must be provided.")
        
        # Validate WhatsApp format (can be phone number or URL)
        if 'whatsapp' in data:
            whatsapp_value = data['whatsapp']
            # Allow phone numbers or WhatsApp URLs
            if not (whatsapp_value.startswith('http') or whatsapp_value.replace('+', '').replace(' ', '').isdigit()):
                raise serializers.ValidationError({
                    'whatsapp': 'WhatsApp must be a valid phone number or URL.'
                })
        
        return data


class SocialMediaLinkBulkUpdateResponseSerializer(serializers.Serializer):
    """
    Serializer for the bulk update response.
    """
    social_links = SocialMediaLinkSerializer(many=True, read_only=True)
    created = serializers.IntegerField(read_only=True, help_text="Number of links created")
    updated = serializers.IntegerField(read_only=True, help_text="Number of links updated")
    removed = serializers.IntegerField(read_only=True, help_text="Number of links removed")
    removed_platforms = serializers.ListField(
        child=serializers.CharField(),
        read_only=True,
        help_text="List of platforms that were removed"
    )


class BranchAttributeSerializer(serializers.ModelSerializer):
    class Meta:
        model = BranchAttribute
        fields = ['id', 'name']


class BusinessProfileHomePageSerializer(serializers.ModelSerializer):
    """
    Serializer for business profile home page data.
    Returns all necessary information for the frontend home page.
    """
    business_name = serializers.CharField(source='user.business_name', read_only=True)
    social_links = SocialMediaLinkSerializer(many=True, read_only=True)
    categories = BusinessCategorySerializer(many=True, read_only=True)
    headquarter_attributes = serializers.SerializerMethodField()
    profile_image = serializers.SerializerMethodField()

    class Meta:
        model = BusinessProfile
        fields = [
            'business_name',
            'social_links', 
            'description',
            'categories',
            'profile_image',
            'headquarter_attributes'
        ]
    
    def get_headquarter_attributes(self, obj):
        """
        Get attributes from the headquarter branch (is_headquarter=True).
        """
        try:
            headquarter_branch = obj.branches.filter(is_headquarter=True).first()
            if headquarter_branch:
                return BranchAttributeSerializer(headquarter_branch.attributes.all(), many=True).data
            return []
        except Exception:
            return []

    def get_profile_image(self, obj):
        request = self.context.get('request')
        profile_image = obj.profile_image
        if profile_image and request:
            return request.build_absolute_uri(profile_image.url)
        elif profile_image:
            return profile_image.url
        return None


class BusinessProfileUpdateSerializer(serializers.Serializer):
    """
    Serializer for updating business profile description and/or headquarter attributes.
    At least one field must be provided.
    """
    description = serializers.CharField(
        required=False,
        allow_blank=True,
        max_length=100,
        help_text="Business profile description"
    )
    headquarter_attributes = serializers.ListField(
        child=serializers.IntegerField(),
        required=False,
        allow_empty=True,
        help_text="List of attribute IDs for the headquarter branch"
    )
    
    def validate(self, data):
        """
        Validate that at least one field is provided.
        """
        if not data.get('description') and 'headquarter_attributes' not in data:
            raise serializers.ValidationError(
                "At least one field must be provided: 'description' or 'headquarter_attributes'"
            )
        
        # Validate that all attribute IDs exist
        if 'headquarter_attributes' in data:
            attribute_ids = data['headquarter_attributes']
            if attribute_ids:  # Only validate if not empty
                existing_ids = set(BranchAttribute.objects.filter(
                    id__in=attribute_ids
                ).values_list('id', flat=True))
                invalid_ids = set(attribute_ids) - existing_ids
                if invalid_ids:
                    raise serializers.ValidationError({
                        'headquarter_attributes': f'Invalid attribute IDs: {list(invalid_ids)}'
                    })
        
        return data


class BusinessProfileUpdateResponseSerializer(serializers.Serializer):
    """
    Serializer for the business profile update response.
    """
    message = serializers.CharField(read_only=True, help_text="Success message")
    updated_fields = serializers.ListField(
        child=serializers.CharField(),
        read_only=True,
        help_text="List of fields that were updated"
    )
    business_profile = BusinessProfileHomePageSerializer(read_only=True, help_text="Updated business profile data")


class BusinessProfileImageSerializer(serializers.ModelSerializer):
    profile_image_display = serializers.ImageField(source='profile_image', read_only=True)
    profile_image = serializers.ImageField(
        validators=[validate_image_size, validate_image_extension],
        write_only=True
    )

    class Meta:
        model = BusinessProfile
        fields = ['profile_image', 'profile_image_display']


class AccountInfoSerializer(serializers.Serializer):
    # User fields
    business_name = serializers.CharField(allow_null=True)
    email = serializers.EmailField(allow_null=True)
    phone_number = serializers.CharField(allow_null=True, allow_blank=True)

    # BusinessProfile flat fields
    business_id = serializers.CharField(allow_null=True)
    business_type = serializers.CharField(allow_null=True)
    exchange_rate = serializers.DecimalField(max_digits=10, decimal_places=2, allow_null=True)

    # City + Country flattened
    city_id = serializers.IntegerField(allow_null=True)
    city_name = serializers.CharField(allow_null=True)
    country_id = serializers.IntegerField(allow_null=True)
    country_name = serializers.CharField(allow_null=True)

    # Primary currency
    primary_currency_id = serializers.IntegerField(allow_null=True)
    primary_currency_name = serializers.CharField(allow_null=True)
    primary_currency_code = serializers.CharField(allow_null=True)

    # Secondary currency
    secondary_currency_id = serializers.IntegerField(allow_null=True)
    secondary_currency_name = serializers.CharField(allow_null=True)
    secondary_currency_code = serializers.CharField(allow_null=True)

    is_primary_to_secondary = serializers.BooleanField(allow_null=True)

    # Categories list
    categories = BusinessCategorySerializer(many=True, read_only=True)

    def to_representation(self, instance):
        # If instance is a dict (as used in views), use default
        if isinstance(instance, dict):
            return super().to_representation(instance)

        # If instance is a User or BusinessProfile, build same dict as view expects
        return super().to_representation(instance)


class AccountInfoUpdateSerializer(serializers.Serializer):
    # User fields
    business_name = serializers.CharField(required=False)
    email = serializers.EmailField(required=False)
    phone_number = serializers.CharField(required=False, allow_blank=True)

    # BusinessProfile flat fields
    business_id = serializers.CharField(required=False)
    business_type = serializers.ChoiceField(
        choices=BusinessProfile.BUSINESS_TYPE_CHOICES,
        required=False
    )
    exchange_rate = serializers.DecimalField(max_digits=10, decimal_places=2, required=False)
    is_primary_to_secondary = serializers.BooleanField(required=False)

    # City + Currencies as PK related fields (DRF validates existence)
    # `source` is redundant when it matches the field name and causes an assertion
    # in recent DRF versions when generating schema. Remove it to avoid errors
    # while keeping the same validation behaviour.
    city = serializers.PrimaryKeyRelatedField(queryset=City.objects.all(), required=False)
    primary_currency = serializers.PrimaryKeyRelatedField(queryset=Currency.objects.all(), required=False)
    secondary_currency = serializers.PrimaryKeyRelatedField(queryset=Currency.objects.all(), required=False, allow_null=True)

    # Categories: list of IDs
    categories = serializers.PrimaryKeyRelatedField(queryset=BusinessCategory.objects.all(), many=True, required=False)

    def update(self, instance: BusinessProfile, validated_data):
        """Update BusinessProfile instance and related User fields.

        `instance` is the BusinessProfile for request.user. User is provided via context['user'].
        """
        user = self.context.get('user')

        # Update user fields
        business_name = validated_data.pop('business_name', None)
        email = validated_data.pop('email', None)
        phone_number = validated_data.pop('phone_number', None)

        user_changed = False
        if business_name is not None:
            user.business_name = business_name
            user_changed = True
        if email is not None:
            user.email = email
            user_changed = True
        if phone_number is not None:
            user.phone_number = phone_number
            user_changed = True
        if user_changed:
            user.save()

        # Handle categories separately
        categories = validated_data.pop('categories', None)

        # Set remaining fields on BusinessProfile
        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        instance.save()

        if categories is not None:
            instance.categories.set(categories)

        return instance
