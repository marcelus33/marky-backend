from cities_light.models import City, Country
from drf_spectacular.utils import extend_schema, OpenApiParameter
from rest_framework import generics, filters
from rest_framework import mixins, viewsets
from rest_framework import status
from rest_framework.exceptions import NotFound
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser
from django.db import transaction

from business.models import BusinessCategory, Currency, BusinessProfile, SocialMediaLink, BranchAttribute
from business.serializers import BusinessCategorySerializer, CurrencySerializer, CitySerializer, CountrySerializer, \
    BusinessProfileWriteSerializer, BusinessProfileListSerializer, BusinessProfileDetailSerializer, SocialMediaLinkSerializer, \
    SocialMediaLinkBulkUpdateSerializer, SocialMediaLinkBulkUpdateResponseSerializer, BusinessProfileHomePageSerializer, \
    BusinessProfileUpdateSerializer, BusinessProfileUpdateResponseSerializer, BranchAttributeSerializer, \
    BusinessProfileImageSerializer
from utils.permissions import IsBusinessOrSuperAdmin
from .models import BusinessProfile


@extend_schema(tags=['Business'])
class BusinessProfileViewSet(mixins.CreateModelMixin,
                             mixins.RetrieveModelMixin,
                             mixins.UpdateModelMixin,
                             viewsets.GenericViewSet):
    permission_classes = [IsBusinessOrSuperAdmin]
    queryset = BusinessProfile.objects.all()
    serializer_class = BusinessProfileWriteSerializer

    def get_serializer_class(self):
        if self.action == "list":
            return BusinessProfileListSerializer
        elif self.action == "retrieve":
            return BusinessProfileDetailSerializer
        elif self.action in ["create", "update", "partial_update"]:
            return BusinessProfileWriteSerializer
        return BusinessProfileWriteSerializer

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


@extend_schema(tags=['Business'])
class BranchAttributeListView(generics.ListAPIView):
    permission_classes = [IsBusinessOrSuperAdmin]
    queryset = BranchAttribute.objects.all()
    serializer_class = BranchAttributeSerializer
    filter_backends = [filters.SearchFilter]
    search_fields = ['name']


@extend_schema(tags=['Business'])
class BusinessCategoryListView(generics.ListAPIView):
    permission_classes = [IsBusinessOrSuperAdmin]
    queryset = BusinessCategory.objects.all()
    serializer_class = BusinessCategorySerializer
    filter_backends = [filters.SearchFilter]
    search_fields = ['name']


@extend_schema(tags=['Business'])
class CurrencyListView(generics.ListAPIView):
    permission_classes = [IsBusinessOrSuperAdmin]
    queryset = Currency.objects.all()
    serializer_class = CurrencySerializer


@extend_schema(tags=['Cities'], parameters=[
    OpenApiParameter('country_id', type=int, description='Country ID')
])
class CityListView(generics.ListAPIView):
    permission_classes = [IsBusinessOrSuperAdmin]
    queryset = City.objects.all()
    serializer_class = CitySerializer

    def get_queryset(self):
        country_id = self.request.query_params.get('country_id', None)
        ALLOWED_CITIES = ["Asunción", "Caracas"]

        if country_id:
            cities = City.objects.filter(country_id=country_id, name__in=ALLOWED_CITIES)

            if not cities.exists():
                raise NotFound('No se encontraron ciudades.')

            return cities
        else:
            return City.objects.all()


@extend_schema(tags=['Cities'])
class CountryListView(generics.ListAPIView):
    permission_classes = [IsBusinessOrSuperAdmin]
    queryset = Country.objects.all()
    serializer_class = CountrySerializer


class ValidateBusinessNameView(APIView):
    """
    API view to validate if a business name is already taken.
    It expects a query parameter 'business_name' and returns:
      { "is_taken": true/false }
    """

    def get(self, request, format=None):
        business_id = request.query_params.get("business_id", None)
        if not business_id:
            return Response(
                {"error": "No se encontró nombre a validar."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Check if a BusinessProfile with the given business_id (business name) exists.
        # Using iexact makes the check case-insensitive.
        exists = BusinessProfile.objects.filter(business_id__iexact=business_id).exists()
        return Response({"is_taken": exists}, status=status.HTTP_200_OK)


@extend_schema(tags=['Business'])
class SocialMediaLinkViewSet(mixins.RetrieveModelMixin,
                             mixins.ListModelMixin,
                             viewsets.GenericViewSet):
    """
    ViewSet for managing social media links for a business.
    Supports retrieving and listing social media links.
    Use the bulk update endpoint for creating/updating/deleting links.
    """
    permission_classes = [IsBusinessOrSuperAdmin]
    serializer_class = SocialMediaLinkSerializer
    
    def get_queryset(self):
        """
        Filter social media links by the business profile of the authenticated user.
        """
        try:
            business_profile = self.request.user.business_profile
            return SocialMediaLink.objects.filter(business=business_profile)
        except BusinessProfile.DoesNotExist:
            return SocialMediaLink.objects.none()


@extend_schema(
    tags=['Business'],
    summary="Bulk update social media links (Atomic)",
    description="""
    Bulk update endpoint for social media links.
    
    **Atomic Operation:** All changes are applied together or none at all. If any validation fails, 
    the entire operation is rolled back and no changes are made.
    
    **Behavior:**
    - Creates new links for platforms that don't exist
    - Updates existing links for platforms that are present  
    - Removes links for platforms that are not present in the request
    
    **Supported platforms:** facebook, instagram, whatsapp, website
    
    **Example request:**
    ```json
    {
        "instagram": "https://www.instagram.com/example",
        "facebook": "https://www.facebook.com/example", 
        "whatsapp": "595982590021",
        "website": "https://www.example.com"
    }
    ```
    """,
    request=SocialMediaLinkBulkUpdateSerializer,
    responses={
        200: SocialMediaLinkBulkUpdateResponseSerializer,
        400: {"description": "Bad request - invalid data, validation error, or missing business profile"}
    }
)
class SocialMediaLinkBulkUpdateView(APIView):
    """
    Bulk update endpoint for social media links.
    """
    permission_classes = [IsBusinessOrSuperAdmin]
    
    @extend_schema(
        request=SocialMediaLinkBulkUpdateSerializer,
        responses={
            200: SocialMediaLinkBulkUpdateResponseSerializer,
            400: {"description": "Bad request - invalid data, validation error, or missing business profile"}
        }
    )
    def post(self, request, *args, **kwargs):
        """
        Bulk update social media links for the business.
        All operations are atomic - if any operation fails, all changes are rolled back.
        """
        try:
            business_profile = request.user.business_profile
        except BusinessProfile.DoesNotExist:
            return Response(
                {"error": "No business profile found for this user."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Validate request data using serializer
        serializer = SocialMediaLinkBulkUpdateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        validated_data = serializer.validated_data
        
        try:
            with transaction.atomic():
                # Get current social media links for this business
                current_links = SocialMediaLink.objects.filter(business=business_profile)
                current_platforms = {link.platform: link for link in current_links}
                
                # Platforms present in the request
                request_platforms = set(validated_data.keys())
                
                # Platforms to remove (present in DB but not in request)
                platforms_to_remove = set(current_platforms.keys()) - request_platforms
                
                # Validate all operations first before making any changes
                links_to_update = []
                links_to_create = []
                
                for platform, url in validated_data.items():
                    if platform in current_platforms:
                        # Prepare update
                        link = current_platforms[platform]
                        link.url = url
                        link.full_clean()  # Validate the model - will raise exception if invalid
                        links_to_update.append(link)
                    else:
                        # Prepare creation - validate first
                        temp_link = SocialMediaLink(
                            business=business_profile,
                            platform=platform,
                            url=url
                        )
                        temp_link.full_clean()  # Validate the model - will raise exception if invalid
                        links_to_create.append((platform, url))
                
                # If we get here, all validations passed, now perform the actual operations
                
                # Remove links not present in request
                removed_count = 0
                if platforms_to_remove:
                    removed_count = SocialMediaLink.objects.filter(
                        business=business_profile,
                        platform__in=platforms_to_remove
                    ).delete()[0]
                
                # Update existing links
                updated_links = []
                for link in links_to_update:
                    link.save()
                    updated_links.append(link)
                
                # Create new links
                created_links = []
                for platform, url in links_to_create:
                    link = SocialMediaLink.objects.create(
                        business=business_profile,
                        platform=platform,
                        url=url
                    )
                    created_links.append(link)
                
                # Prepare response
                response_serializer = SocialMediaLinkSerializer(
                    updated_links + created_links, 
                    many=True
                )
                
                response_data = {
                    "social_links": response_serializer.data,
                    "created": len(created_links),
                    "updated": len(updated_links),
                    "removed": removed_count,
                    "removed_platforms": list(platforms_to_remove)
                }
                
                return Response(response_data, status=status.HTTP_200_OK)
                
        except Exception as e:
            # Any error will cause the entire transaction to be rolled back
            return Response(
                {"error": f"Failed to update social media links: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )


@extend_schema(
    tags=['Business'],
    summary="Get business profile home page data",
    description="""
    Get all necessary business profile information for the frontend home page.
    
    **Returns:**
    - Business name (from user model)
    - All social media links/channels
    - Business description
    - Business categories
    - Profile image
    - Attributes from the headquarter branch (is_headquarter=True)
    
    This endpoint provides all the data needed to display a business profile on the home page.
    """,
    responses={
        200: BusinessProfileHomePageSerializer,
        400: {"description": "Bad request - missing business profile"}
    }
)
class BusinessProfileHomePageView(APIView):
    """
    Get business profile data for home page display.
    """
    permission_classes = [IsBusinessOrSuperAdmin]
    
    def get(self, request, *args, **kwargs):
        """
        Get business profile home page data for the authenticated user.
        """
        try:
            business_profile = request.user.business_profile
        except BusinessProfile.DoesNotExist:
            return Response(
                {"error": "No business profile found for this user."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Use select_related and prefetch_related for optimal database queries
        business_profile = BusinessProfile.objects.select_related('user').prefetch_related(
            'social_links',
            'categories',
            'branches__attributes'
        ).get(id=business_profile.id)
        
        serializer = BusinessProfileHomePageSerializer(business_profile)
        return Response(serializer.data, status=status.HTTP_200_OK)


@extend_schema(
    tags=['Business'],
    summary="Update business profile description and/or headquarter attributes",
    description="""
    Update business profile description and/or headquarter branch attributes.
    
    **Flexible Update:** You can update either field independently or both together.
    At least one field must be provided in the request.
    
    **Fields:**
    - `description`: Business profile description (optional)
    - `headquarter_attributes`: List of attribute IDs for the headquarter branch (optional)
    
    **Example requests:**
    
    Update only description:
    ```json
    {
        "description": "New business description"
    }
    ```
    
    Update only headquarter attributes:
    ```json
    {
        "headquarter_attributes": [1, 2, 3]
    }
    ```
    
    Update both:
    ```json
    {
        "description": "New business description",
        "headquarter_attributes": [1, 2, 3]
    }
    ```
    """,
    request=BusinessProfileUpdateSerializer,
    responses={
        200: BusinessProfileUpdateResponseSerializer,
        400: {"description": "Bad request - invalid data, validation error, or missing business profile"}
    }
)
class BusinessProfileUpdateView(APIView):
    """
    Update business profile description and/or headquarter attributes.
    """
    permission_classes = [IsBusinessOrSuperAdmin]
    
    def patch(self, request, *args, **kwargs):
        """
        Update business profile description and/or headquarter attributes.
        All operations are atomic - if any operation fails, all changes are rolled back.
        """
        try:
            business_profile = request.user.business_profile
        except BusinessProfile.DoesNotExist:
            return Response(
                {"error": "No business profile found for this user."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Validate request data using serializer
        serializer = BusinessProfileUpdateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        validated_data = serializer.validated_data
        updated_fields = []
        
        try:
            with transaction.atomic():
                # Update description if provided
                if 'description' in validated_data:
                    business_profile.description = validated_data['description']
                    business_profile.save()
                    updated_fields.append('description')
                
                # Update headquarter attributes if provided
                if 'headquarter_attributes' in validated_data:
                    # Get or create headquarter branch
                    headquarter_branch, created = business_profile.branches.get_or_create(
                        is_headquarter=True,
                        defaults={
                            'name': 'Casa Matriz',
                            'address': 'Dirección principal'
                        }
                    )
                    
                    # Update attributes
                    attribute_ids = validated_data['headquarter_attributes']
                    if attribute_ids:
                        # Set the new attributes
                        headquarter_branch.attributes.set(attribute_ids)
                    else:
                        # Clear all attributes if empty list provided
                        headquarter_branch.attributes.clear()
                    
                    updated_fields.append('headquarter_attributes')
                
                # Get updated business profile with all related data
                updated_business_profile = BusinessProfile.objects.select_related('user').prefetch_related(
                    'social_links',
                    'categories',
                    'branches__attributes'
                ).get(id=business_profile.id)
                
                # Prepare response
                response_data = {
                    "message": "Business profile updated successfully",
                    "updated_fields": updated_fields,
                    "business_profile": BusinessProfileHomePageSerializer(updated_business_profile).data
                }
                
                return Response(response_data, status=status.HTTP_200_OK)
                
        except Exception as e:
            # Any error will cause the entire transaction to be rolled back
            return Response(
                {"error": f"Failed to update business profile: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )


class BusinessProfileImageView(APIView):
    """
    Upload or update business profile image.
    """
    permission_classes = [IsBusinessOrSuperAdmin]
    parser_classes = (MultiPartParser, FormParser)
    
    @extend_schema(
        tags=['Business'],
        summary="Upload or update business profile image",
        description="""
        Upload or update the business profile image.
        
        **Request:**
        - `profile_image`: The image file to upload.
        
        **Validation:**
        - Max file size: 2MB
        - Allowed extensions: .jpg, .jpeg, .png, .gif
        """,
        request={
            'multipart/form-data': {
                'type': 'object',
                'properties': {
                    'profile_image': {
                        'type': 'string',
                        'format': 'binary'
                    }
                }
            }
        },
        responses={
            200: BusinessProfileImageSerializer,
            400: {"description": "Bad request - invalid data, validation error, or missing business profile"}
        }
    )
    def patch(self, request, *args, **kwargs):
        """
        Update business profile image.
        """
        try:
            business_profile = request.user.business_profile
        except BusinessProfile.DoesNotExist:
            return Response(
                {"error": "No business profile found for this user."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        serializer = BusinessProfileImageSerializer(
            instance=business_profile,
            data=request.data,
            partial=True
        )
        
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
