from cities_light.models import City, Country
from drf_spectacular.utils import extend_schema, OpenApiParameter
from rest_framework import generics, filters
from rest_framework import mixins, viewsets
from rest_framework import status
from rest_framework.exceptions import NotFound
from rest_framework.response import Response
from rest_framework.views import APIView

from business.models import BusinessCategory, Currency, BusinessProfile
from business.serializers import BusinessCategorySerializer, CurrencySerializer, CitySerializer, CountrySerializer, \
    BusinessProfileWriteSerializer, BusinessProfileListSerializer, BusinessProfileDetailSerializer
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
