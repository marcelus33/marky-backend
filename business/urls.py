from django.urls import path, include
from business.views import BusinessCategoryListView, CurrencyListView, CityListView, CountryListView, \
    BusinessProfileViewSet, ValidateBusinessNameView
from rest_framework.routers import DefaultRouter


router = DefaultRouter()
router.register(r'business_profile', BusinessProfileViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('categories/', BusinessCategoryListView.as_view(), name='business-category-list'),
    path('currencies/', CurrencyListView.as_view(), name='currency-list'),
    path('cities/', CityListView.as_view(), name='city-list'),
    path('countries/', CountryListView.as_view(), name='country-list'),
    path('validate-name/', ValidateBusinessNameView.as_view(), name='validate-business-name'),
]