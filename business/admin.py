from django.contrib import admin
from .models import BusinessCategory, Currency, BusinessProfile


@admin.register(BusinessCategory)
class BusinessCategoryAdmin(admin.ModelAdmin):
    list_display = ('id', 'name',)
    search_fields = ('name',)


@admin.register(Currency)
class CurrencyAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'code')
    search_fields = ('name', 'code')


@admin.register(BusinessProfile)
class BusinessProfileAdmin(admin.ModelAdmin):
    list_display = ('id', 'business_id', 'user', 'city',)
    search_fields = ('business_id', 'user__username', 'city__name', )
    list_filter = ('city', )

