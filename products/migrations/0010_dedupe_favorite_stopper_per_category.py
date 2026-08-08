from django.db import migrations


def dedupe_favorite_stopper(apps, schema_editor):
    """Clear 'stopper' on all but the most recently created FAVORITE product
    per category, so the following migration's unique constraint can be
    added safely regardless of what duplicates already exist in this
    environment's data (the app never enforced this rule before)."""
    Product = apps.get_model('products', 'Product')

    category_ids = (
        Product.objects.filter(stopper='FAVORITE', category__isnull=False)
        .values_list('category_id', flat=True)
        .distinct()
    )
    for category_id in category_ids:
        qs = Product.objects.filter(category_id=category_id, stopper='FAVORITE').order_by('-id')
        keep_id = qs.first().id
        qs.exclude(pk=keep_id).update(stopper=None)


class Migration(migrations.Migration):

    dependencies = [
        ('products', '0009_productcategory_is_available'),
    ]

    operations = [
        migrations.RunPython(dedupe_favorite_stopper, migrations.RunPython.noop),
    ]
