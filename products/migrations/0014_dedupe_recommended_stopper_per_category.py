from django.db import migrations


def dedupe_recommended_stopper(apps, schema_editor):
    """Clear 'stopper' on all but the most recently created RECOMMENDED product
    per category, so the following migration's unique constraint can be
    added safely regardless of what duplicates already exist in this
    environment's data (the app never enforced this rule before)."""
    Product = apps.get_model('products', 'Product')

    category_ids = (
        Product.objects.filter(stopper='RECOMMENDED', category__isnull=False)
        .values_list('category_id', flat=True)
        .distinct()
    )
    for category_id in category_ids:
        qs = Product.objects.filter(category_id=category_id, stopper='RECOMMENDED').order_by('-id')
        keep_id = qs.first().id
        qs.exclude(pk=keep_id).update(stopper=None)


class Migration(migrations.Migration):

    dependencies = [
        ('products', '0013_alter_product_discount_percentage_and_more'),
    ]

    operations = [
        migrations.RunPython(dedupe_recommended_stopper, migrations.RunPython.noop),
    ]
