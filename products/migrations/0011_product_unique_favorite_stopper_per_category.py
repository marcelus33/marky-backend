from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('business', '0006_update_currency_names'),
        ('products', '0010_dedupe_favorite_stopper_per_category'),
    ]

    operations = [
        migrations.AddConstraint(
            model_name='product',
            constraint=models.UniqueConstraint(condition=models.Q(('stopper', 'FAVORITE')), fields=('category',), name='unique_favorite_stopper_per_category'),
        ),
    ]
