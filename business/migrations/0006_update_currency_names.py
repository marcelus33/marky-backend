from django.db import migrations


def update_currency_names(apps, schema_editor):
    Currency = apps.get_model('business', 'Currency')
    names = {
        'PYG': 'Guaraní Paraguayo',
        'VES': 'Bolívar Venezolano',
    }
    for code, name in names.items():
        Currency.objects.filter(code=code).update(name=name)


class Migration(migrations.Migration):

    dependencies = [
        ('business', '0005_populate_branch_attributes'),
    ]

    operations = [
        migrations.RunPython(update_currency_names, migrations.RunPython.noop),
    ]
