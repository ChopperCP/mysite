# Generated by Django 3.2.10 on 2022-02-26 09:05

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('apps_home', '0003_alter_hashresult_plaintext'),
    ]

    operations = [
        migrations.AlterField(
            model_name='hashresult',
            name='plaintext',
            field=models.TextField(db_index=True, max_length=10000),
        ),
    ]
