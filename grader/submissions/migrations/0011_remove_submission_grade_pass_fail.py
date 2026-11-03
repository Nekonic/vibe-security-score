from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('submissions', '0010_submission_prompt_efficiency'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='submission',
            name='grade',
        ),
        migrations.RemoveField(
            model_name='submission',
            name='pass_fail',
        ),
    ]
