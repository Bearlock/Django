# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import datetime
from django.utils.timezone import utc


class Migration(migrations.Migration):

    dependencies = [
        ('blog', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='post',
            name='post_slug',
            field=models.SlugField(default=datetime.datetime(2015, 6, 2, 20, 27, 32, 184989, tzinfo=utc)),
            preserve_default=False,
        ),
    ]
