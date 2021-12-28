# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from django.apps import AppConfig


class HomeConfig(AppConfig):
    name = 'apps.home'
    label = 'apps_home'

class HashConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.home.hash'
    label = 'apps_home_hash'