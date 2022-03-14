# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from django.urls import path, re_path
from apps.api import views

# app_name='index'
urlpatterns = [
    path('hash', views.hash, name='hash'),
    path('encode_decode', views.encode_decode, name='encode_decode'),
    path('gen_rsa_key', views.gen_rsa_key, name='gen_rsa_key'),
    path('ip_lookup', views.ip_lookup, name='ip_lookup'),
]
