# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from django.urls import path, re_path
from apps.home import views

# app_name='index'
urlpatterns = [
    # The home page
    path('', views.index, name='index'),
    path('demo', views.demo, name='demo'),

    # Matches any html file
    re_path(r'^.*\.*', views.pages, name='pages'),

]
