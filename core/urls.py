# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from django.contrib import admin
from django.urls import path, include  # add this

urlpatterns = [
	path('admin/', admin.site.urls),  # Django admin route
	path("api/", include("apps.api.urls")),  # API support
	path("proxy/", include("apps.proxy.urls")),  # HTTP proxy
	path("doc/", include("apps.doc.urls")),  # Documentation for API
	path("login/", include("apps.authentication.urls")),  # Auth routes - login / register
	path("", include("apps.home.urls")),  # UI Kits Html files
]
