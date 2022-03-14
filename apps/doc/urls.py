from django.conf.urls import include, url
from django.urls import path

from apps.doc import views

urlpatterns = [
	path('', views.doc, name='doc'),
]
