from django.conf.urls import include, url

from .views import proxy_view

urlpatterns = [
	url(r'^(?P<url>.*)$', proxy_view, name='proxy')
]
