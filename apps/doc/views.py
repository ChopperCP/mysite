import os

from django.http import HttpResponse
from django.shortcuts import render
from django.template import loader


# Create your views here.
def doc(request):
	html_template = loader.get_template('doc/doc.html')
	markdowntext = open('README.md','r+',encoding='utf8').read()
	context = {'markdowntext': markdowntext}
	return HttpResponse(html_template.render(context, request))
