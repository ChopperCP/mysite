# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""
import logging
import re

from django import template
from django.contrib.auth.decorators import login_required
from django.core.files.base import ContentFile
from django.http import HttpResponse, HttpResponseRedirect
from django.template import loader
from django.urls import reverse

from apps.home.models import RSAKeyPair
from apps.home import process


def index(request):
	html_template = loader.get_template('home/index.html')
	context = {}
	context['active_nav'] = 1  # by default, the first page is active
	context['has_hash_result'] = False
	context['has_rsa_key_result'] = False

	if len(request.POST) == 0:
		context['is_fresh'] = True  # whether to load preloader

	try:
		# Hash
		if 'hash_input' in request.POST and "hash_action" in request.POST and request.POST[
			"hash_action"] == 'Get Hash Result':
			context.update(process.hash(request))

		# Hash Reverse Lookup
		if 'hash_input' in request.POST and "hash_action" in request.POST and request.POST[
			"hash_action"] == 'Reverse Lookup':
			context.update(process.hash_reverse_lookup(request))

		# Encode/Decode
		if 'encode_or_decode' in request.POST:
			context.update(process.encode_decode(request))

		# Generate a RSA key
		if 'gen_rsa_key' in request.POST:
			context['active_nav'] = 3
			context['rsa_key_pair'] = RSAKeyPair.gen_rsa_keypair()
			context['has_rsa_key_result'] = True

			response = HttpResponse(html_template.render(context, request))
			response.set_cookie('rsa_key_file', context['rsa_key_pair'].to_pri_pem_bytes().decode(
				'utf8'), max_age=300)  # key data will never enter a database
			return response

		# Download RSA key file (PEM format)
		if 'download_rsa_key_file' in request.POST:
			file_to_send = ContentFile(request.COOKIES['rsa_key_file'])
			response = HttpResponse(file_to_send, 'application/x-gzip')
			response['Content-Length'] = file_to_send.size
			response['Content-Disposition'] = 'attachment; filename="key.pem"'
			return response

		# IP to domain lookup
		if 'ip' in request.POST and len(request.POST['ip']) != 0:
			context.update(process.ip_lookup(request))

		return HttpResponse(html_template.render(context, request))

	except process.InputException as e:
		context.update(e.context)
		return HttpResponse(html_template.render(context, request))


# @login_required(login_url="/login/")
def demo(request):
	context = {'segment': 'index'}

	html_template = loader.get_template('home/demo.html')
	return HttpResponse(html_template.render(context, request))


# @login_required(login_url="/login/")
def pages(request):
	context = {}
	# All resource paths end in .html.
	# Pick out the html file name from the url. And load that template.
	try:

		load_template = request.path.split('/')[-1]

		if load_template == 'admin':
			return HttpResponseRedirect(reverse('admin:index'))
		context['segment'] = load_template

		html_template = loader.get_template('home/' + load_template)
		return HttpResponse(html_template.render(context, request))

	except template.TemplateDoesNotExist:

		html_template = loader.get_template('home/page-404.html')
		return HttpResponse(html_template.render(context, request))

	except:
		html_template = loader.get_template('home/page-500.html')
		return HttpResponse(html_template.render(context, request))
