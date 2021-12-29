# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from django import template
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseBadRequest
from django.template import loader
from django.urls import reverse
from .models import HashResult, EncodeDecodeResult

import hashlib
import binascii


def index(request):
	html_template = loader.get_template('home/index.html')
	context = {}
	context['active_nav'] = 1  # by default, the first page is active

	if len(request.POST) == 0:
		context['is_fresh'] = True

	# Hash
	if 'hash_input' in request.POST:
		context['active_nav'] = 1
		hash_input = request.POST['hash_input'].encode('utf8')

		context['has_hash_result'] = True
		context['md5_result'] = HashResult.calculate_md5_result(hash_input)
		context['sha1_result'] = HashResult.calculate_sha1_result(hash_input)
		context['sha224_result'] = HashResult.calculate_sha224_result(hash_input)
		context['sha256_result'] = HashResult.calculate_sha256_result(hash_input)
		context['sha384_result'] = HashResult.calculate_sha384_result(hash_input)
		context['sha512_result'] = HashResult.calculate_sha512_result(hash_input)

	# Encode/Decode
	if 'encode_or_decode' in request.POST:
		context['active_nav'] = 2
		encode_or_decode = request.POST['encode_or_decode']

		# check encode_or_decode POST param
		if encode_or_decode == "" or encode_or_decode == "Choose Encode/Decode":
			context['is_bad_input'] = True
			context['error_str'] = "Please choose Encode/Decode"
			return HttpResponse(html_template.render(context, request))
		elif encode_or_decode == 'Encode':
			is_encode = True
		elif encode_or_decode == 'Decode':
			is_encode = False
		else:
			context['is_bad_input'] = True
			return HttpResponse(html_template.render(context, request))
		context['is_encode'] = is_encode

		# check encode_decode_input POST param
		if 'encode_decode_input' in request.POST:
			encode_decode_input = request.POST['encode_decode_input']
			if encode_decode_input == "":
				return HttpResponse(html_template.render(context, request))
			encode_decode_input = encode_decode_input.encode('utf8')
		else:
			context['is_bad_input'] = True
			return HttpResponse(html_template.render(context, request))

		# check encode_decode_algorithm POST param
		if 'encode_decode_algorithm' not in request.POST:
			context['is_bad_input'] = True
			return HttpResponse(html_template.render(context, request))
		else:
			algorithm = request.POST['encode_decode_algorithm']
			# Actual cases
			try:
				if algorithm == 'Base16':
					context['encode_decode_result'] = EncodeDecodeResult.base16(encode_decode_input, is_encode)
				elif algorithm == 'Base32':
					context['encode_decode_result'] = EncodeDecodeResult.base32(encode_decode_input, is_encode)
				elif algorithm == 'Base64':
					context['encode_decode_result'] = EncodeDecodeResult.base64(encode_decode_input, is_encode)
				elif algorithm == 'Base85':
					context['encode_decode_result'] = EncodeDecodeResult.base85(encode_decode_input, is_encode)
				elif algorithm == 'Hex':
					context['encode_decode_result'] = EncodeDecodeResult.hex(encode_decode_input, is_encode)
				elif algorithm == 'URL':
					encode_decode_input = encode_decode_input.decode(
						'utf8')  # We don't need bytes for URL encode/decode
					context['encode_decode_result'] = EncodeDecodeResult.url(encode_decode_input, is_encode)

				else:
					context['is_bad_input'] = True
					context['error_str'] = "No valid Algorithm: {}".format(algorithm)
					return HttpResponse(html_template.render(context, request))
			except:
				context['is_bad_input'] = True
				return HttpResponse(html_template.render(context, request))

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
