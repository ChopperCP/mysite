# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""
import logging

from django import template
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseBadRequest
from django.template import loader
from django.urls import reverse
from django.core.exceptions import ObjectDoesNotExist

from apps.home.models import HashResult, EncodeDecodeResult
from apps.utils.consts import *

import hashlib
import binascii


def index(request, is_api=False):
	html_template = loader.get_template('home/index.html')
	context = {}
	context['active_nav'] = 1  # by default, the first page is active

	if len(request.POST) == 0:
		context['is_fresh'] = True

	# Hash
	if 'hash_input' in request.POST and "hash_action" in request.POST and request.POST["hash_action"] == 'Get Hash Result':
		context['active_nav'] = 1
		hash_input = request.POST['hash_input']
		if len(hash_input) > INPUT_MAX_LEN:
			context['is_bad_input'] = True
			context['error_str'] = "Input too long"
			return HttpResponse(html_template.render(context, request))

		context['has_hash_result'] = True
		context['md5_result'] = HashResult.calculate_md5_result(hash_input)
		context['sha1_result'] = HashResult.calculate_sha1_result(hash_input)
		context['sha224_result'] = HashResult.calculate_sha224_result(hash_input)
		context['sha256_result'] = HashResult.calculate_sha256_result(hash_input)
		context['sha384_result'] = HashResult.calculate_sha384_result(hash_input)
		context['sha512_result'] = HashResult.calculate_sha512_result(hash_input)

		# if the plaintext does not exist in the DB, save the result to database.
		query_set = HashResult.objects.filter(plaintext=hash_input)
		if len(query_set) == 0:
			context['md5_result'].save()
			context['sha1_result'].save()
			context['sha224_result'].save()
			context['sha256_result'].save()
			context['sha384_result'].save()
			context['sha512_result'].save()


	# Hash Reverse Lookup
	if 'hash_input' in request.POST and "hash_action" in request.POST and request.POST["hash_action"] == 'Reverse Lookup':
		context['active_nav'] = 1
		hash_input = request.POST['hash_input']
		if len(hash_input) > INPUT_MAX_LEN:
			context['is_bad_input'] = True
			context['error_str'] = "Input too long"
			return HttpResponse(html_template.render(context, request))

		query_set = HashResult.objects.filter(result_hex=hash_input)
		context['reverse_hash_result'] = [result.plaintext for result in query_set]
		context['has_reverse_hash_result'] = False if len(context['reverse_hash_result']) == 0 else True

	# Encode/Decode
	if 'encode_or_decode' in request.POST:
		context['active_nav'] = 2
		encode_or_decode = request.POST['encode_or_decode']

		# check encode_or_decode POST param
		if encode_or_decode == "" or encode_or_decode == "Choose Encode/Decode":
			context['is_bad_input'] = True
			context['error_str'] = "Please choose Encode/Decode"
			if is_api:
				return context
			return HttpResponse(html_template.render(context, request))
		elif encode_or_decode == 'Encode':
			is_encode = True
		elif encode_or_decode == 'Decode':
			is_encode = False
		else:
			context['is_bad_input'] = True
			if is_api:
				return context
			return HttpResponse(html_template.render(context, request))
		context['is_encode'] = is_encode

		# check encode_decode_input POST param
		if 'encode_decode_input' in request.POST:
			encode_decode_input = request.POST['encode_decode_input']
			if encode_decode_input == "":
				if is_api:
					return context
				return HttpResponse(html_template.render(context, request))
			if len(encode_decode_input) > INPUT_MAX_LEN:
				context['is_bad_input'] = True
				context['error_str'] = "Input too long"
				if is_api:
					return context
				return HttpResponse(html_template.render(context, request))
			encode_decode_input_bytes = encode_decode_input.encode('utf8')
		else:
			context['is_bad_input'] = True
			if is_api:
				return context
			return HttpResponse(html_template.render(context, request))

		# check encode_decode_algorithm POST param
		if 'encode_decode_algorithm' not in request.POST:
			context['is_bad_input'] = True
			if is_api:
				return context
			return HttpResponse(html_template.render(context, request))
		else:
			algorithm = request.POST['encode_decode_algorithm']
			# Actual cases
			try:
				if algorithm == 'Base16':
					context['encode_decode_result'] = EncodeDecodeResult.base16(encode_decode_input_bytes, is_encode)
				elif algorithm == 'Base32':
					context['encode_decode_result'] = EncodeDecodeResult.base32(encode_decode_input_bytes, is_encode)
				elif algorithm == 'Base64':
					context['encode_decode_result'] = EncodeDecodeResult.base64(encode_decode_input_bytes, is_encode)
				elif algorithm == 'Base85':
					context['encode_decode_result'] = EncodeDecodeResult.base85(encode_decode_input_bytes, is_encode)
				elif algorithm == 'Hex':
					context['encode_decode_result'] = EncodeDecodeResult.hex(encode_decode_input_bytes, is_encode)
				elif algorithm == 'URL':
					context['encode_decode_result'] = EncodeDecodeResult.url(encode_decode_input, is_encode)
				elif algorithm == 'Quoted-printable':
					context['encode_decode_result'] = EncodeDecodeResult.quoted_printable(encode_decode_input_bytes,
					                                                                      is_encode)
				elif algorithm == 'HTML':
					context['encode_decode_result'] = EncodeDecodeResult.html(encode_decode_input_bytes, is_encode)
				elif algorithm == 'UUencode':
					context['encode_decode_result'] = EncodeDecodeResult.uuencode(encode_decode_input_bytes, is_encode)
				elif algorithm == 'XXencode':
					context['encode_decode_result'] = EncodeDecodeResult.xxencode(encode_decode_input_bytes, is_encode)
				elif algorithm == 'AAencode':
					context['encode_decode_result'] = EncodeDecodeResult.aaencode(encode_decode_input, is_encode)
				elif algorithm == 'JJencode':
					context['encode_decode_result'] = EncodeDecodeResult.jjencode(encode_decode_input, is_encode)
				elif algorithm == 'BubbleBabble':
					context['encode_decode_result'] = EncodeDecodeResult.bubblebabble(encode_decode_input, is_encode)
				elif algorithm == 'JSFuck':
					context['encode_decode_result'] = EncodeDecodeResult.jsfuck(encode_decode_input, is_encode)
				elif algorithm == 'Brainfuck':
					context['encode_decode_result'] = EncodeDecodeResult.brainfuck(encode_decode_input, is_encode)
				elif algorithm == '社会主义核心价值观':
					context['encode_decode_result'] = EncodeDecodeResult.corevalue(encode_decode_input, is_encode)
				elif algorithm == 'Punycode':
					context['encode_decode_result'] = EncodeDecodeResult.punycode(encode_decode_input, is_encode)

				else:
					context['is_bad_input'] = True
					context['error_str'] = "No valid Algorithm: {}".format(algorithm)
					if is_api:
						return context
					return HttpResponse(html_template.render(context, request))
			except Exception as e:
				context['is_bad_input'] = True
				logging.error(e)
				if is_api:
					return context
				return HttpResponse(html_template.render(context, request))

	if is_api:
		return context
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
