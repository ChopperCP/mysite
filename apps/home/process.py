# speration of duty on homepage
import logging
import re
from typing import Dict

from apps.home.models import HashResult, EncodeDecodeResult, IPLookupResult
from apps.utils.consts import *


class InputException(Exception):
	def __init__(self, context: Dict):
		self.context = context


def hash(request) -> Dict:
	context = {}
	context['active_nav'] = 1
	hash_input = request.POST['hash_input']
	if len(hash_input) > INPUT_MAX_LEN:
		context['is_bad_input'] = True
		context['error_str'] = "Input too long"
		raise InputException(context)

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
	return context


def hash_reverse_lookup(request) -> Dict:
	context = {}
	context['active_nav'] = 1
	hash_input = request.POST['hash_input']
	if len(hash_input) > INPUT_MAX_LEN:
		context['is_bad_input'] = True
		context['error_str'] = "Input too long"
		raise InputException(context)

	query_set = HashResult.objects.filter(result_hex=hash_input)
	context['reverse_hash_result'] = [result.plaintext for result in query_set]
	context['has_reverse_hash_result'] = False if len(context['reverse_hash_result']) == 0 else True
	return context


def encode_decode(request) -> Dict:
	context = {}
	context['active_nav'] = 2
	encode_or_decode = request.POST['encode_or_decode']

	# check encode_or_decode POST param
	if encode_or_decode == "" or encode_or_decode == "Choose Encode/Decode":
		context['is_bad_input'] = True
		context['error_str'] = "Please choose Encode/Decode"
		raise InputException(context)
	# if is_api:
	# 	return context
	# return HttpResponse(html_template.render(context, request))
	elif encode_or_decode == 'Encode':
		is_encode = True
	elif encode_or_decode == 'Decode':
		is_encode = False
	else:
		context['is_bad_input'] = True
		raise InputException(context)
	# if is_api:
	# 	return context
	# return HttpResponse(html_template.render(context, request))
	context['is_encode'] = is_encode

	# check encode_decode_input POST param
	if 'encode_decode_input' in request.POST:
		encode_decode_input = request.POST['encode_decode_input']
		if encode_decode_input == "":
			raise InputException(context)
		if len(encode_decode_input) > INPUT_MAX_LEN:
			context['is_bad_input'] = True
			context['error_str'] = "Input too long"
			raise InputException(context)
		encode_decode_input_bytes = encode_decode_input.encode('utf8')
	else:
		context['is_bad_input'] = True
		raise InputException(context)

	# check encode_decode_algorithm POST param
	if 'encode_decode_algorithm' not in request.POST:
		context['is_bad_input'] = True
		raise InputException(context)
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
				raise InputException(context)
		except Exception as e:
			logging.error(e)
			context['is_bad_input'] = True
			raise InputException(context)
	return context


def ip_lookup(request) -> Dict:
	context = {}
	context['active_nav'] = 4
	ip = request.POST['ip']
	re_result = re.search(r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
	                      ip)
	if re_result is None or re_result.group() != ip:
		context['is_bad_input'] = True
		context['error_str'] = "Invalid IP"
		raise InputException(context)
	context['ip_to_domain_result'] = IPLookupResult.get_ip_lookup_result(ip).domains.split('\n')
	context['has_ip_to_domain_result'] = True if len(context['ip_to_domain_result']) != 0 else False
	return context