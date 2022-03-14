import json

from django.http import JsonResponse, HttpResponse
from django.shortcuts import render
from django.core import serializers

# Create your views here.
from apps.home.models import HashResult, EncodeDecodeResult, RSAKeyPair
from apps.home.views import index
from django.views.decorators.csrf import csrf_exempt

# overwrite the default get_dump_object method to get rid of metadata
from django.core.serializers.json import Serializer as Builtin_Serializer


class Serializer(Builtin_Serializer):
	def get_dump_object(self, obj):
		# only return the fields
		return self._current


@csrf_exempt
def hash(request):
	context = index(request, is_api=True)

	if not context['has_hash_result'] and not context['has_reverse_hash_result']:
		return JsonResponse({}, json_dumps_params={'ensure_ascii': False})

	if 'has_reverse_hash_result' in context and context['has_reverse_hash_result']:
		return JsonResponse({'reverse_hash_result': context['reverse_hash_result']},
		                    json_dumps_params={'ensure_ascii': False})

	results = []
	for value in context.values():
		if isinstance(value, HashResult):
			serializer = Serializer()
			serialized = serializer.serialize((value,))
			results.append(serialized)

	return HttpResponse(results)


@csrf_exempt
def encode_decode(request):
	context = index(request, is_api=True)

	for value in context.values():
		if isinstance(value, EncodeDecodeResult):
			serializer = Serializer()
			serialized = serializer.serialize((value,))
			return HttpResponse(serialized)


@csrf_exempt
def gen_rsa_key(request):
	context = {}
	serializer = Serializer()
	key_pair_obj=RSAKeyPair.gen_rsa_keypair()
	context['rsa_key_pair'] = json.loads(serializer.serialize((key_pair_obj,)))[0]
	context['has_rsa_key_result'] = True
	context['rsa_key_file'] = key_pair_obj.to_pri_pem_bytes().decode('utf8')

	return JsonResponse(context)

@csrf_exempt
def ip_lookup(request):
	context = index(request, is_api=True)
	return JsonResponse(context)