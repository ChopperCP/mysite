from django.http import JsonResponse, HttpResponse
from django.shortcuts import render
from django.core import serializers

# Create your views here.
from apps.home.models import HashResult, EncodeDecodeResult
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

	if 'has_hash_result' not in context or context['has_hash_result'] == False:
		return JsonResponse({}, json_dumps_params={'ensure_ascii': False})

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
