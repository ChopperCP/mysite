# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from django.db import models
from django.contrib.auth.models import User

import hashlib
import binascii
import base64


# Create your models here.
class HashResult(models.Model):
	function_name = models.CharField(max_length=50)
	bit_length = models.IntegerField()
	result_base64 = models.CharField(max_length=1024)
	result_hex = models.CharField(max_length=1024)

	def __str__(self):
		return "{}_{}:{}".format(self.function_name, self.bit_length, self.result_base64)

	@staticmethod
	def calculate_md5_result(hash_input: bytes):
		result_base64 = binascii.b2a_base64(hashlib.md5(hash_input).digest()).decode('utf8')
		result_hex = binascii.b2a_hex(hashlib.md5(hash_input).digest()).decode('utf8')
		return HashResult(function_name='MD5', bit_length=128, result_base64=result_base64, result_hex=result_hex)

	@staticmethod
	def calculate_sha1_result(hash_input: bytes):
		result_base64 = binascii.b2a_base64(hashlib.sha1(hash_input).digest()).decode('utf8')
		result_hex = binascii.b2a_hex(hashlib.sha1(hash_input).digest()).decode('utf8')
		return HashResult(function_name='SHA1', bit_length=160, result_base64=result_base64, result_hex=result_hex)

	@staticmethod
	def calculate_sha224_result(hash_input: bytes):
		result_base64 = binascii.b2a_base64(hashlib.sha224(hash_input).digest()).decode('utf8')
		result_hex = binascii.b2a_hex(hashlib.sha224(hash_input).digest()).decode('utf8')
		return HashResult(function_name='SHA2-224', bit_length=224, result_base64=result_base64, result_hex=result_hex)

	@staticmethod
	def calculate_sha256_result(hash_input: bytes):
		result_base64 = binascii.b2a_base64(hashlib.sha256(hash_input).digest()).decode('utf8')
		result_hex = binascii.b2a_hex(hashlib.sha256(hash_input).digest()).decode('utf8')
		return HashResult(function_name='SHA2-256', bit_length=256, result_base64=result_base64, result_hex=result_hex)

	@staticmethod
	def calculate_sha384_result(hash_input: bytes):
		result_base64 = binascii.b2a_base64(hashlib.sha384(hash_input).digest()).decode('utf8')
		result_hex = binascii.b2a_hex(hashlib.sha384(hash_input).digest()).decode('utf8')
		return HashResult(function_name='SHA2-384', bit_length=384, result_base64=result_base64, result_hex=result_hex)

	@staticmethod
	def calculate_sha512_result(hash_input: bytes):
		result_base64 = binascii.b2a_base64(hashlib.sha512(hash_input).digest()).decode('utf8')
		result_hex = binascii.b2a_hex(hashlib.sha512(hash_input).digest()).decode('utf8')
		return HashResult(function_name='SHA2-512', bit_length=512, result_base64=result_base64, result_hex=result_hex)


class EncodeDecodeResult(models.Model):
	algorithm = models.CharField(max_length=50)
	is_encode = models.BooleanField()
	result = models.CharField(max_length=10000)

	def __str__(self):
		return "{}_{}:{}".format(self.algorithm, 'Encode' if self.is_encode else 'Decode',
		                         self.result if len(self.result) <= 10 else self.result[:10])

	# Base
	@staticmethod
	def base16(encode_decode_input: bytes, is_encode):
		if is_encode:
			result = EncodeDecodeResult(algorithm="Base16", is_encode=is_encode,
			                            result=base64.b16encode(encode_decode_input).decode('utf8'))
		else:
			result = EncodeDecodeResult(algorithm="Base16", is_encode=is_encode,
			                            result=base64.b16decode(encode_decode_input).decode('utf8'))

		return result