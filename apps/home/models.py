# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""
from typing import Set

import time
import requests
import hashlib
import binascii
import base64
import urllib.parse
import quopri
import html
import codecs
import re
import sys
import itertools
import string
from pyasn1.codec.der import encoder
from pyasn1.type.univ import Sequence, Integer
from fake_useragent import UserAgent

from django.db import models
from django.contrib.auth.models import User

from apps.utils.consts import *
from apps.utils.int_to_bytes import int_to_bytes
from apps.utils.crypto import generate_prime, invert, PEM_TEMPLATE

ua = UserAgent()


# Create your models here.
class HashResult(models.Model):
	plaintext = models.TextField(max_length=INPUT_MAX_LEN, db_index=True)
	function_name = models.CharField(max_length=50)
	bit_length = models.IntegerField()
	result_base64 = models.CharField(max_length=1024)
	result_hex = models.CharField(max_length=1024, db_index=True)

	def __str__(self):
		return "{}_{}_{}:{}".format(self.function_name, self.bit_length, self.plaintext, self.result_hex)

	@staticmethod
	def calculate_md5_result(hash_input: str):
		plaintext = hash_input
		hash_input = hash_input.encode('utf8')
		result_base64 = binascii.b2a_base64(hashlib.md5(hash_input).digest()).decode('utf8')
		result_hex = binascii.b2a_hex(hashlib.md5(hash_input).digest()).decode('utf8')
		return HashResult(plaintext=plaintext, function_name='MD5', bit_length=HASH_FUNC_TO_BIT_LEN['MD5'],
		                  result_base64=result_base64,
		                  result_hex=result_hex)

	@staticmethod
	def calculate_sha1_result(hash_input: str):
		plaintext = hash_input
		hash_input = hash_input.encode('utf8')
		result_base64 = binascii.b2a_base64(hashlib.sha1(hash_input).digest()).decode('utf8')
		result_hex = binascii.b2a_hex(hashlib.sha1(hash_input).digest()).decode('utf8')
		return HashResult(plaintext=plaintext, function_name='SHA1', bit_length=HASH_FUNC_TO_BIT_LEN['SHA1'],
		                  result_base64=result_base64,
		                  result_hex=result_hex)

	@staticmethod
	def calculate_sha224_result(hash_input: str):
		plaintext = hash_input
		hash_input = hash_input.encode('utf8')
		result_base64 = binascii.b2a_base64(hashlib.sha224(hash_input).digest()).decode('utf8')
		result_hex = binascii.b2a_hex(hashlib.sha224(hash_input).digest()).decode('utf8')
		return HashResult(plaintext=plaintext, function_name='SHA2-224', bit_length=HASH_FUNC_TO_BIT_LEN['SHA2-224'],
		                  result_base64=result_base64,
		                  result_hex=result_hex)

	@staticmethod
	def calculate_sha256_result(hash_input: str):
		plaintext = hash_input
		hash_input = hash_input.encode('utf8')
		result_base64 = binascii.b2a_base64(hashlib.sha256(hash_input).digest()).decode('utf8')
		result_hex = binascii.b2a_hex(hashlib.sha256(hash_input).digest()).decode('utf8')
		return HashResult(plaintext=plaintext, function_name='SHA2-256', bit_length=HASH_FUNC_TO_BIT_LEN['SHA2-256'],
		                  result_base64=result_base64,
		                  result_hex=result_hex)

	@staticmethod
	def calculate_sha384_result(hash_input: str):
		plaintext = hash_input
		hash_input = hash_input.encode('utf8')
		result_base64 = binascii.b2a_base64(hashlib.sha384(hash_input).digest()).decode('utf8')
		result_hex = binascii.b2a_hex(hashlib.sha384(hash_input).digest()).decode('utf8')
		return HashResult(plaintext=plaintext, function_name='SHA2-384', bit_length=HASH_FUNC_TO_BIT_LEN['SHA2-384'],
		                  result_base64=result_base64,
		                  result_hex=result_hex)

	@staticmethod
	def calculate_sha512_result(hash_input: str):
		plaintext = hash_input
		hash_input = hash_input.encode('utf8')
		result_base64 = binascii.b2a_base64(hashlib.sha512(hash_input).digest()).decode('utf8')
		result_hex = binascii.b2a_hex(hashlib.sha512(hash_input).digest()).decode('utf8')
		return HashResult(plaintext=plaintext, function_name='SHA2-512', bit_length=HASH_FUNC_TO_BIT_LEN['SHA2-512'],
		                  result_base64=result_base64,
		                  result_hex=result_hex)


class EncodeDecodeResult(models.Model):
	algorithm = models.CharField(max_length=50)
	is_encode = models.BooleanField()
	result = models.TextField(max_length=50000)

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

	@staticmethod
	def base32(encode_decode_input: bytes, is_encode):
		if is_encode:
			result = EncodeDecodeResult(algorithm="Base32", is_encode=is_encode,
			                            result=base64.b32encode(encode_decode_input).decode('utf8'))
		else:
			result = EncodeDecodeResult(algorithm="Base32", is_encode=is_encode,
			                            result=base64.b32decode(encode_decode_input).decode('utf8'))
		return result

	@staticmethod
	def base64(encode_decode_input: bytes, is_encode):
		if is_encode:
			result = EncodeDecodeResult(algorithm="Base64", is_encode=is_encode,
			                            result=base64.b64encode(encode_decode_input).decode('utf8'))
		else:
			result = EncodeDecodeResult(algorithm="Base64", is_encode=is_encode,
			                            result=base64.b64decode(encode_decode_input).decode('utf8'))
		return result

	@staticmethod
	def base85(encode_decode_input: bytes, is_encode):
		if is_encode:
			result = EncodeDecodeResult(algorithm="Base85", is_encode=is_encode,
			                            result=base64.b85encode(encode_decode_input).decode('utf8'))
		else:
			result = EncodeDecodeResult(algorithm="Base85", is_encode=is_encode,
			                            result=base64.b85decode(encode_decode_input).decode('utf8'))
		return result

	# Hex
	@staticmethod
	def hex(encode_decode_input: bytes, is_encode):
		if is_encode:
			result = EncodeDecodeResult(algorithm="Hex", is_encode=is_encode,
			                            result=binascii.hexlify(encode_decode_input).decode('utf8'))
		else:
			result = EncodeDecodeResult(algorithm="Hex", is_encode=is_encode,
			                            result=base64.b85decode(encode_decode_input).decode('utf8'))
		return result

	# URL
	@staticmethod
	def url(encode_decode_input: str, is_encode):
		if is_encode:
			result = EncodeDecodeResult(algorithm="URL", is_encode=is_encode,
			                            result=urllib.parse.quote_plus(encode_decode_input))
		else:
			result = EncodeDecodeResult(algorithm="URL", is_encode=is_encode,
			                            result=urllib.parse.unquote(encode_decode_input))
		return result

	# Quoted-printable
	@staticmethod
	def quoted_printable(encode_decode_input: bytes, is_encode):
		if is_encode:
			result = EncodeDecodeResult(algorithm="Quoted-printable", is_encode=is_encode,
			                            result=quopri.encodestring(encode_decode_input).decode('utf8'))
		else:
			result = EncodeDecodeResult(algorithm="Quoted-printable", is_encode=is_encode,
			                            result=quopri.decodestring(encode_decode_input).decode('utf8'))
		return result

	# HTML
	@staticmethod
	def html(encode_decode_input: str, is_encode):
		if is_encode:
			result = EncodeDecodeResult(algorithm="Quoted-printable", is_encode=is_encode,
			                            result=html.escape(encode_decode_input))
		else:
			result = EncodeDecodeResult(algorithm="Quoted-printable", is_encode=is_encode,
			                            result=html.unescape(encode_decode_input))
		return result

	# UUencode
	@staticmethod
	def uuencode(encode_decode_input: bytes, is_encode):
		if is_encode:
			result = codecs.encode(encode_decode_input, 'uu').decode('utf8')  # get codec result
			result = re.findall('begin 666 <data>\n([\\s\\S]*)\n \nend\n', result)[0]  # extract real encoded message
		else:
			result = b"begin 666 <data>\n" + encode_decode_input + b"\n \nend\n"  # get codec result
			result = codecs.decode(result, 'uu')  # extract real encoded message

		result = EncodeDecodeResult(algorithm="UUencode", is_encode=is_encode,
		                            result=result)
		return result

	# XXencode
	@staticmethod
	def xxencode(encode_decode_input: bytes, is_encode):
		if is_encode:
			encode_map = dict(zip(range(
				0, 2 ** 6), iter("+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")))

			raw_len = len(encode_decode_input)
			while (len(encode_decode_input) % 3 != 0):
				encode_decode_input += b'\x00'

			result = ""
			for i in range(0, len(encode_decode_input), 3):
				curr_block = encode_decode_input[i:i + 3]
				# turn the block into a int
				block_int = int(binascii.b2a_hex(curr_block), 16)
				# split the block to 4 6-bits int
				fourbitints = [(block_int & 0xfc0000) >> 3 * 6, (block_int & 0x3f000)
				               >> 2 * 6, (block_int & 0xfc0) >> 6, block_int & 0x3f]
				result += ''.join(encode_map[fourbitint] for fourbitint in fourbitints)

			# Each group of sixty output characters(corresponding to 45 input bytes) is output as a separate line preceded by an encoded character giving the number of encoded bytes on that line.
			formatted_result = []
			if len(result) >= 60:
				for i in range(0, len(result), 60):
					line = result[i:i + 60]
					if len(line) == 60:
						line_input_len = 45
					else:
						line_input_len = raw_len % 45
					formatted_result.append(encode_map[line_input_len] + line)
				formatted_result = '\n'.join(formatted_result)
			else:
				formatted_result = encode_map[len(encode_decode_input)] + result

			result = EncodeDecodeResult(algorithm="XXencode", is_encode=is_encode,
			                            result=formatted_result)
		else:
			encode_decode_input = encode_decode_input.decode('utf8')
			decode_map = dict(zip(iter("+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"), range(
				0, 2 ** 6)))

			# we don't need the first character in each line (the length indicator)
			s = ''.join(line[1:] for line in encode_decode_input.replace('\r', '').split('\n'))
			if len(s) % 4 != 0:
				raise Exception("Bad Input (data length not divisible by 4)")

			result = b''
			for i in range(0, len(s), 4):
				# 4 characters each block
				curr_encoded_block = s[i:i + 4]
				fourbitints = [decode_map[c] for c in curr_encoded_block]
				block_int = 0
				for index, shift in enumerate(reversed(range(0, 4))):
					block_int += fourbitints[index] << shift * 6
				result += int_to_bytes(block_int)

			result = EncodeDecodeResult(algorithm="XXencode", is_encode=is_encode,
			                            result=result.strip(b'\x00').decode('utf8'))
		return result

	# AAencode
	@staticmethod
	def aaencode(encode_decode_input: str, is_encode):
		if is_encode:
			t = ""
			b = [
				"(c^_^o)",
				"(ﾟΘﾟ)",
				"((o^_^o) - (ﾟΘﾟ))",
				"(o^_^o)",
				"(ﾟｰﾟ)",
				"((ﾟｰﾟ) + (ﾟΘﾟ))",
				"((o^_^o) +(o^_^o))",
				"((ﾟｰﾟ) + (o^_^o))",
				"((ﾟｰﾟ) + (ﾟｰﾟ))",
				"((ﾟｰﾟ) + (ﾟｰﾟ) + (ﾟΘﾟ))",
				"(ﾟДﾟ) .ﾟωﾟﾉ",
				"(ﾟДﾟ) .ﾟΘﾟﾉ",
				"(ﾟДﾟ) ['c']",
				"(ﾟДﾟ) .ﾟｰﾟﾉ",
				"(ﾟДﾟ) .ﾟДﾟﾉ",
				"(ﾟДﾟ) [ﾟΘﾟ]"
			]
			result = "ﾟωﾟﾉ= /｀ｍ´）ﾉ ~┻━┻   //*´∇｀*/ ['_']; o=(ﾟｰﾟ)  =_=3; c=(ﾟΘﾟ) =(ﾟｰﾟ)-(ﾟｰﾟ); "
			result += "(ﾟДﾟ) =(ﾟΘﾟ)= (o^_^o)/ (o^_^o);" + \
			          "(ﾟДﾟ)={ﾟΘﾟ: '_' ,ﾟωﾟﾉ : ((ﾟωﾟﾉ==3) +'_') [ﾟΘﾟ] " + \
			          ",ﾟｰﾟﾉ :(ﾟωﾟﾉ+ '_')[o^_^o -(ﾟΘﾟ)] " + \
			          ",ﾟДﾟﾉ:((ﾟｰﾟ==3) +'_')[ﾟｰﾟ] }; (ﾟДﾟ) [ﾟΘﾟ] =((ﾟωﾟﾉ==3) +'_') [c^_^o];" + \
			          "(ﾟДﾟ) ['c'] = ((ﾟДﾟ)+'_') [ (ﾟｰﾟ)+(ﾟｰﾟ)-(ﾟΘﾟ) ];" + \
			          "(ﾟДﾟ) ['o'] = ((ﾟДﾟ)+'_') [ﾟΘﾟ];" + \
			          "(ﾟoﾟ)=(ﾟДﾟ) ['c']+(ﾟДﾟ) ['o']+(ﾟωﾟﾉ +'_')[ﾟΘﾟ]+ ((ﾟωﾟﾉ==3) +'_') [ﾟｰﾟ] + " + \
			          "((ﾟДﾟ) +'_') [(ﾟｰﾟ)+(ﾟｰﾟ)]+ ((ﾟｰﾟ==3) +'_') [ﾟΘﾟ]+" + \
			          "((ﾟｰﾟ==3) +'_') [(ﾟｰﾟ) - (ﾟΘﾟ)]+(ﾟДﾟ) ['c']+" + \
			          "((ﾟДﾟ)+'_') [(ﾟｰﾟ)+(ﾟｰﾟ)]+ (ﾟДﾟ) ['o']+" + \
			          "((ﾟｰﾟ==3) +'_') [ﾟΘﾟ];(ﾟДﾟ) ['_'] =(o^_^o) [ﾟoﾟ] [ﾟoﾟ];" + \
			          "(ﾟεﾟ)=((ﾟｰﾟ==3) +'_') [ﾟΘﾟ]+ (ﾟДﾟ) .ﾟДﾟﾉ+" + \
			          "((ﾟДﾟ)+'_') [(ﾟｰﾟ) + (ﾟｰﾟ)]+((ﾟｰﾟ==3) +'_') [o^_^o -ﾟΘﾟ]+" + \
			          "((ﾟｰﾟ==3) +'_') [ﾟΘﾟ]+ (ﾟωﾟﾉ +'_') [ﾟΘﾟ]; " + \
			          "(ﾟｰﾟ)+=(ﾟΘﾟ); (ﾟДﾟ)[ﾟεﾟ]='\\\\'; " + \
			          "(ﾟДﾟ).ﾟΘﾟﾉ=(ﾟДﾟ+ ﾟｰﾟ)[o^_^o -(ﾟΘﾟ)];" + \
			          "(oﾟｰﾟo)=(ﾟωﾟﾉ +'_')[c^_^o];" + \
			          "(ﾟДﾟ) [ﾟoﾟ]='\\\"';" + \
			          "(ﾟДﾟ) ['_'] ( (ﾟДﾟ) ['_'] (ﾟεﾟ+"
			result += "(ﾟДﾟ)[ﾟoﾟ]+ "
			for i in range(len(encode_decode_input)):
				n = ord(encode_decode_input[i])
				t = "(ﾟДﾟ)[ﾟεﾟ]+"
				if n <= 127:
					for k in list(str(oct(n)))[2:]:
						t += b[int(k)] + "+ "
				else:
					t += "(oﾟｰﾟo)+ "
					z = hex(n)[2:]
					for o in range(4 - len(z)):
						z = "0" + z
					for k in list(z)[:4]:
						t += b[int(k)] + "+ "
				result += t
			result += "(ﾟДﾟ)[ﾟoﾟ]) (ﾟΘﾟ)) ('_');"
		else:
			result = ''  # decode is handled on the client side using JS, because running JS code is necessary

		result = EncodeDecodeResult(algorithm="AAencode", is_encode=is_encode,
		                            result=result)
		return result

	# JJencode
	@staticmethod
	def jjencode(encode_decode_input: str, is_encode):
		import re
		import sys
		from struct import unpack

		class JJEncoder(object):
			def __init__(self, text, var_name="$", palindrome=False):
				if text:
					self.encoded_text = self.__encode(var_name, text)

					if palindrome:
						self.encoded_text = re.split("[,;]$", self.encoded_text)[0]
						self.encoded_text = """\"\'\\\"+\'+\",""" + \
						                    self.encoded_text + "".join(list(self.encoded_text)[::-1])

			def __encode(self, gv, text):
				r = ""
				n = None
				t = None
				b = ["___", "__$", "_$_", "_$$", "$__", "$_$", "$$_", "$$$",
				     "$___", "$__$", "$_$_", "$_$$", "$$__", "$$_$", "$$$_", "$$$$"]
				s = ""

				for i in range(len(text)):
					n = ord(text[i])
					if (n == 0x22 or n == 0x5c):
						s += "\\\\\\" + chr(unpack("b", text[i])[0])
					elif ((0x21 <= n and n <= 0x2f) or (0x3A <= n and n <= 0x40) or (0x5b <= n and n <= 0x60) or (
							0x7b <= n and n <= 0x7f)):
						s += text[i]

					elif ((0x30 <= n and n <= 0x39) or (0x61 <= n and n <= 0x66)):
						if s:
							r += '"' + s + '"+'

						if n < 0x40:
							tmp_index = n - 0x30
						else:
							tmp_index = n - 0x57

						r += gv + "." + b[tmp_index] + "+"
						s = ""

					elif n == 0x6c:  # 'l'
						if s:
							r += '"' + s + '"+'

						r += '(![]+"")[' + gv + '._$_]+'
						s = ""

					elif n == 0x6f:  # 'o'
						if s:
							r += '"' + s + '"+'

						r += gv + "._$+"
						s = ""
					elif n == 0x74:  # 'u'
						if s:
							r += '"' + s + '"+'

						r += gv + ".__+"
						s = ""
					elif n == 0x75:  # 'u'
						if s:
							r += '"' + s + '"+'

						r += gv + "._+"
						s = ""
					elif n < 128:
						if s:
							r += '"' + s
						else:
							r += '"'

						r += '\\\\"+' + "".join([self.__f(gv, b, i) for i in [int(x)
						                                                      for x in
						                                                      re.findall("[0-7]", oct(n))[1:]]])
						s = ""
					else:
						if s:
							r += '"' + s
						else:
							r += '"'

						r += '\\\\"+' + gv + "._+" + \
						     "".join([self.__g(gv, b, i) for i in [int(x)
						                                           for x in re.findall("[0-9a-f]", oct(n), re.I)[1:]]])
						s = ""

				if s:
					r += '"' + s + '"+'

				r = (gv + "=~[];" +
				     gv + "={___:++" + gv + ',$$$$:(![]+"")[' + gv + "],__$:++" + gv + ',$_$_:(![]+"")[' + gv + "],_$_:++" +
				     gv + ',$_$$:({}+"")[' + gv + "],$$_$:(" + gv + "[" + gv + """]+"")[""" + gv + "],_$$:++" + gv + ',$$$_:(!""+"")[' +
				     gv + "],$__:++" + gv + ",$_$:++" + gv + ',$$__:({}+"")[' + gv + "],$$_:++" + gv + ",$$$:++" + gv + ",$___:++" + gv + ",$__$:++" + gv + "};" +
				     gv + ".$_=" +
				     "(" + gv + ".$_=" + gv + '+"")[' + gv + ".$_$]+" +
				     "(" + gv + "._$=" + gv + ".$_[" + gv + ".__$])+" +
				     "(" + gv + ".$$=(" + gv + '.$+"")[' + gv + ".__$])+" +
				     "((!" + gv + ')+"")[' + gv + "._$$]+" +
				     "(" + gv + ".__=" + gv + ".$_[" + gv + ".$$_])+" +
				     "(" + gv + '.$=(!""+"")[' + gv + ".__$])+" +
				     "(" + gv + '._=(!""+"")[' + gv + "._$_])+" +
				     gv + ".$_[" + gv + ".$_$]+" +
				     gv + ".__+" +
				     gv + "._$+" +
				     gv + ".$;" +
				     gv + ".$$=" +
				     gv + ".$+" +
				     '(!""+"")[' + gv + "._$$]+" +
				     gv + ".__+" +
				     gv + "._+" +
				     gv + ".$+" +
				     gv + ".$$;" +
				     gv + ".$=(" + gv + ".___)[" + gv + ".$_][" + gv + ".$_];" +
				     gv + ".$(" + gv + ".$(" + gv + '.$$+"\\""+' + r + '"\\"")())();')

				return r

			def __f(self, a, b, c):
				return a + "." + b[c] + "+"

			def __g(self, a, b, c):
				return a + "." + b[int(c, 16)] + "+"

		class JJDecoder(object):

			def __init__(self, jj_encoded_data):
				self.encoded_str = jj_encoded_data

			def clean(self):
				return re.sub('^\s+|\s+$', '', self.encoded_str)

			def checkPalindrome(self, Str):
				startpos = -1
				endpos = -1
				gv, gvl = -1, -1

				index = Str.find('"\'\\"+\'+",')

				if index == 0:
					startpos = Str.find('$$+"\\""+') + 8
					endpos = Str.find('"\\"")())()')
					gv = Str[Str.find('"\'\\"+\'+",') + 9:Str.find('=~[]')]
					gvl = len(gv)
				else:
					gv = Str[0:Str.find('=')]
					gvl = len(gv)
					startpos = Str.find('"\\""+') + 5
					endpos = Str.find('"\\"")())()')

				return (startpos, endpos, gv, gvl)

			def decode(self):

				self.encoded_str = self.clean()
				startpos, endpos, gv, gvl = self.checkPalindrome(self.encoded_str)

				if startpos == endpos:
					raise Exception('No data!')

				data = self.encoded_str[startpos:endpos]

				b = ['___+', '__$+', '_$_+', '_$$+', '$__+', '$_$+', '$$_+', '$$$+',
				     '$___+', '$__$+', '$_$_+', '$_$$+', '$$__+', '$$_$+', '$$$_+', '$$$$+']

				str_l = '(![]+"")[' + gv + '._$_]+'
				str_o = gv + '._$+'
				str_t = gv + '.__+'
				str_u = gv + '._+'

				str_hex = gv + '.'

				str_s = '"'
				gvsig = gv + '.'

				str_quote = '\\\\\\"'
				str_slash = '\\\\\\\\'

				str_lower = '\\\\"+'
				str_upper = '\\\\"+' + gv + '._+'

				str_end = '"+'

				out = ''
				while data != '':
					# l o t u
					if data.find(str_l) == 0:
						data = data[len(str_l):]
						out += 'l'
						continue
					elif data.find(str_o) == 0:
						data = data[len(str_o):]
						out += 'o'
						continue
					elif data.find(str_t) == 0:
						data = data[len(str_t):]
						out += 't'
						continue
					elif data.find(str_u) == 0:
						data = data[len(str_u):]
						out += 'u'
						continue

					# 0123456789abcdef
					if data.find(str_hex) == 0:
						data = data[len(str_hex):]

						for i in range(len(b)):
							if data.find(b[i]) == 0:
								data = data[len(b[i]):]
								out += '%x' % i
								break
						continue

					# start of s block
					if data.find(str_s) == 0:
						data = data[len(str_s):]

						# check if "R
						if data.find(str_upper) == 0:  # r4 n >= 128
							data = data[len(str_upper):]  # skip sig
							ch_str = ''
							for i in range(2):  # shouldn't be more than 2 hex chars
								# gv + "."+b[ c ]
								if data.find(gvsig) == 0:
									data = data[len(gvsig):]
									for k in range(len(b)):  # for every entry in b
										if data.find(b[k]) == 0:
											data = data[len(b[k]):]
											ch_str = '%x' % k
											break
								else:
									break

							out += chr(int(ch_str, 16))
							continue

						elif data.find(str_lower) == 0:  # r3 check if "R // n < 128
							data = data[len(str_lower):]  # skip sig

							ch_str = ''
							ch_lotux = ''
							temp = ''
							b_checkR1 = 0
							for j in range(3):  # shouldn't be more than 3 octal chars
								if j > 1:  # lotu check
									if data.find(str_l) == 0:
										data = data[len(str_l):]
										ch_lotux = 'l'
										break
									elif data.find(str_o) == 0:
										data = data[len(str_o):]
										ch_lotux = 'o'
										break
									elif data.find(str_t) == 0:
										data = data[len(str_t):]
										ch_lotux = 't'
										break
									elif data.find(str_u) == 0:
										data = data[len(str_u):]
										ch_lotux = 'u'
										break

								# gv + "."+b[ c ]
								if data.find(gvsig) == 0:
									temp = data[len(gvsig):]
									for k in range(8):  # for every entry in b octal
										if temp.find(b[k]) == 0:
											if int(ch_str + str(k), 8) > 128:
												b_checkR1 = 1
												break

											ch_str += str(k)
											data = data[len(gvsig):]  # skip gvsig
											data = data[len(b[k]):]
											break

									if b_checkR1 == 1:
										if data.find(str_hex) == 0:  # 0123456789abcdef
											data = data[len(str_hex):]
											# check every element of hex decode string for a match
											for i in range(len(b)):
												if data.find(b[i]) == 0:
													data = data[len(b[i]):]
													ch_lotux = '%x' % i
													break
											break
								else:
									break

							out += chr(int(ch_str, 8)) + ch_lotux
							continue

						else:  # "S ----> "SR or "S+
							# if there is, loop s until R 0r +
							# if there is no matching s block, throw error

							match = 0
							n = None

							# searching for matching pure s block
							while True:
								n = ord(data[0])
								if data.find(str_quote) == 0:
									data = data[len(str_quote):]
									out += '"'
									match += 1
									continue
								elif data.find(str_slash) == 0:
									data = data[len(str_slash):]
									out += '\\'
									match += 1
									continue
								elif data.find(str_end) == 0:  # reached end off S block ? +
									if match == 0:
										raise '+ no match S block: ' + data
									data = data[len(str_end):]
									break  # step out of the while loop
								# r4 reached end off S block ? - check if "R n >= 128
								elif data.find(str_upper) == 0:
									if match == 0:
										raise 'no match S block n>128: ' + data
									data = data[len(str_upper):]  # skip sig

									ch_str = ''
									ch_lotux = ''

									for j in range(10):  # shouldn't be more than 10 hex chars
										if j > 1:  # lotu check
											if data.find(str_l) == 0:
												data = data[len(str_l):]
												ch_lotux = 'l'
												break
											elif data.find(str_o) == 0:
												data = data[len(str_o):]
												ch_lotux = 'o'
												break
											elif data.find(str_t) == 0:
												data = data[len(str_t):]
												ch_lotux = 't'
												break
											elif data.find(str_u) == 0:
												data = data[len(str_u):]
												ch_lotux = 'u'
												break

										# gv + "."+b[ c ]
										if data.find(gvsig) == 0:
											data = data[len(gvsig):]  # skip gvsig
											for k in range(len(b)):  # for every entry in b
												if data.find(b[k]) == 0:
													data = data[len(b[k]):]
													ch_str += '%x' % k
													break
										else:
											break  # done
									out += chr(int(ch_str, 16))
									break  # step out of the while loop
								elif data.find(str_lower) == 0:  # r3 check if "R // n < 128
									if match == 0:
										raise Exception('no match S block n<128: ' + data)

									data = data[len(str_lower):]  # skip sig

									ch_str = ''
									ch_lotux = ''
									temp = ''
									b_checkR1 = 0

									for j in range(3):  # shouldn't be more than 3 octal chars
										if j > 1:  # lotu check
											if data.find(str_l) == 0:
												data = data[len(str_l):]
												ch_lotux = 'l'
												break
											elif data.find(str_o) == 0:
												data = data[len(str_o):]
												ch_lotux = 'o'
												break
											elif data.find(str_t) == 0:
												data = data[len(str_t):]
												ch_lotux = 't'
												break
											elif data.find(str_u) == 0:
												data = data[len(str_u):]
												ch_lotux = 'u'
												break

										# gv + "."+b[ c ]
										if data.find(gvsig) == 0:
											temp = data[len(gvsig):]
											for k in range(8):  # for every entry in b octal
												if temp.find(b[k]) == 0:
													if int(ch_str + str(k), 8) > 128:
														b_checkR1 = 1
														break

													ch_str += str(k)
													# skip gvsig
													data = data[len(gvsig):]
													data = data[len(b[k]):]
													break

											if b_checkR1 == 1:
												if data.find(str_hex) == 0:  # 0123456789abcdef
													data = data[len(str_hex):]
													# check every element of hex decode string for a match
													for i in range(len(b)):
														if data.find(b[i]) == 0:
															data = data[len(b[i]):]
															ch_lotux = '%x' % i
															break
										else:
											break
									out += chr(int(ch_str, 8)) + ch_lotux
									break  # step out of the while loop
								elif (0x21 <= n and n <= 0x2f) or (0x3A <= n and n <= 0x40) or (
										0x5b <= n and n <= 0x60) or (0x7b <= n and n <= 0x7f):
									out += data[0]
									data = data[1:]
									match += 1
							continue
					raise ('No match : ' + data)
					break
				return out

		if is_encode:
			result = JJEncoder(encode_decode_input).encoded_text
		else:
			result = JJDecoder(encode_decode_input).decode()

		result = EncodeDecodeResult(algorithm="JJencode", is_encode=is_encode,
		                            result=result)
		return result

	# BubbleBabble
	@staticmethod
	def bubblebabble(encode_decode_input: str, is_encode):
		class BubbleBabble(object):
			""" encodes or decodes to and from bubblebabble """

			def __init__(self):
				super(BubbleBabble, self).__init__()
				self.vowels = 'aeiouy'
				self.consonants = 'bcdfghklmnprstvzx'

			def encode(self, src):
				out = 'x'
				c = 1

				for i in range(0, len(src) + 1, 2):
					if i >= len(src):
						out += self.vowels[c % 6] + \
						       self.consonants[16] + self.vowels[int(c / 6)]
						break

					byte1 = ord(src[i])
					out += self.vowels[(((byte1 >> 6) & 3) + c) % 6]
					out += self.consonants[(byte1 >> 2) & 15]
					out += self.vowels[((byte1 & 3) + int(c / 6)) % 6]

					if (i + 1) >= len(src):
						break

					byte2 = ord(src[i + 1])
					out += self.consonants[(byte2 >> 4) & 15]
					out += '-'
					out += self.consonants[byte2 & 15]

					c = (c * 5 + byte1 * 7 + byte2) % 36

				out += 'x'

				return out

			def decode(self, src):
				c = 1

				if src[0] is not 'x':
					raise Exception(
						"corrupt string at offset 0: must begin with a 'x'")

				if src[-1] is not 'x':
					raise Exception(
						"corrupt string at the last offset: must end with a 'x'")

				if len(src) != 5 and len(src) % 6 != 5:
					raise Exception("corrupt string: wrong length")

				src = src[1:-1]
				src = list(enumerate([src[x:x + 6] for x in range(0, len(src), 6)]))
				last_tuple = len(src) - 1
				out = ''

				for k, tup in src:
					pos = k * 6
					tup = self._decode_tuple(tup, pos)

					if k == last_tuple:
						if tup[1] == 16:
							if tup[0] != c % 6:
								raise Exception(
									"corrupt string at offset %d (checksum)" % pos)

							if tup[2] != int(c / 6):
								raise Exception(
									"corrupt string at offset %d (checksum)" % (pos + 2))
						else:
							byte = self._decode_3way_byte(
								tup[0], tup[1], tup[2], pos, c)
							out += chr(byte)
					else:
						byte1 = self._decode_3way_byte(tup[0], tup[1], tup[2], pos, c)
						byte2 = self._decode_2way_byte(tup[3], tup[5], pos)

						out += chr(byte1)
						out += chr(byte2)

						c = (c * 5 + byte1 * 7 + byte2) % 36

				return out

			def _decode_tuple(self, src, pos):
				tupl = [self.vowels.index(src[0]),
				        self.consonants.index(src[1]),
				        self.vowels.index(src[2])]
				try:
					tupl.append(self.consonants.index(src[3]))
					tupl.append('-')
					tupl.append(self.consonants.index(src[5]))
				except:
					pass

				return tupl

			def _decode_2way_byte(self, a1, a2, offset):
				if a1 > 16:
					raise Exception(
						"corrupt string at offset %d" % offset)

				if a2 > 16:
					raise Exception(
						"corrupt string at offset %d" % (offset + 2))

				return (int(a1) << 4) | int(a2)

			def _decode_3way_byte(self, a1, a2, a3, offset, c):
				high2 = (a1 - (c % 6) + 6) % 6

				if high2 >= 4:
					raise Exception(
						"corrupt string at offset %d" % offset)

				if int(a2) > 16:
					raise Exception(
						"corrupt string at offset %d" % (offset + 1))

				mid4 = a2
				low2 = (a3 - (int(c / 6) % 6) + 6) % 6

				if low2 >= 4:
					raise Exception(
						"corrupt string at offset %d" % (offset + 2))

				return high2 << 6 | mid4 << 2 | low2

		bb = BubbleBabble()
		if is_encode:
			result = bb.encode(encode_decode_input)
		else:
			result = bb.decode(encode_decode_input)

		result = EncodeDecodeResult(algorithm="BubbleBabble", is_encode=is_encode,
		                            result=result)
		return result

	# JSFuck
	@staticmethod
	def jsfuck(encode_decode_input: str, is_encode):
		# https://github.com/j4ckstraw/jsfuck-py
		from urllib import parse
		import time
		import math
		import html
		import re

		if is_encode:
			USE_CHAR_CODE = "USE_CHAR_CODE"
			MIN, MAX = 32, 126  # 可见字符范围

			SIMPLE = {
				'false'    : '![]',
				'true'     : '!![]',
				'undefined': '[][[]]',
				'NaN'      : '+[![]]',
				# +"1e1000"
				'Infinity' : '+(+!+[]+(!+[]+[])[!+[]+!+[]+!+[]]+[+!+[]]+[+[]]+[+[]]+[+[]])'
			}

			CONSTRUCTORS = {
				'Array'   : '[]',
				'Number'  : '(+[])',
				'String'  : '([]+[])',
				'Boolean' : '(![])',
				'Function': '[]["fill"]',
				'RegExp'  : 'Function("return/"+false+"/")()'
			}

			MAPPING = {
				'a' : '(false+"")[1]',
				'b' : '([]["entries"]()+"")[2]',
				'c' : '([]["fill"]+"")[3]',
				'd' : '(undefined+"")[2]',
				'e' : '(true+"")[3]',
				'f' : '(false+"")[0]',
				'g' : '(false+[0]+String)[20]',
				'h' : '(+(101))["to"+String["name"]](21)[1]',
				'i' : '([false]+undefined)[10]',
				'j' : '([]["entries"]()+"")[3]',
				'k' : '(+(20))["to"+String["name"]](21)',
				'l' : '(false+"")[2]',
				'm' : '(Number+"")[11]',
				'n' : '(undefined+"")[1]',
				'o' : '(true+[]["fill"])[10]',
				'p' : '(+(211))["to"+String["name"]](31)[1]',
				'q' : '(+(212))["to"+String["name"]](31)[1]',
				'r' : '(true+"")[1]',
				's' : '(false+"")[3]',
				't' : '(true+"")[0]',
				'u' : '(undefined+"")[0]',
				'v' : '(+(31))["to"+String["name"]](32)',
				'w' : '(+(32))["to"+String["name"]](33)',
				'x' : '(+(101))["to"+String["name"]](34)[1]',
				'y' : '(NaN+[Infinity])[10]',
				'z' : '(+(35))["to"+String["name"]](36)',

				'A' : '(+[]+Array)[10]',
				'B' : '(+[]+Boolean)[10]',
				'C' : 'Function("return escape")()(("")["italics"]())[2]',
				'D' : 'Function("return escape")()([]["fill"])["slice"]("-1")',
				'E' : '(RegExp+"")[12]',
				'F' : '(+[]+Function)[10]',
				'G' : '(false+Function("return Date")()())[30]',
				'H' : USE_CHAR_CODE,
				'I' : '(Infinity+"")[0]',
				'J' : USE_CHAR_CODE,
				'K' : USE_CHAR_CODE,
				'L' : USE_CHAR_CODE,
				'M' : '(true+Function("return Date")()())[30]',
				'N' : '(NaN+"")[0]',
				'O' : '(NaN+Function("return{}")())[11]',
				'P' : USE_CHAR_CODE,
				'Q' : USE_CHAR_CODE,
				'R' : '(+[]+RegExp)[10]',
				'S' : '(+[]+String)[10]',
				'T' : '(NaN+Function("return Date")()())[30]',
				'U' : '(NaN+Function("return{}")()["to"+String["name"]]["call"]())[11]',
				'V' : USE_CHAR_CODE,
				'W' : USE_CHAR_CODE,
				'X' : USE_CHAR_CODE,
				'Y' : USE_CHAR_CODE,
				'Z' : USE_CHAR_CODE,

				' ' : '(NaN+[]["fill"])[11]',
				'!' : USE_CHAR_CODE,
				'"' : '("")["fontcolor"]()[12]',
				'#' : USE_CHAR_CODE,
				'$' : USE_CHAR_CODE,
				'%' : 'Function("return escape")()([]["fill"])[21]',
				'&' : '("")["link"](0+")[10]',
				'\'': USE_CHAR_CODE,
				'(' : '(undefined+[]["fill"])[22]',
				')' : '([0]+false+[]["fill"])[20]',
				'*' : USE_CHAR_CODE,
				'+' : '(+(+!+[]+(!+[]+[])[!+[]+!+[]+!+[]]+[+!+[]]+[+[]]+[+[]])+[])[2]',
				',' : '([]["slice"]["call"](false+"")+"")[1]',
				'-' : '(+(.+[0000000001])+"")[2]',
				'.' : '(+(+!+[]+[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+[!+[]+!+[]]+[+[]])+[])[+!+[]]',
				'/' : '(false+[0])["italics"]()[10]',
				':' : '(RegExp()+"")[3]',
				';' : '("")["link"](")[14]',
				'<' : '("")["italics"]()[0]',
				'=' : '("")["fontcolor"]()[11]',
				'>' : '("")["italics"]()[2]',
				'?' : '(RegExp()+"")[2]',
				'@' : USE_CHAR_CODE,
				'[' : '([]["entries"]()+"")[0]',
				'\\': USE_CHAR_CODE,
				']' : '([]["entries"]()+"")[22]',
				'^' : USE_CHAR_CODE,
				'_' : USE_CHAR_CODE,
				'`' : USE_CHAR_CODE,
				'{' : '(true+[]["fill"])[20]',
				'|' : USE_CHAR_CODE,
				'}' : '([]["fill"]+"")["slice"]("-1")',
				'~' : USE_CHAR_CODE
			}

			GLOBAL = 'Function("return this")()'

			def fillMissingChars():
				'''
				将 USE_CHAR_CODE 替换掉
				'''
				for key in MAPPING:
					if MAPPING[key] == USE_CHAR_CODE:
						s = str(hex(ord(key)))[2:]
						string = '''("%"+({})+"{}")'''.format(
							re.findall('\d+', s)[0] if re.findall('\d', s) else "",
							re.findall('[a-zA-Z]+', s)[0] if re.findall('[a-zA-Z]', s) else "")
						MAPPING[key] = """Function("return unescape")()""" + string

			def fillMissingDigits():
				'''
				填充MAPPING中 0-9 的数字
				'''
				for num in range(10):
					output = "+[]"
					if num > 0:
						output = "+!" + output
					for i in range(1, num):
						output = "+!+[]" + output
					if num > 1:
						output = output[1:]
					MAPPING[str(num)] = "[" + output + "]"

			class replaceMap(object):
				'''
				替换 MAPPING中的
				'''

				def replace(self, pattern, replacement):
					self.value = re.sub(pattern, replacement, self.value)

				def digitReplacer(self, x):
					x = re.findall(r'\d', x.group())[0]
					# 正则表达式 分组
					# python 匹配 \[(\d)\]   例如 [0]  并不是 选中分组\d 即0   而是 [0]
					return MAPPING[x]

				def numberReplacer(self, y):
					values = list(y.group())
					values.reverse()
					head = int(values.pop())
					values.reverse()
					output = "+[]"

					if head > 0:
						output = "+!" + output
					for i in range(1, head):
						output = "+!+[]" + output
					if head > 1:
						output = output[1:]
					output = [output] + values
					output = "+".join(output)
					output = re.sub(r'\d', self.digitReplacer, output)
					return output

				def __init__(self):
					self.character = ""
					self.value = ""
					self.original = ""

					for i in range(MIN, MAX + 1):
						self.character = chr(i)
						self.value = MAPPING[self.character]
						if not self.value:
							continue
						self.original = self.value

						for key in CONSTRUCTORS:
							self.value = re.sub(
								r'\b' + key, CONSTRUCTORS[key] + '["constructor"]', self.value)

						for key in SIMPLE:
							self.value = re.sub(key, SIMPLE[key], self.value)

						self.replace('(\\d\\d+)', self.numberReplacer)
						self.replace('\\((\\d)\\)', self.digitReplacer)
						self.replace('\\[(\\d)\\]', self.digitReplacer)
						# python 和 js中正则表达式 () 分组 有区别?

						self.value = re.sub("GLOBAL", GLOBAL, self.value)
						self.value = re.sub(r'\+""', "+[]", self.value)
						self.value = re.sub('\"\"', "[]+[]", self.value)

						MAPPING[self.character] = self.value

			class replaceStrings(object):
				'''
				替换 字符串
				'''

				def findMissing(self):
					self.missing = {}
					done = False
					for m in MAPPING:
						value = MAPPING[m]
						if re.search(self.regEx, value):
							# Python offers two different primitive operations based on regular expressions:
							# re.match() checks for a match only at the beginning of the string,
							# while re.search() checks for a match anywhere in the string (this is what Perl does by default).
							self.missing[m] = value
							done = True
					return done

				def mappingReplacer(self, b):
					return "+".join(list(b.group().strip('""')))

				# strip去掉 “”

				def valueReplacer(self, c):
					c = c.group()
					return c if c in self.missing else MAPPING[c]

				# return c if self.missing[c] else MAPPING[c]
				# js  missing[c] 不存在 为undefined
				# python missing[c] 不存在 会报错

				def __init__(self):
					self.regEx = r'[^\[\]\(\)\!\+]{1}'
					self.missing = {}
					self.count = MAX - MIN

					for m in MAPPING:
						MAPPING[m] = re.sub(
							r'\"([^\"]+)\"', self.mappingReplacer, MAPPING[m])

					while self.findMissing():
						for m in self.missing:
							value = MAPPING[m]
							value = re.sub(self.regEx, self.valueReplacer, value)
							MAPPING[m] = value
							self.missing[m] = value
						# for self.missing  此处修改了missing的值  but ok
						self.count -= 1
						if self.count == 0:
							print("Could not compile the following chars:", self.missing)
							break

			class JSFuck(object):
				def encodeReplacer(self, c):
					c = c.group()
					replacement = c in SIMPLE
					if replacement:
						self.output.append("[" + SIMPLE[c] + "]+[]")
					else:
						replacement = c in MAPPING
						if replacement:
							self.output.append(MAPPING[c])
						else:
							replacement = "([]+[])[" + JSFuck("constructor") + "]" + \
							              "[" + JSFuck("fromCharCode") + "]" + \
							              "(" + JSFuck(str(ord(c[0]))) + ")"

							self.output.append(replacement)
							MAPPING[c] = replacement

				def __init__(self, input, wrapWithEval=False, runInParentScope=False):
					fillMissingChars()
					fillMissingDigits()
					replaceMap()
					replaceStrings()

					self.output = []
					self.input = input
					self.wrapWithEval = wrapWithEval
					self.runInParentScope = runInParentScope

				def encode(self):
					if not self.input:
						return ""

					r = ""
					for i in SIMPLE:
						r += i + "|"
					r += "."

					# self.input = re.sub(r,self.encodeReplacer,self.input)
					re.sub(r, self.encodeReplacer, self.input)
					# 此处未改变input的值 后面 re.search 因为会判断input 是否为数字

					self.output = "+".join(self.output)
					if re.search(r'^\d$', self.input):
						self.output += "+[]"

					if self.wrapWithEval:
						if self.runInParentScope:
							self.output = "[][" + JSFuck("fill").encode() + "]" + \
							              "[" + JSFuck("constructor").encode() + "]" + \
							              "(" + JSFuck("return eval").encode() + ")()" + \
							              "(" + self.output + ")"
						else:
							self.output = "[][" + JSFuck("fill").encode() + "]" + \
							              "[" + JSFuck("constructor").encode() + "]" + \
							              "(" + self.output + ")()"

					return self.output

			encoder = JSFuck(encode_decode_input)
			result = encoder.encode()
		else:
			# https://github.com/eagleoflqj/antiJSFuck
			def date(millisecond):
				weekday, month, day, tm, year = time.ctime(millisecond / 1000).split()
				if int(day) < 10:
					day = '0' + day
				return ' '.join((weekday, month, day, year, tm, 'GMT+0800'))

			class Node():
				def __init__(self, kind, value, raw):
					self.kind = kind
					self.value = value
					self.raw = raw

				def __str__(self):
					return f'Node {self.kind} {self.value}'

			class JSObject():
				def __init__(self, kind, value=None):
					self.kind = kind
					self.value = value

				def __str__(self):
					if isinstance(self.value, list):
						value = '[' + ','.join(str(x) for x in self.value) + ']'
					elif isinstance(self.value, tuple):
						value = '(' + ','.join(str(x) for x in self.value) + ')'
					else:
						value = self.value
					return f'JSObject {self.kind} {value}'

			class JSCode():
				def __init__(self, code):
					self.code = code

				def __str__(self):
					return f'JSCode {self.code}'

			def bool2number(b):
				if b is True:
					return 1
				if b is False:
					return 0
				return b

			def array2string(a):
				return ','.join(o2string(x) for x in a)

			def bool2string(b):
				if b is True:
					return 'true'
				if b is False:
					return 'false'

			def numberToString(n, b):
				if b < 2 or b > 36:
					raise Exception()
				series = '0123456789abcdefghijklmnopqrstuvwxyz'
				result = ''
				while True:
					q, r = divmod(n, b)
					result = series[r] + result
					if q == 0:
						break
					n = q
				return result

			def int_like(o: JSObject):
				if o.kind == 'Number' and isinstance(o.value, int) or o.kind == 'String' and re.match(r'[\+\-]?\d+',
				                                                                                      o.value):
					return True
				return False

			def o2string(o: JSObject, base=None):
				if o.kind == 'String':
					return o.value
				if o.kind == 'Number':
					if math.isnan(o.value):
						return 'NaN'
					if o.value == math.inf:
						return 'Infinity'
					if base is None:
						return str(o.value)
					return numberToString(o.value, base)
				if o.kind == 'Array':
					return array2string(o.value)
				if o.kind == 'Boolean':
					return bool2string(o.value)
				if o.kind == 'undefined':
					return 'undefined'
				if o.kind == 'Function':
					if o.value in ('filter', 'String', 'Array', 'Boolean', 'RegExp', 'Number', 'Function', 'fill'):
						return 'function ' + o.value + '() { [native code] }'
				if o.kind == 'Object':
					if o.value == 'this':
						return '[object Window]'
					if o.value == 'Array Iterator':
						return '[object Array Iterator]'
					if o.value == '{}':
						return '[object Object]'
				if o.kind == 'Date':
					return date(o.value)
				if o.kind == 'RegExp':
					return o.value
				raise NotImplementedError(f'{o} to String failed')

			# a+b

			def add(a, b):
				to_stringer = ('Array', 'Function', 'Object', 'String', 'RegExp', 'Date')
				if a is None:
					return b
				if a.kind in to_stringer or b.kind in to_stringer:
					return JSObject('String', o2string(a) + o2string(b))
				if a.kind in ('Number', 'Boolean') and b.kind == 'undefined' or a.kind == 'undefined' and b.kind in (
						'Number', 'Boolean'):
					return JSObject('Number', math.nan)
				if a.kind == 'Number' and b.kind == 'Number':
					return JSObject('Number', a.value + b.value)
				if a.kind == 'Boolean' and b.kind in (
						'Boolean', 'Number') or a.kind == 'Number' and b.kind == 'Boolean':
					return JSObject('Number', bool2number(a.value) + bool2number(b.value))
				raise NotImplementedError(f'{a} + {b} failed')

			# !

			def reverse(o: JSObject):
				if o.kind == 'Array':  # ![1]=false
					return JSObject('Boolean', False)
				if o.kind == 'Boolean':  # !false=true
					return JSObject('Boolean', not o.value)
				if o.kind == 'Number':
					if o.value == 0 or math.isnan(o.value):  # !0=true,!NaN=true
						return JSObject('Boolean', True)
					return JSObject('Boolean', False)  # !1=false
				raise NotImplementedError(f'! {o} failed')

			def call(a, b):
				if a is None and b.kind == 'Function' and isinstance(b.value, tuple) and b.value[0] == 'toString':
					return JSObject('String', '[object Undefined]')
				if isinstance(b, JSObject) and b.kind == 'Array' and b.value[0].kind == 'String':
					if b.value[0].value == 'constructor':
						return JSObject('Function', a.kind)
					if b.value[0].value == 'toString':
						return JSObject('Function', ('toString', a))
				if a.kind == 'Array' and b.kind == 'Array':
					if b.value[0].kind == 'Array':
						return JSObject('undefined')
					if b.value[0].kind == 'String':
						if b.value[0].value == 'filter':
							return JSObject('Function', 'filter')
						if b.value[0].value == 'concat':
							return JSObject('Function', ('concat', a))
						if b.value[0].value == 'fill':
							return JSObject('Function', 'fill')
						if b.value[0].value == 'entries':
							return JSObject('Function', 'entries')
						if b.value[0].value == 'slice':
							return JSObject('Function', ('slice', a))
				if a.kind == 'String':
					if b.kind == 'Array':
						if int_like(b.value[0]):
							return JSObject('String', a.value[int(b.value[0].value)])
						if b.value[0].kind == 'String':
							if b.value[0].value in ('italics', 'fontcolor', 'link', 'slice'):
								return JSObject('Function', (b.value[0].value, a))
					if b.kind == 'Function' and \
							isinstance(b.value, tuple) and b.value[0] == 'slice' and b.value[1].kind == 'Array':
						return JSObject('Array', [JSObject('String', x) for x in a.value])
				if a.kind == 'Function':
					# f()
					if a.value == 'escape':
						return JSObject('String', parse.quote(o2string(b)))
					if a.value == 'unescape':
						return JSObject('String', parse.unquote(b.value))
					if a.value == 'Function':
						if b is None:
							return JSObject('Function', JSObject('String', ''))
						if b.kind == 'String':
							m = re.match(r'return(\s\S.*|[\/\{]\S+)', b.value)
							if m:
								return_value = m.group(1).strip()
								return JSObject('Function', ('return', return_value))
							return JSObject('Function', b)
					if a.value == 'Array':
						if b is None:
							return JSObject('Array', [])
						if b.kind == 'String':
							return JSObject('Array', [b])
					# potential bug: not distinguish f[] and f([])
					if a.value == 'String' and b.kind == 'Array' and b.value[0].kind == 'String':
						if b.value[0].value == 'fromCharCode':
							return JSObject('Function', 'fromCharCode')
						if b.value[0].value == 'name':
							return JSObject('String', 'String')
					if a.value == 'Date':
						# I'm too lazy to generate a real time
						default_date = 'Mon Nov 12 2018 15:54:05 GMT+0800'
						return JSObject('String', default_date)
					if a.value == 'RegExp':
						return JSObject('RegExp', '/(?:)/')
					if a.value == 'fromCharCode':
						return JSObject('String', chr(int(b.value)))
					if a.value == 'eval':
						if b is None:
							return JSCode('')
						if b.kind == 'String':
							return JSCode(b.value)
					if a.value == 'entries':
						return JSObject('Object', 'Array Iterator')
					if isinstance(a.value, tuple):
						if a.value[0] == 'return':
							return_value = a.value[1]
							if return_value in ('escape', 'unescape', 'italics', 'Date', 'eval'):
								return JSObject('Function', return_value)
							if return_value == 'this':
								return JSObject('Object', 'this')
							if return_value[0] == '/':
								return JSObject('RegExp', return_value)
							if return_value[0] == '{':
								return JSObject('Object', return_value)
							m = re.match(r'new\s+Date\((\d+)\)', return_value)
							if m:
								return JSObject('Date', int(m.group(1)))
						if a.value[0] == 'italics':
							return JSObject('String', f'<i>{a.value[1].value}</i>')
						if a.value[0] == 'fontcolor':
							return JSObject('String', f'<font color="undefined">{a.value[1].value}</font>')
						if a.value[0] == 'concat' and b.kind == 'Array':
							return JSObject('Array', a.value[1].value + b.value)
						if a.value[0] == 'toString':
							if b is None:
								return JSObject('String', o2string(a.value[1]))
							if int_like(b):
								return JSObject('String', o2string(a.value[1], int(b.value)))
						if a.value[0] == 'link':
							return JSObject('String', f'<a href="{html.escape(b.value)}">{a.value[1].value}</a>')
						if a.value[0] == 'slice' and int_like(b):
							return JSObject('String', a.value[1].value[int(b.value)])
						if a.value[0] == 'call':
							return call(b, a.value[1])
					if b is None and isinstance(a.value, JSObject) and a.value.kind == 'String':
						return JSCode(a.value.value)
					# f.g
					if isinstance(b, JSObject) and b.kind == 'Array':
						if b.value[0].value == 'call':
							return JSObject('Function', ('call', a))
				raise NotImplementedError(f'{a} call {b} failed')

			# +

			def positive(o):
				if o.kind == 'Array':
					if len(o.value) == 0:  # +[]=0
						return JSObject('Number', 0)
					if o.value[0].kind == 'Number':  # +[1]=1
						return JSObject('Number', o.value[0].value)
					if o.value[0].kind == 'Boolean':  # +[true]=NaN
						return JSObject('Number', math.nan)
				if o.kind == 'Boolean':  # +false=0
					return JSObject('Number', bool2number(o.value))
				if o.kind == 'String':  # +"1"=1
					try:
						value = int(o.value)
					except:
						value = float(o.value)
					return JSObject('Number', value)
				raise NotImplementedError(f'+ {o} failed')

			def evaluate_term(o):
				if o[0] == '!':
					return reverse(evaluate_term(o[1:]))
				if o[0] == '+':
					return positive(evaluate_term(o[1:]))
				evaluated = [evaluate(item) for item in o]
				result = evaluated[0]
				for item in evaluated[1:]:
					result = call(result, item)
				return result

			def evaluate_list(o):
				if len(o) == 0:
					return None
				start = 0
				now = 0
				terms = []
				while now < len(o):
					if o[now] == '#':
						terms.append(evaluate_term(o[start:now]))
						start = now + 1
						now = start
					now += 1
				terms.append(evaluate_term(o[start:now]))
				result = None
				for term in terms:
					result = add(result, term)
				return result

			def evaluate(o):
				if isinstance(o, list):
					return evaluate_list(o)
				if not isinstance(o, Node):
					raise Exception()
				if o.kind == '[':
					value = evaluate(o.value)
					return JSObject('Array', [value] if value else [])
				if o.kind == '(':
					return evaluate(o.value)

			def fight(jsfuck_code):
				# build simple AST
				stack = []
				aux = []
				pairs = {']': '[', ')': '('}
				for index, c in enumerate(jsfuck_code):
					if c in ('[', '(', '!'):
						stack.append(c)
						aux.append(index)
					elif c in pairs:
						left = pairs[c]
						i = len(stack) - 1
						while stack[i] != left:
							i -= 1
						node = Node(left, stack[i + 1:], jsfuck_code[aux[i]:index + 1])
						stack = stack[:i]
						stack.append(node)
						aux = aux[:i]
						aux.append(None)
					elif c == '+':
						if len(stack) > 0 and isinstance(stack[-1], Node):
							stack.append('#')
							aux.append(None)
						else:
							stack.append('+')
							aux.append(None)
					else:
						raise Exception(f'not jsfuck character {c}')
				return evaluate(stack)

			result = fight(encode_decode_input).value

		result = EncodeDecodeResult(algorithm="JSFuck", is_encode=is_encode,
		                            result=result)
		return result

	# Brainfuck
	@staticmethod
	def brainfuck(encode_decode_input: bytes, is_encode):
		if is_encode:
			# https://www.wishingstarmoye.com/ctf/jsencode/brainfuck
			def remove_pairs(string, pair):
				'''Remove sequential occurrences of canceling values

				Used to remove things like ++-- from brainfuck code, as this would
				just do nothing, or collapse >>><< to just >
				'''
				result = []
				count = [0, 0]
				pair_seq = False

				# this sub-function just checks the counts for which of the pair
				# occurred more, then appends their difference to the result
				# this has the effect of turning +++-- into just +
				def end_seq():
					if count == [0, 0]:
						return
					most_in_seq = pair[count[0] <= count[1]]
					diff = abs(count[0] - count[1])
					result.append(most_in_seq * diff)
					count[0] = count[1] = 0

				# goes through each character, appending to result unless it's part
				# of a pair sequence, then collapses those as much as possible
				for c in string:
					if c not in pair:
						if pair_seq:
							end_seq()
							pair_seq = False
						result.append(c)
					else:
						count[pair.index(c)] += 1
						pair_seq = True
				end_seq()
				return ''.join(result)

			def minimize(brainfuck):
				'''Remove unnecessary pairs from brainfuck code

				There are two pairs of brainfuck instructions that cancel each other
				out when in sequence. + and - because those add and subtract to the
				current cell, and >, < because those add and subtract from the
				pointer value. We remove these sequences to shorten code.
				'''
				brainfuck = remove_pairs(brainfuck, ('+', '-'))
				brainfuck = remove_pairs(brainfuck, ('>', '<'))
				return brainfuck

			def loop_encode(string):
				result = ""
				if string[-1] != "\n":
					string += "\n"
				chrs = list(enumerate([None] + [ord(c) for c in string]))[1:]
				sorted_chrs = reversed(sorted(chrs, key=lambda x: x[1]))
				groups = itertools.groupby(sorted_chrs, key=lambda x: round(x[1] / 10))
				for group in groups:
					group_num, group_chrs = group[0], list(group[1])
					group_chrs = sorted(group_chrs, key=lambda x: x[0])
					result += "+" * group_num
					result += "[>"
					last_index = 1
					for c in group_chrs:
						result += ">" * (c[0] - last_index)
						result += "+" * 10
						last_index = c[0]
					result += "<" * last_index + "-]"
					last_index = 0
					for c in group_chrs:
						result += ">" * (c[0] - last_index)
						op = "+" if c[1] > 10 * group_num else "-"
						result += op * abs(c[1] - 10 * group_num)
						last_index = c[0]
					result += "<" * last_index
				result += ">[.>]"
				return minimize(result)

			result = loop_encode(encode_decode_input)
		else:
			# https://github.com/pablojorge/brainfuck/blob/master/python/brainfuck-simple.py
			def precompute_jumps(program):
				stack = []
				ret = {}

				pc = 0

				while not pc == len(program):
					opcode = program[pc]
					if opcode == "[":
						stack.append(pc)
					elif opcode == "]":
						target = stack.pop()
						ret[target] = pc
						ret[pc] = target
					pc += 1

				return ret

			def run(program, output_buffer: list):
				buffer = [0]
				jump_map = precompute_jumps(program)

				ptr = 0
				pc = 0

				while not pc == len(program):
					opcode = program[pc]
					if opcode == ">":
						ptr += 1
						if ptr == len(buffer):
							buffer.append(0)
					elif opcode == "<":
						ptr -= 1
					elif opcode == "+":
						buffer[ptr] += 1
					elif opcode == "-":
						buffer[ptr] -= 1
					elif opcode == ".":
						output_buffer.append(chr(buffer[ptr]))
					elif opcode == ",":
						buffer[ptr] = ord(sys.stdin.read(1))
					elif opcode == "[":
						if buffer[ptr] == 0:
							pc = jump_map[pc]
					elif opcode == "]":
						if buffer[ptr] != 0:
							pc = jump_map[pc]
					pc += 1

			output_buffer = []
			program = "".join(filter(lambda c: c in "<>-+[],.", encode_decode_input))
			run(program, output_buffer)
			result = "".join(output_buffer)

		result = EncodeDecodeResult(algorithm="Brainfuck", is_encode=is_encode,
		                            result=result)
		return result

	# CoreValue
	@staticmethod
	def corevalue(encode_decode_input: str, is_encode):
		core_values = ['富强', '民主', '文明', '和谐', '自由',
		               '平等', '公正', '法治', '爱国', '敬业', '诚信', '友善']
		if is_encode:
			result = ""

			hexes = ""
			for c in encode_decode_input:
				if c in string.ascii_letters + string.digits + "-_.!~*'()":
					hexes += hex(ord(c))[2:]  # hex of UTF-8 code point
				else:
					hexes += c
			hexes = urllib.parse.quote(hexes).replace('%', '')
			# for each character

			core_value_indicies = []
			for h in hexes:
				# for each hex character in the hex value
				h_int = int(h, 16)
				if h_int < 10:
					core_value_indicies.append(h_int)
				else:
					# In the original implementation, (https://github.com/sym233/core-values-encoder/blob/a419ea532629782ebe7442a8682b72bb5ae3eab5/src/index.js#L51), random is introduced.
					# Although it doesn't effect decoding, I think it's a bad idea to produce possible different encoded text.
					# So, only the first case (if h_int>=10, push 10 and h_int-10) is kept
					# If you are wondering, the second case is (if h_int>=10, push 11 and h_int-11) and the posibility of each case is 50-50.
					core_value_indicies.append(10)
					core_value_indicies.append(h_int - 10)

			# map the ints to their corresponding core value phrase
			result += ''.join([core_values[core_value_index]
			                   for core_value_index in core_value_indicies])

		else:
			decode_map = dict(zip(core_values, range(len(core_values))))
			s_list = [encode_decode_input[i:i + 2] for i in range(0, len(encode_decode_input), 2)]
			core_value_indicies = [decode_map[core_value]
			                       for core_value in s_list]

			hexes = []
			is_skip = False
			for i in range(len(core_value_indicies)):
				if not is_skip:
					if core_value_indicies[i] < 10:
						hexes.append(str(core_value_indicies[i]))
					else:
						hexes.append(hex(core_value_indicies[i + 1] + 10)[2:])
						is_skip = True
				else:
					is_skip = False

			url_encoded = ""
			for i in range(len(hexes)):
				if i % 2 == 0:
					url_encoded += '%'
				url_encoded += hexes[i]

			result = urllib.parse.unquote(url_encoded)

		result = EncodeDecodeResult(algorithm="CoreValue", is_encode=is_encode,
		                            result=result)
		return result

	# Punycode
	@staticmethod
	def punycode(encode_decode_input: str, is_encode):
		if is_encode:
			result = encode_decode_input.encode('punycode').decode('utf8')
		else:
			result = encode_decode_input.encode('utf8').decode('punycode')
		result = EncodeDecodeResult(algorithm="Punycode", is_encode=is_encode,
		                            result=result)
		return result


class RSAKeyPair(models.Model):
	p = models.TextField(max_length=2048)
	q = models.TextField(max_length=2048)
	n = models.TextField(max_length=2048)
	e = models.TextField(max_length=2048)
	phi = models.TextField(max_length=2048)
	d = models.TextField(max_length=2048)

	# fields required by RFC2313
	dP = models.TextField(max_length=2048)
	dQ = models.TextField(max_length=2048)
	qInv = models.TextField(max_length=2048)

	@staticmethod
	def gen_rsa_keypair():
		"""
		Randomly generate a RSA key pair
		Returns ( public key, private key )
		"""
		p = generate_prime(1024)
		q = generate_prime(1024)
		n = p * q
		e = 65537  # 65537 is prime.

		phi = (p - 1) * (q - 1)
		d = invert(e, phi)

		dP = d % (p - 1)
		dQ = d % (q - 1)
		qInv = invert(q, p)
		return RSAKeyPair(p=p, q=q, n=n, e=e, phi=phi, d=d, dP=dP, dQ=dQ, qInv=qInv)

	def to_pri_pem_bytes(self):
		seq = Sequence()

		for idx, x in enumerate(
				[0, self.n, self.e, self.d, self.p, self.q, self.dP, self.dQ, self.qInv]
		):
			seq.setComponentByPosition(idx, Integer(x))

		return PEM_TEMPLATE % base64.encodebytes(encoder.encode(seq))


class IPLookupResult(models.Model):
	ip = models.CharField(max_length=100)
	domains = models.TextField(max_length=20000)  # each domain is seperated by '\n'

	# ip138
	headers_ip138 = {
		'Host'           : 'site.ip138.com',
		'User-Agent'     : ua.random,
		'Accept'         : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
		'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
		'Accept-Encoding': 'gzip, deflate, br',
		'Referer'        : 'https://site.ip138.com/'}
	# 爱站
	headers_aizhan = {
		'Host'           : 'dns.aizhan.com',
		'User-Agent'     : ua.random,
		'Accept'         : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
		'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
		'Accept-Encoding': 'gzip, deflate, br',
		'Referer'        : 'https://dns.aizhan.com/'}

	@staticmethod
	def ip138_spider(ip) -> Set:
		ip138_url = 'https://site.ip138.com/' + str(ip) + '/'
		ip138_r = requests.get(url=ip138_url, headers=IPLookupResult.headers_ip138, timeout=3).text
		ip138_address = re.findall(r"<h3>(.*?)</h3>", ip138_r)  # 归属地
		# result = re.findall(r"<li>(.*?)</li>", ip138_r)
		if '<li>暂无结果</li>' in ip138_r:
			return set()
		else:
			# print('[+]ip:{}'.format(ip))
			# print('归属地：{}'.format(ip138_address[0]))
			# result_time = re.findall(r"""class="date">(.*?)</span>""", ip138_r)  # 绑定时间
			return set(re.findall(r"""</span><a href="/(.*?)/" target="_blank">""", ip138_r))  # 绑定域名结果

	@staticmethod
	def aizhan_spider(ip) -> Set:
		aizhan_url = 'https://dns.aizhan.com/' + str(ip) + '/'
		aizhan_r = requests.get(url=aizhan_url, headers=IPLookupResult.headers_aizhan, timeout=3).text
		#  1. 取出该地址的真实地址
		aizhan_address = re.findall(r'''<strong>(.*?)</strong>''', aizhan_r)
		#  2. 取出该ip的解析过多少个域名
		aizhan_nums = re.findall(r'''<span class="red">(.*?)</span>''', aizhan_r)
		aizhan_domains = set()
		if len(aizhan_nums) != 0 and int(aizhan_nums[0]) > 0:
			if int(aizhan_nums[0]) > 20:
				# 计算多少页
				pages = (int(aizhan_nums[0]) % 20) + (int(aizhan_nums[0]) // 20)

				for page in range(1, pages + 1):
					aizhan_page_url = aizhan_url + str(page) + '/'
					# print(aizhan_page_url)
					aizhan_page_r = requests.get(url=aizhan_page_url, headers=IPLookupResult.headers_aizhan,
					                             timeout=3).text
					# 取出该ip曾经解析过多少个域名
					for domain in re.findall(r'''rel="nofollow" target="_blank">(.*?)</a>''', aizhan_page_r):
						aizhan_domains.add(domain)
					time.sleep(0.5)
			else:
				# 取出该ip曾经解析过多少个域名
				aizhan_domains = set(re.findall(r'''rel="nofollow" target="_blank">(.*?)</a>''', aizhan_r))
				for aizhan_domain in aizhan_domains:
					print(aizhan_domain)

		return aizhan_domains

	@staticmethod
	def get_ip_lookup_result(ip: str):
		ip138_result = IPLookupResult.ip138_spider(ip)
		aizhan_result = IPLookupResult.aizhan_spider(ip)
		total_result = ip138_result.union(aizhan_result)
		return IPLookupResult(ip=ip, domains='\n'.join(total_result))
