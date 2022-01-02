# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from django.db import models
from django.contrib.auth.models import User

import hashlib
import binascii
import base64
import urllib.parse
import quopri
import html
import codecs
import re

from apps.tools.int_to_bytes import int_to_bytes


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
	result = models.CharField(max_length=200000)

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
