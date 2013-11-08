import socket
import sys
import re

class protocols:
	"""
	attempt to create an IP protocols database from

	a) socket.IPPROTO_* constants and
	b) the host system's protocols file

	"""
	__default_protocols_file = '/etc/protocols'
	__win32_protocols_file = 'C:\\WINDOWS\\system32\\drivers\\etc\\protocols'

	def __init__(self):
		self._protocols = {}
		_protocolsfile = self.__default_protocols_file
		### Cygwin symlinks /etc/protocols -> /cygdrive/C/WINDOWS/system32/drivers/etc/protocols
		if sys.platform.startswith('win32'):
			_protocolsfile = self.__win32_protocols_file

		### grab constants from socket.IPPROTOCOL_*
		for c in dir(socket):
			m = re.search("^IPPROTO_(\w+)$", c)
			if m and len(m.group(1)) > 0:
				try:
					code = int(eval("socket."+c))
					self._protocols[code] = m.group(1)
				except AttributeError as e:
					pass

		### overlay the host system protocols database (if available)
		try:
			f = open(_protocolsfile,"r")
			for line in f:
				if re.match("^(#.*|\s*)$",line): continue
				m = re.search("^([\w\-]+)\s+(\d+)\s+([\w\-]+)\s+.*",line)
				if m and len(m.group(0)) > 0:
					self._protocols[int(m.group(2))] = str((m.group(1))).upper()
			f.close()

		except IOError as e:
			pass

	def get(self):
		"""
		get full table/dict
		"""
		return self._protocols

	def getbynum(self,num):
		"""
		get the name of the protocol given the integer code
		"""
		_result = None
		if num in self._protocols:
			_result = self._protocols[num]

		return _result

	def getbyname(self,name):
		"""
		get the integer code given the name
		"""
		_result = None
		for i in self._protocols.items():
			if i[1] == name: # re.match?
				_result = i[0]

		return _result

	def dump(self):
		"""
		print a table of int: name pairs
		"""
		print "=== Default IP protocols database ===\n"
		for i in self._protocols.items():
			print "{0}: {1}".format(i[0],i[1])

if __name__ == "__main__":
	IPProtocol().dump()

