#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Markus Thilo'
__version__ = '0.1-20200306'
__license__ = 'GPL-3'
__doc__ = '''
Wrapper for zeek-cut
This is executed: cat <logfiles> | zeek-cut [<options>] <columns>
Usage:
zeeklog = ZeekCut(
	logfiles,
	columns = ['ts', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p'],
	options = '-d'
)
for line in zeeklog.gentsv:
	print(line)
for line in zeeklog.gentsv:
	print(line)
print(zeeklog.json)
print(zeeklog.data)
'''

from subprocess import Popen, PIPE
from json import dumps

class ZeekCut:
	'Python wrapper for zeek-cut'

	ZEEKCUT = '/usr/local/zeek/bin/zeek-cut'	# set path to zeek-cut here!!!

	def __init__(self,
		logfiles,
		columns = ['ts', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p'],
		options = None
	):
		'''
			Create Object for zeek-cut:
			cat logfile | zeek-cut [<options>] <columns>
			Warning: -c does not work!
		'''
		self.logfiles = []	# create a list of filenames as strings
		if isinstance(logfiles, str):
			self.logfiles = [logfiles]
		else:
			for logfile in logfiles:
				if isinstance(logfile, str):
					self.logfiles.append(logfile)
				else:
					self.logfiles.append(logfile.name)
		cat_cmd = ['cat']	# assemble shell command for cat
		cat_cmd.extend(self.logfiles)
		zeek_cmd = [self.ZEEKCUT]	# assemble shell command for zeek-cut
		if options != None:
			zeek_cmd.extend(self.__convert2list__(self.options))
		zeek_cmd.extend(self.__convert2list__(columns))
		cat = Popen(cat_cmd, stdout=PIPE)	# generate cat
		zeekcut = Popen(zeek_cmd, stdin=cat.stdout, stdout=PIPE)	# generate zeek-cut
		lines = zeekcut.communicate()[0].decode().rstrip('\n').split('\n')	# read lines from stdout
		self.data = [{colname: colvalue for colname, colvalue in zip(zeek_cmd[-1*len(lines[0].split('\t')):], line.split('\t'))} for line in lines]

	def __convert2list__(self, arg):
		'Convert argument to a list'
		if isinstance(arg, str):
			return [arg]
		return list(arg)

	def gentsv(self):
		'Generator for TSV format'
		for line in self.data:
			yield ''.join(map(lambda tab: f'{line[tab]}\t', line))[:-1]

	def gencsv(self):
		'Generator for CSV format'
		for line in self.data:
			yield ''.join(map(lambda tab: f'"{line[tab]}",', line))[:-1]

	def json(self):
		'Give data in JSON format'
		return dumps(self.data)
