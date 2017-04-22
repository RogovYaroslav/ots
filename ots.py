#!/usr/bin/env python3

from json import loads as jsonparse
import requests
from requests.auth import HTTPBasicAuth

from configparser import ConfigParser

from time import time, ctime

import re

from getopt import getopt
from getopt import GetoptError as goerror
from sys import argv
from os import environ as env

'''
	TODO:

		1. perms check and error
		2. Metakeys database

		MODES:
			main = share
			generate - ?
			retrieve

'''


configdir='~/.config/ots'

status_url='https://onetimesecret.com/api/v1/status'

status_url = 'https://onetimesecret.com/api/v1/status'
share_url = 'https://onetimesecret.com/api/v1/share'
generate_url = 'https://onetimesecret.com/api/v1/generate'
retrieve_url = 'https://onetimesecret.com/api/v1/secret/{}' # {} = SECRET_KEY
metadata_url = 'https://onetimesecret.com/api/v1/private/{}' # {} = METADATA_KEY
metadata_recent_url = 'https://onetimesecret.com/api/v1/private/recent'

# NON-API CALLS
# burn_url = 'https://onetimesecret.com/private/{}/burn'

timepat = re.compile(
'''
	(?:([1-9][0-9]*)[C])?\s*
	(?:([1-9][0-9]*)[D])?\s*
	(?:([1-9][0-9]*)[Y])?\s*
	(?:([1-9][0-9]*)[M])?\s*
	(?:([1-9][0-9]*)[W])?\s*
	(?:([1-9][0-9]*)[d])?\s*
	(?:([1-9][0-9]*)[h])?\s*
	(?:([1-9][0-9]*)[m])?\s*
	(?:([1-9][0-9]*)[s]?)?\s*
''',
flags=re.VERBOSE)

def share_secret(data, auth=None):
	"""
		TODO: docstring
	"""


	r = requests.post(share_url, data=data, auth=auth)
	if r.status_code != 200:
		print('Request error. Code:', r.status_code)
		print('Response: ', r.text)
		return None

	data = jsonparse(r.text)
	return data






def parsetime(s):

	"""
		Parses string in a form '1C 2D	3Y4M5W 6d7h8m9s' to time units respectively
			(Centuries, Decades, Years, Months and etc.)

		Returns time in seconds

	"""



	a = list(timepat.match(s).groups())
	for i in range(0,len(a)):
		if a[i] == None:
			a[i] = 0;
		a[i]=int(a[i])

	centuries, decades, years, months, weeks, days, hours, minutes, seconds = a;
	days = (centuries * 100 + decades * 10 + years) * 365.25 + months * 30.4375 + weeks * 7 + days
	seconds = ((days * 24 + hours) * 60 + minutes ) * 60 + seconds

	return int(seconds)


def print_metadata_default(meta, printmeta=True):

	"""
		Default function for printing received information about metadata

			meta -- dictionary (parsed from json)

		Keyword arguments:

			printmeta -- print information about metadata itself: key, expiration date (default: True)
	"""

	t = time()
	expired = meta['secret_ttl']<=0;

	print( 'Secret key:', meta['secret_key'] )
	if 'received' in meta:
		print( 'Recieved' if meta['received'] else 'Not Recieved')
	print( 'Expired' if expired else 'Expiring:', ctime(t+meta['secret_ttl']) )
	print( 'No passphrase' if meta['passphrase_required'] else 'Passphrase required' )
	if meta['recipient']:
		print( 'Recipient:', meta['recipient'] )

	if printmeta:
		mexpired = meta['metadata_ttl']<=0;
		print( 'Metadata key:', meta['metadata_key'] )
		print( 'Expired' if mexpired else 'Expiring:', ctime(t+meta['metadata_ttl']) )


def usage():
	USAGE = '''
	usage: ots [mode] [options] [arguments]

	ots (One Time Secret) is a open-source cli-program to work with onetimesecret.com (further Service) API.
	Program is in fact script written in Python (3.+).

	Secret is simply a message one would want to share with someone only one time.
	Being received, Secret's deleted forever, as stated by Service.

	ots provides a dozen of modes to work with.
	Modes are the following:

		-S  -  share a secret. Default mode
		-C  -  check availability of service. The only mode with no options and arguments
		-R  -  retrieve a secret
		-M  -  check metadata
		-G  -  generate a secret
		-L  -  get last metadata


		==================================================================
		SHARING A SECRET
		==================================================================

		Default mode that lets you to send a Secret and retrieve URL where one can view this Secret
		You can provide a few Units (that is just Secret's lines) that will be joined with newline as separator.

		-S is mode option for it

		usage:
			ots [-S] [options] [arguments]

		Options manage both configuration of a secret and secret's content.
		Arguments are used as in "echo" command: they concatenated with space as a delimeter

		Options:

			-f filename    -  add content of a file to m
			-s unit        -  add Unit to Secret list
			-t time        -  time-to-live for a Secret.
			                time is either a string in form "1Y2M3d4h5m6s" (where letters are corresponding time units)
                                     or simply a number of seconds.
			-r email       -  email where Secret's URL will be send to automatically through by Service itself.
			-i identity    -  identity is a name of a set of parameters in Credentials File. (see below in corresp. section)
			-p passphrase  -  passphrase used to encrypt Secret. Hashed via bcrypt, as stated by Service.
			-q             -  quiet: print only Secret Key


	'''


if __name__ != '__main__':
	exit()

print_metadata = print_metadata_default

try:
	opts, args = getopt(argv[1:], 'CSGRMLs:p:t:f:r:i:q')
except goerror as err:
	print(err)
	usage()
	exit(2)

modes=[ k[0] for k in filter(lambda a: a[0][1:] in 'CSGRML' and not a[0][2:], opts)]

if len(modes) == 0:
	mode = '-S'
else:
	mode = modes[-1]


if mode == '-C':
	r = req.get(status_url);
	status = jsonparse(r.text)['status']
	if r.status_code=='200' and status == 'nominal':
		print( 'Online' )
		exit(0)
	exit(1)

if mode == '-S':

	data = {
		'secret' : '',
		'passphrase' : '',
		'ttl' : str(7*24*60*60), # default: 1 week
		'recipient' : ''
	}

	auth=None
	quiet=False
	secret=[]

	for o in opts:
		k = o[0]
		arg = o[1]

		if '-q' == k:
			quiet=True

		if '-f' == k:
			try:
				with open(arg) as f:
					secret.append(f.read())
			except IOError as err:
				print(err)
				exit(1)

		if '-s' == k:
			secret.append(arg)
			continue

		if '-t' == k:
			data['ttl'] = str(parsetime(arg))
			continue

		if '-r' == k:
			data['recipient'] = arg;
			continue

		if '-i' == k:
			# TODO!
			continue

		if '-p' == k:
			data['passphrase'] = arg
			continue

	if len(args) != 0:
		secret.append(' '.join(args))

	if len(secret) == 0:
		print( 'ERROR: No secret provided' )
		exit(1)

	data['secret']	= '\n'.join(secret)

	# print(data)

	meta = share_secret(data, auth)

	if meta == None:
		exit(3)

	if quiet:
		print(meta['secret_key'])
	else:
		print_metadata(meta)

	exit(0)



if mode == '-G':
	print( 'Not supported yet' )
	exit(1)


# if ''
