#!/usr/bin/env python3

from json import loads as jsonparse
from json.decoder import JSONDecodeError
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
		3. clipboard

		MODES:
			main = share
			generate - ?
			retrieve

'''

def usage():
	USAGE = '''
	usage: ots [mode] [options] [arguments]

	ots (One Time Secret) is a open-source cli-program to work with onetimesecret.com (further Service) API.
	Program is in fact script written in Python (3.+).

	Secret is simply a message one would want to share with someone only one time.
	Being received, Secret's deleted forever, as stated by Service.

	So called Identity is simply a pair EMAIL:APIKEY stored from Credentials File. (see below in Credentials section)
	It's used for authentification in Service

	ots provides a dozen of modes to work with.
	Modes are the following:

		-S  -  share a secret. Default mode
		-C  -  check availability of service. The only mode with no options and arguments
		-R  -  retrieve a secret
		-B  -  burn a secret
		-M  -  check metadata
		-G  -  generate a secret
		-L  -  get last metadata


	Common options for all modes (except availability check -C):

		-i identity -  use identity (email, apikey) from Crdentials File for authentication

		Following options override corresponding auth data received with -i option.

		-e email    -  email for authentication
		-a apikey   -  apikey for authentication

		-k key      -  metadata or secret key depending on mode
		-v          -  verbose. Print as much information as possible
		-q          -  quiet. Return only exit code

	==================================================================
	SHARING A SECRET (-S)
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
		-c             -  copy result to clipboard (via xsel or xclip). Implies -q


	==================================================================
	RETRIEVING A SECRET (-R)
	==================================================================

	Mode for retrieving a Secret. It's content, that is.

	Common option -k provides Secret Key
	Secret Key can be provided as an argument (or list of them, if key's happened to have spaces somehow)

	==================================================================
	CHECKING A SECRET WITH METADATA (-M)
	==================================================================

	without -v common option returns only Secret Key associated with Metadata Key provided


	EXIT CODES
		0 - everything is OK
		1 - program failed
		2 - wrong options/usage
		3 - Service failed or wrong parameters




	'''

configdir='~/.config/ots'

status_url = 'https://onetimesecret.com/api/v1/status'
share_url = 'https://onetimesecret.com/api/v1/share'
generate_url = 'https://onetimesecret.com/api/v1/generate'
retrieve_url = 'https://onetimesecret.com/api/v1/secret/{}' # {} = SECRET_KEY
metadata_url = 'https://onetimesecret.com/api/v1/private/{}' # {} = METADATA_KEY
metadata_recent_url = 'https://onetimesecret.com/api/v1/private/recent'
burn_url = 'https://onetimesecret.com/api/v1/burn/{}' # {} = METADATA_KEY

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

def print_dummy(a):
	"""
		Does nothing
		Used as a (print=print_dummy) when -q quiet option provided
	"""
	return

def print_request_error(request, process_name):
	print('[ERROR] Request error during', process_name)
	print('  Code:', request.status_code)
	print('  Response:', request.text)


def api_call(url, data, process_name, auth=None, forcereturn=False):
	r = requests.post(url, data=data, auth=auth)
	# print(r.url)
	if r.status_code != 200:
		print('[ERROR] Request error during', process_name)
		print('  Code:', r.status_code)
		print('  Response:', r.text)
		if not forcereturn:
			return None

	try:
		data = jsonparse(r.text)
	except JSONDecodeError:
		data = {}

	return data

def check_availability():
	r = requests.get(status_url);
	if r.status_code==200:
		status = jsonparse(r.text)['status']
		if status == 'nominal':
			print('Online')
			return True
		print('Offline. Status:', status)
	else:
		print('Offline')
	return False;


def share_secret(data, auth=None):
	"""
		TODO: docstring
	"""
	return api_call(share_url, data, 'sharing a Secret', auth=auth)

def retrieve_secret(data, auth=None):
	return api_call(retrieve_url.format(data['secret_key']), data, 'retrieving a Secret', auth=auth)

def retrieve_metadata(data, auth=None):
	return api_call(metadata_url.format(data['metadata_key']), None, 'retrieving Metadata', auth=auth)

def retrieve_latest_metadata(data, auth=None):
	#TODO
	return

def generate_secret(data, auth=None):
	#TODO
	return

def burn_secret(data, auth=None):
	return api_call(burn_url.format(data['metadata_key']), None, 'burning a secret', auth=auth)




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


def print_metadata_default(meta, print_recieve=True, print_meta=True):

	"""
		Default function for printing received information about metadata

			meta -- dictionary (parsed from json)

		Keyword arguments:

			print_recieve -- if secret was just created so information about receivement's not needed
			print_meta -- print information about metadata itself: key, expiration date (default: True)
	"""

	t = time()

	# print(meta)

	print( 'Secret key:', meta['secret_key'] )


	if 'state' in meta and print_recieve: # new, viewed (via metadata) or received (burn may be?)
		"""
			4 possible state:
				new - created and metadata wasn't checked
				viewed - metadata was checked at least once
				received - secret was received
				burned - secret was burned
		"""

		if meta['state'] == 'received':
			print( 'Recieved in {}'.format(ctime(meta['received'])) )
		elif meta['state'] == 'burned':
			print( 'Burned in {}'.format(ctime(meta['updated'])))
		else:
			print('Not Recieved')

	else:
		expired = meta['secret_ttl']<=0;
		print( 'Expired' if expired else 'Expiring:', ctime(t+meta['secret_ttl']) )

	if 'passphrase_required' in meta:
		print( 'Passphrase required' if meta['passphrase_required'] else 'No passphrase' )
	if meta['recipient']:
		print( 'Recipient:', meta['recipient'] )

	if print_meta:
		mexpired = meta['metadata_ttl']<=0;
		print( 'Metadata key:', meta['metadata_key'] )
		print( 'Expired' if mexpired else 'Expiring:', ctime(t+meta['metadata_ttl']) )


if __name__ != '__main__':
	exit()

print_metadata = print_metadata_default

try:
	opts, args = getopt(argv[1:],
		'CSGRML' #Modes
		+ 'vqi:e:a:k:' # Common options
		+ 's:p:t:f:r:' # -S share options
		)
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
	if check_availability():
		exit(0)
	else:
		exit(1)


key = ''
identity = ['','']
email = ''
apikey = ''
verbose = False

for o in opts:
	k = o[0]
	arg = o[1]

	if '-e' == k:
		email = arg
		continue

	if '-a' == k:
		apikey = arg
		continue

	if '-i' == k:
		i = get_identity(arg)
		if i == None:
			print('[ERROR] No identity {} found'.format(arg))
			exit(1)
		identity = i

	if '-q' == k:
		print = print_dummy

	if '-v' == k:
		verbose = True



if len(email) != 0:
	identity[0] = email

if len(apikey) != 0:
	identity[1] = apikey

if len(identity[0]) == 0 or len(identity[1]) == 0:
	auth = None
else:
	auth = HTTPBasicAuth(identity)



# Sharing a secret
if mode == '-S':

	data = {
		'secret' : '',
		'passphrase' : '',
		'ttl' : str(7*24*60*60), # default: 1 week
		'recipient' : ''
	}

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

	if verbose:
		print_metadata(meta)
	else:
		print(meta['secret_key'])

	exit(0)


# Checking a metadata
if mode == '-M':
	data = {	'metadata_key' : '' }

	metadata_key = key

	if len(metadata_key) == 0:
		metadata_key=' '.join(args)

	if len(metadata_key) == 0:
		print('[ERROR] No metadata key was provided')
		exit(2)

	data['metadata_key'] = metadata_key

	meta = retrieve_metadata(data, auth=auth)

	if meta == None:
		exit(3)

	print_metadata(meta, print_meta=False)

	exit(0)

# Retrieve a secret
if mode == '-R':

	data = { 'secret_key' : '' }

	secret_key = key

	if len(secret_key) == 0:
		secret_key = ' '.join(args)

	if len(secret_key) == 0:
		print('[ERROR] No secret key was provided')
		exit(2)

	data['secret_key'] = secret_key

	response = retrieve_secret(data, auth=auth)

	if response == None:
		exit(3)

	if verbose:
		print('Secret Key:', response['secret_key'])
		print('Value:', response['value'])
	else:
		print(response['value'])

	exit(0)


# Generate a secret
if mode == '-G':
	print( 'Not supported yet' )
	exit(1)


# Retrieve set of metadata for last secrets
if mode == '-L':
	print( 'Not supported yet' )
	exit(1)

# Burn a Secret
if mode == '-B':
	print( 'Not supported yet' )
	exit(1)



usage()
exit(1)