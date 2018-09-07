#!/usr/bin/python3

# (c) 2018 by sin@imacandi.net - All rights reserved
#
#
# All the files must be installed under /opt/kaa/
#   - /bin/ -> all the .py files
#   - /etc/ -> config.json
#
# What:
#   alert_manager listens for log messages POSTed by the HX system
#   and will initiate file acquisitions for identified malicious files
#
# Dependencies:
#   - Python 3.6 or above
#   - python libraries: http.server, pprint, json, urllib3, base64, redis
#   - Redis 4.0 or higher
#
# Supported operating system: Ubuntu 18.04 LTS
#
# TLS connections:
#   If you choose to run the alert_maager over HTTPS,
#   the certfile configuration option must point to a file that
#   contains the digital certificate and its key.
#   The key MUST NOT have a password set.

from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import json
import urllib3
import base64
import syslog
import ssl
import os
import redis as redislib

with open('/opt/kaa/etc/config.json') as config_file:
    cfg = json.load(config_file)
HX_HOST = cfg['hx']['host']
HX_PORT = cfg['hx']['port']
HX_API_USER = cfg['hx']['user']
HX_API_PASS = cfg['hx']['password']
DST_ROOT = cfg['hx']['dst']['root']
REDIS_HOST = cfg['hx']['redis']['host']
REDIS_PORT = cfg['hx']['redis']['port']
REDIS_PASSWORD = cfg['hx']['redis']['password']
REDIS_DB = cfg['hx']['redis']['db']
REDIS_SET = cfg['hx']['redis']['set']
HTTP_ADDRESS = cfg['hx']['http_listener']['address']
HTTP_PORT = cfg['hx']['http_listener']['port']
HTTP_SECURE = cfg['hx']['http_listener']['secure']
HTTP_CERT = cfg['hx']['http_listener']['certfile']

if cfg['debug']['enabled'] == 1:
    DEBUG=True
else:
    DEBUG=False

if REDIS_PASSWORD == "null":
    redis = redislib.Redis(host=REDIS_HOST,
                           port=REDIS_PORT,
                           db=REDIS_DB)
else:
    redis = redislib.Redis(host=REDIS_HOST,
                           port=REDIS_PORT,
                           db=REDIS_DB,
                           password=REDIS_PASSWORD)

syslog.openlog(logoption=syslog.LOG_PID)

hx_auth_info = base64.b64encode(':'.join([HX_API_USER, HX_API_PASS]).encode('UTF-8'))
urllib3.disable_warnings()

hx = urllib3.HTTPSConnectionPool(
    host=HX_HOST,
    port=HX_PORT,
    cert_reqs='CERT_NONE',
    assert_hostname=False
)

def request_acquisition(full_path, f_name, agent_id):
    try:
        r = hx.request(
            'GET',
            '/hx/api/v3/token',
            headers={
                'Accept': 'application/json',
                'Authorization': "Basic {}".format(hx_auth_info.decode('UTF-8'))
            }
        )
    except urllib3.exceptions.MaxRetryError as e:
        syslog.syslog(syslog.LOG_ERR, f'[ERR]: api_token_request: Could not connect to the HX system: {e}')
        raise Exception(f'[ERR]: api_token_request: Could not connect to the HX system: {e}')
    try:
        if r.status == 204:
			fe_api_token = r.headers['X-FeApi-Token']
				if DEBUG:
					syslog.syslog(syslog.LOG_DEBUG,f'[DBG]: API token received: {fe_api_token}')
        elif r.status == 401:
            syslog.syslog(syslog.LOG_ERR,'[ERR]: HX authentication information is incorrect.')
            raise Exception('[ERR]: hx_get_api_token: HX authentication information is incorrect.')
	acq = dict([('req_path', full_path), ('req_filename', f_name)])
		try:
            r = hx.request(
                'POST',
                f'/hx/api/v3/hosts/{agent_id}/files',
                headers={
                    'X-FeApi-Token': fe_api_token,
                    'Content-Type': 'application/json'
                },
            )
		if r.status == 200:
			response = json.loads(r.data.decode('UTF-8'))
        	download_url = response['data']['url']
        	redis.sadd(REDIS_SET,download_url[22:])
   		 else:
			syslog.syslog(syslog.LOG_ERR,'[ERR]: Error getting the download URL for file.')

class ThreadedHTTPServer(HTTPServer, ThreadingMixIn):
	pass

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def do_GET(self):
        self.send_response(200)
        self.end_headers()

    def do_POST(self):
        def log_message(self, format, *args):
            return
        try:
            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length)
            self.send_response(200)
            self.end_headers()
            msg = json.loads(body.decode('UTF-8'))
            if msg['alert']['event_type'] == "fileWriteEvent":
                agent_id = msg['alert']['host']['agent_id']
                f_path = msg['alert']['event_values']['fileWriteEvent/filePath']
                f_drive = msg['alert']['event_values']['fileWriteEvent/drive']
                full_path = ''.join([f_drive, ':\\', f_path])
                f_name = msg['alert']['event_values']['fileWriteEvent/fileName']
                request_acquisition(full_path=full_path, f_name=f_name, agent_id=agent_id)
        except Exception as e:
            syslog.syslog(syslog.LOG_ERR,f'[ERR]: Error processing the received POST for agent ID {agent_id}: {e}')

syslog.syslog(syslog.LOG_INFO,f'[INF]: Application started from {os.path.dirname(os.path.abspath(__file__))}')

httpd = ThreadedHTTPServer((HTTP_ADDRESS, HTTP_PORT), SimpleHTTPRequestHandler)
if HTTP_SECURE == 1:
    httpd.socket = ssl.wrap_socket(sock=httpd.socket,certfile=HTTP_CERT,server_side=True,ssl_version=ssl.PROTOCOL_TLSv1_2)
httpd.serve_forever()
