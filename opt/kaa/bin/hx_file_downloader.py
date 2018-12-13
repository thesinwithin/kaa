#!/usr/bin/python3

# (c) 2018 by sin@imacandi.net - All rights reserved.
#
#
# All the files must be installed under /opt/kaa/
#   - /bin/ -> all the .py files
#   - /etc/ -> config.json
#
# What:
#   hx_file_downloader checks periodically if any downloads are pending,
#   then checks if the file acquisitions have completed and if yes,
#   downloads and extract the file
#
# Dependencies:
#   - Python 3.6 or above
#   - python libraries: http.server, pprint, json, urllib3, base64, redis
#   - Redis 4.0 or higher
#
# Supported operating system: Ubuntu 18.04 LTS

import redis as redislib
import urllib3
import zipfile
import base64
import time
import json
import os
import shutil
import syslog

with open('/opt/kaa/etc/config.json') as config_file:
    cfg = json.load(config_file)
HX_HOST = cfg['hx']['host']
HX_PORT = cfg['hx']['port']
HX_API_USER = cfg['hx']['user']
HX_API_PASS = cfg['hx']['password']
CHECK_INTERVAL = cfg['hx']['interval']
DST_ROOT = cfg['hx']['dst']['root']
TEMPDIR = cfg['hx']['dst']['tempdir']
REDIS_HOST = cfg['hx']['redis']['host']
REDIS_PORT = cfg['hx']['redis']['port']
REDIS_PASSWORD = cfg['hx']['redis']['password']
REDIS_DB = cfg['hx']['redis']['db']
REDIS_SET = cfg['hx']['redis']['set']
HTTP_ADDRESS = cfg['hx']['http_listener']['address']
HTTP_PORT = cfg['hx']['http_listener']['port']
HTTP_SECURE = cfg['hx']['http_listener']['secure']
if HTTP_SECURE == 1:
    HTTP_CERT = ''.join(['/opt/kaa/etc/tls/',cfg['hx']['http_listener']['certfile']])
if cfg['hx']['debug']['enabled'] == 1:
    DEBUG=True
else:
    DEBUG=False


syslog.openlog(logoption=syslog.LOG_PID)

if REDIS_PASSWORD == "null":
    redis = redislib.Redis(host=REDIS_HOST,
                           port=REDIS_PORT,
                           db=REDIS_DB)
else:
    redis = redislib.Redis(host=REDIS_HOST,
                           port=REDIS_PORT,
                           db=REDIS_DB,
                           password=REDIS_PASSWORD)

hx_auth = base64.b64encode(':'.join([HX_API_USER, HX_API_PASS]).encode('UTF-8'))

urllib3.disable_warnings()

hx = urllib3.HTTPSConnectionPool(
    host=HX_HOST,
    port=HX_PORT,
    cert_reqs='CERT_NONE',
    assert_hostname=False
    )

def download_file(fid):
    d_s = 1
    try:
        r = hx.request(
            'GET',
            '/hx/api/v3/token',
            headers={
                'Accept': 'application/json',
                'Authorization': "Basic {}".format(hx_auth.decode('UTF-8'))
            }
        )
    except urllib3.exceptions.MaxRetryError as e:
        syslog.syslog(syslog.LOG_ERR, f'[ERR]: api_token_request: Could not connect to the HX system: {e}')
        raise Exception('[ERR]: api_token_request: Could not connect to the HX system: {e}')
    if r.status == 204:
        fe_api_token = (r.headers['X-FeApi-Token'])
    elif r.status == 401:
        syslog.syslog(syslog.LOG_ERR,f'[ERR]: hx_auth: Incorrect username/password. HTTP call status: {r.status}')
        raise Exception(f'[ERR]: hx_auth: Incorrect username/password. HTTP response: {r.status}')
    try:
        r = hx.request(
                'GET',
                f'/hx/api/v3/acqs/files/{fid}',
                headers={
                    'X-FeApi-Token': fe_api_token
                }
        )
    except Exception as e:
        syslog.syslog(syslog.LOG_ERR,f'[ERR]: Error encountered trying to get information on FID {fid}: {e}')
        raise Exception(f'[ERR]: get_fid_details: Error encountered getting details for FID {fid}: {e}')
    try:
        resp = json.loads(r.data.decode('UTF-8'))
    except Exception as e:
        syslog.syslog(syslog.LOG_ERR,f'[ERR]: fid_response_to_json: Error loading the response for FID {fid}: {e}')
        raise Exception(f'[ERR]: fid_response_to_json: Error loading the response for FID {fid}: {e}')
    if resp['message'] == "OK":
        if resp['data']['state'] == "COMPLETE":
            file = resp['data']['req_filename']
            zip_password = resp['data']['zip_passphrase']
            try:
                r = hx.request(
                    'GET',
                    f'/hx/api/v3/acqs/files/{fid}.zip',
                    headers={
                        'X-FeApi-Token': fe_api_token
                    },
                    preload_content=False
                )
            except Exception as e:
                syslog.syslog(syslog.LOG_ERR,f'[ERR]: acquisition_file_download: Error getting the file for FID {fid}: {e}')
            try:
                with open(f'{TEMPDIR}/{fid}.zip', 'wb') as outfile:
                    while True:
                        zipdata = r.read()
                        if not zipdata:
                            break
                        outfile.write(zipdata)
                        syslog.syslog(syslog.LOG_ERR, f'downloaded {fid}')
                d_s = 0
            except Exception as e:
                syslog.syslog(syslog.LOG_ERR,f'[ERR]: zip_save_to_disk: Error occured for FID {fid}: {e}')
            try:
                with zipfile.ZipFile(f'{TEMPDIR}/{fid}.zip') as zf:
                    if f'{file}_' in zf.namelist():
                        syslog.syslog(syslog.LOG_ERR, f'{TEMPDIR} - {fid} - {file}_')
                        zf.extract(f'{file}_', path=f'{TEMPDIR}/', pwd=bytes(zip_password,encoding='UTF-8'))
                        os.remove(f'{TEMPDIR}/{fid}.zip')
                        os.rename(f'{TEMPDIR}/{file}_', f'{TEMPDIR}/{fid}_{file}')
                        syslog.syslog(syslog.LOG_ERR, f'{TEMPDIR} - {fid} - {file}')
                        # copy the file in all the SRC folders that will be inspected by the AX system
                        # this is done in order to ensure that a potentially malicious file is passed
                        # thtough all the available operating systems supported by the AX
                        shutil.copy(f'{TEMPDIR}/{fid}_{file}', f'{DST_ROOT}/osx10_13/{fid}_{file}')
                        shutil.copy(f'{TEMPDIR}/{fid}_{file}', f'{DST_ROOT}/osx10_8/{fid}_{file}')
                        shutil.copy(f'{TEMPDIR}/{fid}_{file}', f'{DST_ROOT}/win10x64m/{fid}_{file}')
                        shutil.copy(f'{TEMPDIR}/{fid}_{file}', f'{DST_ROOT}/win7sp1m/{fid}_{file}')
                        shutil.copy(f'{TEMPDIR}/{fid}_{file}', f'{DST_ROOT}/win7x64sp1m/{fid}_{file}')
                        shutil.copy(f'{TEMPDIR}/{fid}_{file}', f'{DST_ROOT}/winxpsp1m/{fid}_{file}')
                        os.remove(f'{TEMPDIR}/{fid}_{file}')
                    else:
                        os.remove(f'{TEMPDIR}/{fid}.zip')
                        syslog.syslog(syslog.LOG_INFO,f'[INF]: extract_acquisition_file: Acquisition for FID {fid} did not contain the file {file}.')
            except Exception as e:
                syslog.syslog(syslog.LOG_ERR,f'[ERR]: unzip_acquisition_file: Acquisition for FID {fid} was not successful: {e}')
    try:
        r = hx.request(
            'DELETE',
            '/hx/api/v3/token',
            headers={
                'X-FeApi-Token': fe_api_token
            }
        )
    except Exception as e:
        syslog.syslog(syslog.LOG_ERR,f'[ERR]: hx_session_cleanup: Error cleaning up the API session: {e}')
    return d_s
syslog.syslog(syslog.LOG_INFO,f'[INF]: Application started from {os.path.dirname(os.path.abspath(__file__))}')

while True:
    fids = redis.smembers(REDIS_SET)
    if len(fids) > 0:
        for fid in sorted(fids):
            # if _stop_ is found as a FID, the downloader will exit gracefully
            # this is done in order to ensure that you don't stop the program mid-download
            if fid == b'stop':
                syslog.syslog(syslog.LOG_INFO,'[INF]: FID "stop" found. Exiting cleanly.')
                syslog.closelog()
                redis.srem(REDIS_SET,'stop')
                exit(0)
            try:
                res = download_file(fid=int(fid))
                # if 0 = the download completed successfuly
                # if 1 = the download failed and you should check the logs to see why
                if res == 0:
                    dl_status = 0
                else:
                    dl_status = 1
            except Exception as e:
                syslog.syslog(syslog.LOG_ERR,f'[ERR]: download_file: Exception encountered: {e}')
                dl_status = 1
                raise Exception(f'[ERR]: download_file: Exception encountered: {e}')
            if dl_status == 0:
                redis.srem(REDIS_SET, fid)
            time.sleep(1)
    else:
        syslog.syslog(syslog.LOG_INFO,f'[INF]: No new acquisitions queued. Checking again in {CHECK_INTERVAL}s.')
        time.sleep(CHECK_INTERVAL)
