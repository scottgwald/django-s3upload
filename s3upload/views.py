from base64 import b64encode
from datetime import datetime, timedelta
from json import dumps
from mimetypes import guess_type
from os import path
from uuid import uuid4
import hmac
import sha

import boto

from django.conf import settings
from django.http import HttpResponse
from django.shortcuts import render_to_response
from django.utils import simplejson

s3 = boto.connect_s3()
bucket = s3.get_bucket('jamski2014')
bucket.list()
bucketList = bucket.list()
for file in bucketList:
   print file.name

def index(request):
    return render_to_response('index.html', {"settings": settings})

def bucket_files(request):
    data = [];
    for file in bucketList:
        data.append(file.name)
    jdata = simplejson.dumps(data)
    return HttpResponse(jdata, mimetype='application/json')

def static(request, filename):
    try:
        with open(path.join(settings.STATIC_ROOT, path.basename(filename))) as handle:
            response = HttpResponse(handle.read())
            mimetype, encoding = guess_type(filename)
            if mimetype:
                response['Content-Type'] = mimetype
            return response
    except IOError:
        return HttpResponse("No such file or directory", status=404)

def get_upload_params(request):
    def make_policy():
        policy_object = {
            "expiration": (datetime.now() + timedelta(hours=24)).strftime('%Y-%m-%dT%H:%M:%S.000Z'),
            "conditions": [
                { "bucket": settings.AWS_S3_BUCKET_NAME },
                { "acl": "public-read" },
                ["starts-with", "$key", "uploads/"],
                { "success_action_status": "201" }
            ]
        }
        return b64encode(dumps(policy_object).replace('\n', '').replace('\r', ''))

    def sign_policy(policy):
        return b64encode(hmac.new(settings.AWS_SECRET_ACCESS_KEY, policy, sha).digest())

    policy = make_policy()
    return HttpResponse(dumps({
        "policy": policy,
        "signature": sign_policy(policy),
        "key": "uploads/" + uuid4().hex + ".bin",
        "success_action_redirect": "/"
    }), content_type="application/json")
