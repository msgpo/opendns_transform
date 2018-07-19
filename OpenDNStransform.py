''' 
Copyright (c) 2014, OpenDNS, Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
'''

import sys
import requests
import json

from MaltegoTransform import *

api_url = 'https://investigate.api.umbrella.com'	# OpenDNS Investigate API URL
api_key = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' 	# OpenDNS Investigate API key. Obtain from OpenDNS.
headers = {'Authorization': 'Bearer ' + api_key}

class NoContentAPI(Exception):
    def __init__(self, message, suggestion):
        self.message = message
        self.suggestion = suggestion

class GenericErrorAPI(Exception):
    def __init__(self, message, suggestion):
        self.message = message
        self.suggestion = suggestion

def call_api(url):
    try:
        resp = requests.get(url, headers=headers)
    except:
        raise GenericErrorAPI(message="Could not send request to OpenDNS API", 
            suggestion="Ensure API key is correct, requests python library is installed, and machine has network connectivity")
    if resp.status_code == 204:
        raise NoContentAPI(message="OpenDNS API returned: 204 No Content.", suggestion="Try a different domain name")
    elif resp.status_code != 200:
        raise GenericErrorAPI(message="OpenDNS API returned: %s" % (resp.status_code), suggestion="Ensure API key is correct")
    elif json.loads(resp.content) == {}:
        raise GenericErrorAPI(message="OpenDNS API returned an empty response", suggestion="Try again or try a different domain/ip")
    else:
        return json.loads(resp.content)

def post_api(url, data):
    try:
        resp = requests.post(url, data=data, headers=headers)
    except:
        raise GenericErrorAPI(message="Could not send request to OpenDNS API", 
            suggestion="Ensure API key is correct, requests python library is installed, and machine has network connectivity")
    if resp.status_code == 204:
        raise NoContentAPI(message="OpenDNS API returned: 204 No Content.", suggestion="Try a different domain name")
    elif resp.status_code != 200:
        raise GenericErrorAPI(message="OpenDNS API returned: %s" % (resp.status_code), suggestion="Ensure API key is correct")
    elif json.loads(resp.content) == {}:
        raise GenericErrorAPI(message="OpenDNS API returned an empty response", suggestion="Try again or try a different domain/ip")
    else:
        return json.loads(resp.content)

def domains_to_attributes(mt, names):
    url = api_url + '/domains/categorization/'
    category_endpoint = api_url + '/domains/categories/'
    status_index = {-1:"Blacklisted", 0:"Unknown", 1:"Whitelisted"}
    names = [name[:-1] if name.endswith('.') else name for name in names]
    if not names:
        return mt

    try:
        r = post_api(url, json.dumps(names))
        categories = call_api(category_endpoint)
    except:
        mt.addUIMessage(message="OpenDNS API returned invalid results from domains_to_attributes_function", 
                        messageType="PartialError")
        mt.addUIMessage(message="Ensure API key is correct", 
                        messageType="PartialError")
        return mt

    for name in names:
        if name not in r:
            mt.addUIMessage(message="OpenDNS API returned invalid results from domains_to_attributes_function", 
                            messageType="PartialError")
            mt.addUIMessage(message="Ensure API key is correct", 
                            messageType="PartialError")

        if 'status' not in r[name] or 'security_categories' not in r[name] or 'content_categories' not in r[name]:
            mt.addUIMessage(message="OpenDNS API returned invalid results from domains_to_attributes_function", 
                            messageType="PartialError")
            mt.addUIMessage(message="Ensure API key is correct", 
                            messageType="PartialError")

        security_categories = [categories[i] for i in r[name]['security_categories'] if i in categories]
        content_categories = [categories[i] for i in r[name]['content_categories'] if i in categories]
        entity = mt.addEntity(enType="maltego.Domain", enValue="%s" % (name))
        entity.addAdditionalFields("Status", "Status", "static", status_index[r[name]['status']])
        entity.addAdditionalFields("Security Category", "Security Category", "static", ','.join(security_categories))
        entity.addAdditionalFields("Content Category", "Content Category", "static", ','.join(content_categories))
        
    return mt

def domain_to_cooccurences(mt, name):
    url = api_url + '/recommendations/name/%s.json' % (name)
    if name.endswith('.'):
        name = name[:-1]
    try:
        r = call_api(url)
        if 'pfs2' not in r:
            raise GenericErrorAPI(message="OpenDNS API returned invalid results from domain_to_cooccurences function", 
                suggestion="Ensure API key is correct")
        names = [name[0] for name in r['pfs2']]
        mt = domains_to_attributes(mt, names)
    except (NoContentAPI, GenericErrorAPI) as e:
        mt.addUIMessage(message="%s" % (e.message), messageType="PartialError")
        mt.addUIMessage(message="%s" % (e.suggestion), messageType="PartialError")
    else:
        e = sys.exc_info()[0]
        mt.addUIMessage(message="%s" % e, messageType="PartialError")
    return mt

def domain_to_related_domains(mt, name):
    url = api_url + '/links/name/%s.json' % (name)
    if name.endswith('.'):
        name = name[:-1]
    try:
        r = call_api(url)
        if 'tb1' not in r:
            raise GenericErrorAPI(message="OpenDNS API returned invalid results from domain_to_related_domains function",
                suggestion="Ensure API key is correct")
        names = [name[0] for name in r['tb1']]
        domains_to_attributes(mt, names)
    except (NoContentAPI, GenericErrorAPI) as e:
        mt.addUIMessage(message="%s" % (e.message), messageType="PartialError")
        mt.addUIMessage(message="%s" % (e.suggestion), messageType="PartialError")
    else:
        e = sys.exc_info()[0]
        mt.addUIMessage(message="%s" % e, messageType="PartialError")
    return mt

def domain_to_ips(mt, name):
    url = api_url + '/dnsdb/name/a/%s.json' % (name)
    if name.endswith('.'):
        name = name[:-1]
    try:
        r = call_api(url)
        for tf in r['rrs_tf']:
            for rrs in tf['rrs']:
                if rrs['class'] == 'IN' and rrs['type'] == 'A':
                    entity = mt.addEntity(enType="maltego.IPv4Address", enValue="%s" % (rrs['rr']))
    except (NoContentAPI, GenericErrorAPI) as e:
        mt.addUIMessage(message="%s" % (e.message), messageType="PartialError")
        mt.addUIMessage(message="%s" % (e.suggestion), messageType="PartialError")
    else:
        e = sys.exc_info()[0]
        mt.addUIMessage(message="%s" % e, messageType="PartialError")
    return mt

def domain_to_asns(mt, name):
    url = api_url + '/dnsdb/name/a/%s.json' % (name)
    if name.endswith('.'):
        name = name[:-1]
    try:
        r = call_api(url)
        if 'features' not in r:
            raise GenericErrorAPI(message="No data found for domain name", suggestion="Try a different domain")
        if 'asns' not in r['features']:
            raise GenericErrorAPI(message="No data found for domain name", suggestion="Try a different domain")
        for asn in r['features']['asns']:
            mt.addEntity(enType="maltego.AS", enValue="asn: %s" % (asn))
    except (NoContentAPI, GenericErrorAPI) as e:
        mt.addUIMessage(message="%s" % (e.message), messageType="PartialError")
        mt.addUIMessage(message="%s" % (e.suggestion), messageType="PartialError")
    else:
        e = sys.exc_info()[0]
        mt.addUIMessage(message="%s" % e, messageType="PartialError")
    return mt

def domain_to_ns_ips(mt, name):
    url = api_url + '/dnsdb/name/ns/%s.json' % (name)
    if name.endswith('.'):
        name = name[:-1]
    try:
        r = call_api(url)
        if 'rrs_tf' not in r:
            raise  GenericErrorAPI(message="OpenDNS API returned invalid results from resource record endpoint",
                suggestion="Ensure API key is correct")
        for tf in r['rrs_tf']:
            for rrs in tf['rrs']:
                if rrs['class'] == 'IN' and rrs['type'] == 'NS':
                    mt.addEntity(enType="maltego.NSRecord", enValue="%s" % (rrs['rr']))
    except (NoContentAPI, GenericErrorAPI) as e:
        mt.addUIMessage(message="%s" % (e.message), messageType="PartialError")
        mt.addUIMessage(message="%s" % (e.suggestion), messageType="PartialError")
    else:
        e = sys.exc_info()[0]
        mt.addUIMessage(message="%s" % e, messageType="PartialError")
    return mt

def domain_to_registrants(mt, name):
    if name.endswith('.'):
        name = name[:-1]
    url = api_url + '/whois/%s' % (name)
    try:
        r = call_api(url)
        if 'emails' not in r:
            raise  GenericErrorAPI(message="OpenDNS API returned invalid results from whois endpoint",
                suggestion="Ensure API key is correct")
        for email in r['emails']:
            entity = mt.addEntity(enType='maltego.EmailAddress', enValue="%s" % (email))
    except (NoContentAPI, GenericErrorAPI) as e:
        mt.addUIMessage(message="%s" % (e.message), messageType="PartialError")
        mt.addUIMessage(message="%s" % (e.suggestion), messageType="PartialError")
    else:
        e = sys.exc_info()[0]
        mt.addUIMessage(message="%s" % e, messageType="PartialError")
    return mt

def hash_to_connections(mt, sample):
    url = api_url + '/sample/%s?limit=100' % (sample)
    try:
        r = call_api(url)
        if 'connections' not in r:
            raise GenericErrorAPI(message="OpenDNS API returned invalid results from hash_to_connections function",
                                  suggestion="Ensure API key is correct")
        connections = r['connections']['connections']
        hostnames = []
        for connection in connections:
            if connection['type'] == 'HOST':
                hostnames.append(connection['name'])
            elif connection['type'] == 'IP':
                entity = mt.addEntity(enType="maltego.IPv4Address", enValue="%s" % connection['name'])
        if hostnames:
            mt = domains_to_attributes(mt, hostnames)
    except (NoContentAPI, GenericErrorAPI) as e:
        mt.addUIMessage(message="%s" % (e.message), messageType="PartialError")
        mt.addUIMessage(message="%s" % (e.suggestion), messageType="PartialError")
    else:
        e = sys.exc_info()[0]
        mt.addUIMessage(message="%s" % e, messageType="PartialError")
    return mt

def ip_to_domains(mt, ip):
    url = api_url + '/dnsdb/ip/a/%s.json' % (ip)
    try:
        r = call_api(url)
        if 'rrs' not in r:
            raise GenericErrorAPI(message="OpenDNS API returned invalid results from ip_to_domains function",
                suggestion="Ensure API key is correct")
        names = [name['rr'] for name in r['rrs'] if name['class'] == 'IN' and name['type'] == 'A']
        mt = domains_to_attributes(mt, names)
    except (NoContentAPI, GenericErrorAPI) as e:
        mt.addUIMessage(message="%s" % (e.message), messageType="PartialError")
        mt.addUIMessage(message="%s" % (e.suggestion), messageType="PartialError")
    else:
        e = sys.exc_info()[0]
        mt.addUIMessage(message="%s" % e, messageType="PartialError")
    return mt

def input_to_samples(mt, resource):
    if resource.endswith('.'):
        resource = resource[:-1]
    url = api_url + '/samples/%s?limit=100' % (resource)
    try:
        r = call_api(url)
        if 'samples' not in r:
            raise GenericErrorAPI(message="OpenDNS API returned invalid results from input_to_samples function",
                                  suggestion="Ensure API key is correct")
        for sample in r['samples']:
            entity = mt.addEntity(enType="maltego.Hash", enValue="%s" % sample['sha256'])
            entity.addAdditionalFields("Threat Score", "Threat Score", "static","%d" % sample['threatScore'])
            entity.addAdditionalFields("Magic Type", "Magic Type", "static", "%s" % sample['magicType'])
            entity.addAdditionalFields("First Seen", "First Seen", "static", "%d" % sample['firstSeen'])
            entity.addAdditionalFields("Last Seen", "Last Seen", "static", "%d" % sample['lastSeen'])
            entity.addAdditionalFields("AV Results", 
                                       "AV Results",
                                       "static",
                                       ','.join([res['signature'] for res in sample['avresults']]))
    except (NoContentAPI, GenericErrorAPI) as e:
        mt.addUIMessage(message="%s" % (e.message), messageType="PartialError")
        mt.addUIMessage(message="%s" % (e.suggestion), messageType="PartialError")
    else:
        e = sys.exc_info()[0]
        mt.addUIMessage(message="%s" % e, messageType="PartialError")
    return mt

def registrant_to_domains(mt, email):
    email = email.lower()
    url = api_url + '/whois/emails/%s' % (email)
    try:
        r = call_api(url)
        if email not in r:
            raise  GenericErrorAPI(message="OpenDNS API returned invalid results from whois endpoint",
                suggestion="Ensure API key is correct")
        names = [entry['domain'] for entry in r[email]['domains'] if entry['current']]
        mt = domains_to_attributes(mt, names)
    except (NoContentAPI, GenericErrorAPI) as e:
        mt.addUIMessage(message="%s" % (e.message), messageType="PartialError")
        mt.addUIMessage(message="%s" % (e.suggestion), messageType="PartialError")
    else:
        e = sys.exc_info()[0]
        mt.addUIMessage(message="%s" % e, messageType="PartialError")
    return mt

handlers = {
	'domain_to_cooccurences':	domain_to_cooccurences,
	'domain_to_related_domains':	domain_to_related_domains,
	'domain_to_ips':		domain_to_ips,
	'domain_to_asns':		domain_to_asns,	
	'domain_to_ns_ips':		domain_to_ns_ips,
        'domain_to_registrants':        domain_to_registrants,
        'hash_to_connections':          hash_to_connections,
	'ip_to_domains':		ip_to_domains,
        'input_to_samples':             input_to_samples,
        'registrant_to_domains':        registrant_to_domains
}

if __name__ == '__main__':
    transform = sys.argv[1]
    input = sys.argv[2]
    
    mt = MaltegoTransform()
    mt = handlers[transform](mt, input)
    mt.returnOutput()
