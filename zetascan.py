import yaml
from requests import Session
import datetime
import os
import json
import sys


path = os.environ["WORKDIR"]


with open(path + "/lookup_plugins/zetascan/dnifconfig.yml", 'r') as ymlfile:
    cfg = yaml.load(ymlfile)
    api_key = cfg['lookup_plugin']['ZETASCAN_API_KEY']

def execute():
    print "hello the world!"


def check_config():
    print cfg['lookup_plugin']['ZETASCAN_API_KEY']


def get_domain_report(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = str(i[var_array[0]])+"?key="
            try:
                s = Session()
                s.head("https://api.zetascan.com/v2/check/json/"+params+api_key)
                res = s.get("https://api.zetascan.com/v2/check/json/"+params+api_key)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                i['$ZSStatus'] =json_response['status']
            except Exception:
                pass
            for dt in json_response['results']:
               try:
                   i['$ZSFound'] = dt['found']
               except Exception:
                   pass
               try:
                   if dt['fromSubnet'] != []:
                       i['$ZSFromSubnet'] = dt['fromSubnet']
               except Exception:
                   pass
               try:
                   i['$ZSItem'] = dt['item']
               except Exception:
                   pass
               try:
                   if dt['lastModified'] != []:
                       c = datetime.datetime.utcfromtimestamp(dt['lastModified']).strftime('%Y-%m-%d %H:%M:%S')
                       i['$ZSLastModified'] = c
               except Exception:
                   pass
               try:
                   i['$ZSScore'] = dt['score']
               except Exception:
                   pass
               try:
                   if dt['sources'] != []:
                       i['$ZSSources'] = dt['sources']
               except Exception:
                   pass
               try:
                   i['$ZSWebScore'] = dt['webscore']
               except Exception:
                   pass
               try:
                   i['$ZSWhiteList'] = dt['wl']
               except Exception:
                   pass
               try:
                   if dt['wldata'] !='':
                       i['$ZSWhiteListData'] = dt['wldata']
               except Exception:
                   pass
    return inward_array


def get_ip_report(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = str(i[var_array[0]])+"?key="
            try:
                s = Session()
                s.head("https://api.zetascan.com/v2/check/jsonx/"+params+api_key)
                res = s.get("https://api.zetascan.com/v2/check/jsonx/"+params+api_key)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                i['$ZSStatus'] = json_response['status']
            except Exception:
                pass
            for dt in json_response['results']:
               try:
                   i['$ZSFound'] = dt['found']
               except Exception:
                   pass
               try:
                   if dt['fromSubnet'] != []:
                       i['$ZSFromSubnet'] = dt['fromSubnet']
               except Exception:
                   pass
               try:
                   i['$ZSItem'] = dt['item']
               except Exception:
                   pass
               try:
                   if dt['lastModified'] != []:
                       c = datetime.datetime.utcfromtimestamp(dt['lastModified']).strftime('%Y-%m-%d %H:%M:%S')
                       i['$ZSLastModified'] = c
               except Exception:
                   pass
               try:
                   i['$ZSScore'] = dt['score']
               except Exception:
                   pass
               try:
                   if dt['sources'] != []:
                       i['$ZSSources'] = dt['sources']
               except Exception:
                   pass
               try:
                   i['$ZSWebScore'] = dt['webscore']
               except Exception:
                   pass
               try:
                   i['$ZSWhiteList'] = dt['wl']
               except Exception:
                   pass
               try:
                   if dt['wldata'] !='':
                       i['$ZSWhiteListData'] = dt['wldata']
               except Exception:
                   pass
               if dt['extended'] != {}:
                   try:
                       i['$ZSASN'] = dt['extended']['ASNum']
                   except Exception:
                       pass
                   try:
                       i['$ZSCountry'] = dt['extended']['country']
                   except Exception:
                       pass
                   try:
                       i['$ZSDomain'] = dt['extended']['domain']
                   except Exception:
                       pass
                   try:
                       i['$ZSEmailLastDay'] = dt['extended']['emailslastday']
                   except Exception:
                       pass
                   try:
                       if dt['extended']['reason']['type'] == "sinkhole" and dt['extended']['reason']['class'] == "BOT":
                           i['$ZSReason'] = ("Class : " + str(dt['extended']['reason']['class'])
                                           + "\nDestination : " + str(dt['extended']['reason']['destination'])
                                           + "\nName : " + str(dt['extended']['reason']['name'])
                                           + "\nPort : " + str(dt['extended']['reason']['port'])
                                           + "\nRule : " + str(dt['extended']['reason']['rule'])
                                           + "\nSource : " + str(dt['extended']['reason']['source'])
                                           + "\nSourcePort : " + str(dt['extended']['reason']['sourceport'])
                                           + "\nType : " + str(dt['extended']['reason']['type']))
                       elif dt['extended']['reason']['type'] == "spamlink" and dt['extended']['reason'][
                           'class'] == "BOT":
                           i['$ZSReason'] = ("Class : " + str(dt['extended']['reason']['class'])
                                           + "\nType : " + str(dt['extended']['reason']['type'])
                                           + "\nDomain : " + str(dt['extended']['reason']['domain'])
                                           + "\nSource : " + str(dt['extended']['reason']['source'])
                                           + "\nName : " + str(dt['extended']['reason']['name'])
                                           + "\nLink : " + str(dt['extended']['reason']['link'])
                                           + "\nRedirect : " + str(dt['extended']['reason']['redirect']))
                       elif dt['extended']['reason']['type'] == "web server attack" and dt['extended']['reason'][
                           'class'] == "BOT":
                           i['$ZSReason'] = ("Class : " + str(dt['extended']['reason']['class'])
                                           + "\nRule : " + str(dt['extended']['reason']['rule'])
                                           + "\nType : " + str(dt['extended']['reason']['type'])
                                           + "\nName : " + str(dt['extended']['reason']['name']))
                       elif dt['extended']['reason']['type'] == "miscellaneous" and dt['extended']['reason'][
                           'class'] == "BOT":
                           i['$ZSReason'] = ("Class : " + str(dt['extended']['reason']['class'])
                                           + "\nRule : " + str(dt['extended']['reason']['rule'])
                                           + "\nType : " + str(dt['extended']['reason']['type'])
                                           + "\nName : " + str(dt['extended']['reason']['name'])
                                           + "\nUser : " + str(dt['extended']['reason']['user'])
                                           + "\nPassword : " + str(dt['extended']['reason']['password'])
                                           + "\nPort : " + str(dt['extended']['reason']['port'])
                                           + "\nSource : " + str(dt['extended']['reason']['source'])
                                           + "\nSourcePort : " + str(dt['extended']['reason']['sourceport'])
                                           + "\nDomain : " + str(dt['extended']['reason']['domain']))
                       elif dt['extended']['reason']['type'] == "unknown" and dt['extended']['reason'][
                           'class'] == "BOT":
                           i['$ZSReason'] = ("Class : " + str(dt['extended']['reason']['class'])
                                           + "\nRule : " + str(dt['extended']['reason']['rule'])
                                           + "\nType : " + str(dt['extended']['reason']['type'])
                                           + "\nName : " + str(dt['extended']['reason']['name'])
                                           + "\nHalo : " + str(dt['extended']['reason']['halo']))
                       elif dt['extended']['reason']['class'] == "LOC":
                           i['$ZSReason'] = ("Class : " + str(dt['extended']['reason']['class'])
                                           + "\nType : " + str(dt['extended']['reason']['type']))
                       elif dt['extended']['reason']['class'] == "MPD":
                           i['$ZSReason'] = ("Class : " + str(dt['extended']['reason']['class'])
                                           + "\nType : " + str(dt['extended']['reason']['type'])
                                           + "\nHelosCount : " + str(dt['extended']['reason']['heloscount'])
                                           + "\nDomainsCount : " + str(dt['extended']['reason']['domainscount'])
                                           + "\nDomains : " + str(dt['extended']['reason']['domains']))
                       elif dt['extended']['reason']['class'] == "NEVER":
                           i['$ZSReason'] = ("Class : " + str(dt['extended']['reason']['class'])
                                           + "\nType : " + str(dt['extended']['reason']['type'])
                                           + "\nhalo : " + str(dt['extended']['reason']['halo']))
                       elif dt['extended']['reason']['class'] == "MISC":
                           i['$ZSReason'] = ("Class : " + str(dt['extended']['reason']['class'])
                                           + "\nType : " + str(dt['extended']['reason']['type'])
                                           + "\nHalo : " + str(dt['extended']['reason']['halo']))
                       elif dt['extended']['reason']['class'] == "BOGUS":
                           i['$ZSReason'] = ("Class : " + str(dt['extended']['reason']['class'])
                                           + "\nType : " + str(dt['extended']['reason']['type'])
                                           + "\nHalo : " + str(dt['extended']['reason']['halos']))
                       elif dt['extended']['reason']['class'] == "BSIP":
                           i['$ZSReason'] = ("Class : " + str(dt['extended']['reason']['class'])
                                           + "\nType : " + str(dt['extended']['reason']['type'])
                                           + "\nHalo : " + str(dt['extended']['reason']['halo']))
                       elif dt['extended']['reason']['class'] == "SSIP":
                           i['$ZSReason'] = ("Class : " + str(dt['extended']['reason']['class'])
                                           + "\nType : " + str(dt['extended']['reason']['type'])
                                           + "\nHalo : " + str(dt['extended']['reason']['halo']))
                       elif dt['extended']['reason']['class'] == "FAM":
                           i['$ZSReason'] = ("Class : " + str(dt['extended']['reason']['class'])
                                           + "\nRDNS : " + str(dt['extended']['reason']['rdns'])
                                           + "\nHalo : " + str(dt['extended']['reason']['halo']))
                       elif dt['extended']['reason']['class'] == "NOHELO":
                           i['$ZSReason'] = ("Class : " + str(dt['extended']['reason']['class']))
                       elif dt['extended']['reason']['class'] == "HELI":
                           i['$ZSReason'] = ("Class : " + str(dt['extended']['reason']['class'])
                                           + "\nType : " + str(dt['extended']['reason']['type'])
                                           + "\nHalo : " + str(dt['extended']['reason']['halo']))
                   except Exception:
                       pass
                   try:
                       i['$ZSRoute'] = dt['extended']['route']
                   except Exception:
                       pass
                   try:
                       i['$ZSState'] = dt['extended']['state']
                   except Exception:
                       pass
                   try:
                       ci = datetime.datetime.utcfromtimestamp(int(dt['extended']['time'])).strftime(
                           '%Y-%m-%d %H:%M:%S')
                       i['$ZSTime'] = ci
                   except Exception:
                       pass
               else:
                   pass
               if dt['extendedSecl'] !={}:
                   try:
                       i['$ZSCidr']= dt['extendedSecl']['cidr']
                   except Exception:
                       pass
                   try:
                       i['$ZSASN'] = dt['extendedSecl']['asn']
                   except Exception:
                       pass
                   try:
                       i['$ZSFirstseen']=dt['extendedSecl']['first_seen']
                   except Exception:
                       pass
                   try:
                       i['$ZSLastseen'] = dt['extendedSecl']['last_seen']
                   except Exception:
                       pass
                   try:
                       i['$ZSCategories'] = dt['extendedSecl']['categories']
                   except Exception:
                       pass
               else:
                   pass
    return inward_array

