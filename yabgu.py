from distutils.log import error
import requests
import subprocess
import json
from urllib3.exceptions import InsecureRequestWarning
from pathlib import Path
import time
import configparser
import shutil
import glob
import tldextract
import argparse
import sys
import os
from sys import platform as _platform
from datetime import date
import logging
import sqlite3 as sql

# Suppress https warning (Burp)
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
config = configparser.ConfigParser()
config.read('config.ini')
today = date.today()


def db(procedure=0, values=[]):
    try:
        con = sql.connect("yabgu.db")
        sql_create_table = """ CREATE TABLE IF NOT EXISTS certs (
                                        id text NOT NULL,
                                        domains text NOT NULL,
                                        create_date DATE DEFAULT (datetime('now','localtime'))
                                    ); """

        con.execute(sql_create_table)

        if procedure == 1:
            cursor = con.cursor()
            sql_insert_query = """INSERT INTO certs
                          (id, domains) 
                           VALUES 
                          ('{val0}','{val1}')""".format(val0=values[0],val1=values[1])

            count = cursor.execute(sql_insert_query)
            con.commit()
            print(str(cursor.rowcount)+" Başarılı şekilde kaydedildi")
            cursor.close()
        elif procedure ==2:
                cursor = con.cursor()
                cursor.execute("SELECT * FROM certs")
                return cursor.fetchall()
    except Exception as e:
        print(e)


parser = argparse.ArgumentParser(
    description='Yabgu - Zerossl - apache ve plesk icin SSL sertifika yoneticisi'
)
parser.add_argument('-s', '--site', metavar='site',
                    required=False, help='Kayit edilecek domain')
parser.add_argument('-l', '--list', metavar='list',
                    required=False, help='Kayitli domain listesi')
parser.add_argument('-r', '--renew', metavar='renew',
                    required=False, help='Kayitli domainleri yenile')
parser.add_argument('-rm', '--remove', metavar='remove',
                    required=False, help='Kayitli domaini revoke et ve sil')

args = parser.parse_args()
path_sep = "\\"
print(args)
if _platform == "linux" or _platform == "linux2":
    path_sep = "/"
elif _platform == "darwin":
    path_sep = "/"
elif _platform == "win32":
    path_sep = "\\"
elif _platform == "win64":
    path_sep = "\\"

d1 = today.strftime("%m.%Y")

domain = ''
domains = ""
status = ""
logging.basicConfig(filename=f'log{path_sep}yabgu-' + today.strftime("%d-%m-%Y") + '.log',
                    format='%(asctime)s %(message)s',
                    level=logging.DEBUG)

logging.debug(args)


class SSLCertReNew(object):

    def __init__(self):
        global domain, domains, status
        self.url = config['oturum']['api_end_point']
        self.proxies = None
        self.apiKey = config['oturum']['api_key']
        if args.site is not None:
            logging.debug(args.site)
            domains = args.site.split(",")
            domain = args.site
            logging.debug(domain)
            logging.debug(domains)
        else:
            domains = domain.split(",")
            domain = domain
            logging.debug(domain)
            logging.debug(domains)
        self.certificateDomain = ""
        self.commonName = ""
        self.requestSites = ""
        self.organization = ""
        self.status = 0
        self.makeDomain()
        self.csr = self.createCsr()
        # run steps
        self.InitialRequest()
        self.VerificationMethods()
        if (self.status == 0):
            time.sleep(config['diger']['bekleme_suresi'])
        else:
            self.DownloadAndSave()

    def makeDomain(self):
        print(domains)
        self.commonName = domains[0].strip()
        self.certificateDomain = "DNS: " + \
            domain.replace(",", ",DNS: ").strip()
        self.requestSites = domain.strip()
        self.organization = tldextract.extract(self.commonName)
        # print(self.commonName)
        # print(self.certificateDomain)
        # print(self.requestSites)
        
    def createCsr(self):
        logging.debug("crt create")
        req = f'''
[ req ]
default_bits = 2048
prompt = no
encrypt_key = no
default_md = sha256 
distinguished_name = dn
req_extensions = req_ext

[ dn ]
CN = {self.commonName}
emailAddress = {config['crs']['email_address']}
O = {config['crs']['organizasyon']}
OU = {config['crs']['organizasyon_birim']}
L = {config['crs']['ilce']}
ST = {config['crs']['sehir']}
C = {config['crs']['ulke']}

[ req_ext ]
subjectAltName = {self.certificateDomain}'''

        # save file domain.conf
        # create blank file
        f = open(f'{self.commonName}.conf', 'w+')
        f.write(req)
        f.close()
        logging.debug("openssl crt req")
        subprocess.Popen(['openssl', 'req', '-new', '-config', f'{self.commonName}.conf', '-keyout',
                          f'{self.commonName}_key.pem', '-out', f'{self.commonName}.csr'])
        time.sleep(3)
        # read csr
        with open(f'{self.commonName}.csr', 'r') as file:
            data = file.read().replace('\n', '')
            logging.debug(data)
        return data

    def InitialRequest(self):
        logging.debug("init request")
        with open(f'{self.commonName}.csr', 'r') as file:
            csrf = file.read().replace('\n', '')
        response = requests.post(self.url + f'/certificates?access_key={self.apiKey}',
                                 proxies=self.proxies,
                                 data={'certificate_domains': self.requestSites,
                                       'certificate_validity_days': 90,
                                       'certificate_csr': csrf}
                                 )
        logging.debug(response.text)
        result = json.loads(response.text)
        success = "success" in result

        if success is not True:
            self.certHash = result['id']
            logging.debug("cert id" + result["id"])
        else:
            print("error " + str(result["error"]["code"]
                                 ) + " : " + result["error"]["type"])
            logging.debug(
                "error " + str(result["error"]["code"]) + " : " + result["error"]["type"])
            logging.debug("exit")
            sys.exit()
       # self.certHash = result['id']
        # url from json
        self.HttpsUrl = result['validation']['other_methods'][
            f'{self.commonName}']['file_validation_url_https']
        self.HttpsContent = result['validation']['other_methods'][
            f'{self.commonName}']['file_validation_content']
        self.dirOne = self.HttpsUrl.split('/')[-3]
        self.dirTwo = self.HttpsUrl.split('/')[-2]
        self.fileName = self.HttpsUrl.split('/')[-1]
        # create directories
        Path(
            f'{config["konumlar"]["site_dir"]}{path_sep}{self.commonName}{path_sep}{config["konumlar"]["site_doc_dir"]}{path_sep}{self.dirOne}{path_sep}{self.dirTwo}').mkdir(
            parents=True, exist_ok=True)
        # save file
        # convert array into string with newline
        string = '\n'.join(
            result['validation']['other_methods'][f'{self.commonName}']['file_validation_content'])
        f = open(
            f'{config["konumlar"]["site_dir"]}{path_sep}{self.commonName}{path_sep}{config["konumlar"]["site_doc_dir"]}{path_sep}{self.dirOne}{path_sep}{self.dirTwo}{path_sep}{self.fileName}',
            'w')
        f.write(string)
        f.close()

    def VerificationMethods(self):
        response = requests.post(self.url + f'/certificates/{self.certHash}/challenges?access_key={self.apiKey}',
                                 proxies=self.proxies, data={'validation_method': 'HTTPS_CSR_HASH'})

    def VerificationStatus(self):
        response = requests.post(self.url + f'/certificates/{self.certHash}/status?access_key={self.apiKey}',
                                 proxies=self.proxies)
        result = json.loads(response.text)
        self.status = result['validation_completed']

    def DownloadAndSave(self):
        response = requests.get(self.url + f'/certificates/{self.certHash}/download/return?access_key={self.apiKey}',
                                verify=False)
        result = json.loads(response.text)

        ca_bundle = result['ca_bundle.crt']
        cert = result['certificate.crt']

        f = open(
            '{config["konumlar"]["cert_dir"]}{path_sep}{self.commonName}_cert.pem', 'w+')
        f.write(cert)
        f.close()

        f = open(
            '{config["konumlar"]["cert_dir"]}{path_sep}{self.commonName}_ca.pem', 'w+')
        f.write(ca_bundle)
        f.close()
        # move private key
        shutil.move(f'{self.commonName}_key.pem',
                    f'{config["konumlar"]["key_dir"]}{path_sep}{self.commonName}_key.pem')
        # install cert to plesk
        if config["diger"]["deploy"] == "plesk":
            subprocess.Popen(['plesk', 'bin', 'certificate', '-c',
                              'zero_{self.commonName}_{d1}',
                              '-domain ', '{self.commonName}',
                              '-cert-file', '{config["konumlar"]["cert_dir"]}{path_sep}{self.commonName}_cert.pem',
                              '-cacert-file', '{config["konumlar"]["cert_dir"]}{path_sep}{self.commonName}_ca.pem'])

        db(1, [self.certHash, self.requestSites])

        # delete files
        #         files = glob.glob(
        f'{config["konumlar"]["site_dir"]}{path_sep}{self.commonName}{path_sep}{config["konumlar"]["site_doc_dir"]}{path_sep}{self.dirOne}{path_sep}{self.dirTwo}{path_sep}*'
        for f in files:
            os.remove(f)


class SSLCertReNewControl(object):
    def __init__(self):
        print("Bu parametre gelistirme asamasinda\n"
              "*********\n"
              "Yabgu\n"
              "*********\n"
              )


class SSLCertReNewList(object):
    def __init__(self):
        rows =db(2,[])
        for i in rows:
            print(i)

class SSLCertRemove(object):
    def __init__(self):
        print("Bu parametre gelistirme asamasinda\n"
              "*********\n"
              "Yabgu\n"
              "*********\n"
              )


if args.site is not None and args.renew is None and args.list is None:
    obj = SSLCertReNew()
elif args.site is None and args.renew is not None and args.list is None:
    obj = SSLCertReNewControl()
elif args.site is None and args.renew is None and args.list is not None:
    obj = SSLCertReNewList()
elif args.site is None and args.renew is None and args.list is None and args.remove is not None:
    obj = SSLCertRemove()
