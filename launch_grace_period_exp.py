from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import datetime
import uuid
import ipaddress
from cryptography.x509.oid import ExtensionOID
import subprocess
from subprocess import Popen, PIPE
import argparse
import pdb
import sys
import os
import shlex


def generate_root_CA():
    """
    a) generate rootCA key
    b) generate rootCA crt
    """

    ##generating root key

    root_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend())


    ##self-sign and generate the root certificate

    root_public_key = root_private_key.public_key()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u'Northeastern SSL Test CA'),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Northeastern'),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'SSL Clock Skews'),
    ]))

    builder = builder.issuer_name(x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u'Northeastern SSL Test CA'),
    ]))
    builder = builder.not_valid_before(datetime.datetime.today() - datetime.timedelta(days=1))
    builder = builder.not_valid_after(datetime.datetime(2019, 12, 31))
    builder = builder.serial_number(int(uuid.uuid4()))
    builder = builder.public_key(root_public_key)
    builder = builder.add_extension(
    x509.BasicConstraints(ca=True, path_length=None), critical=True,)

    root_certificate = builder.sign(
        private_key=root_private_key, algorithm=hashes.SHA256(),
        backend=default_backend()
    )


    ##write to disk
    


    with open("rootCA.key", "wb") as f:
        f.write(root_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("rootCA.crt", "wb") as f:
        f.write(root_certificate.public_bytes(
            encoding=serialization.Encoding.PEM,
        ))

    return root_private_key, root_certificate

def load_root_CA():

    with open('rootCA.crt', 'rb') as f:
        pem_data = f.read()

    root_cert = x509.load_pem_x509_certificate(pem_data, default_backend())


    with open('rootCA.key', 'rb') as f:
        pem_data = f.read()

    root_private_key = load_pem_private_key(pem_data, password=None, backend=default_backend())

    return root_private_key, root_cert


def generate_key(domain_name):
    """
    a) generate key for the certificate being created
    """
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

     #storing client's private key
    with open(domain_name + ".key", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
     ))

    return key

def generate_csr(key, domain_name):
    """
    generate csr for the client certificate
    """
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"MA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Boston"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Northeastern"),
        x509.NameAttribute(NameOID.COMMON_NAME, domain_name),
    ])).add_extension(
        x509.SubjectAlternativeName([
        x509.DNSName(domain_name),
    ])
    ,
    critical=True,

    # Sign the CSR with our private key.
    ).sign(key, hashes.SHA256(), default_backend())


    # Write our CSR out to disk.
    with open(domain_name + ".csr", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    return csr

def collect_results():
    pass

def build_table(type_):
    """build table as python or latex"""
    pass

def run_chrome_automation(domains, thresholds, notAfter_date, test_type):
    """
    runs domain and returns results

    """
    
    f = open('out.txt', 'w') 

    for index, domain in enumarate(domains):        
        cmd = "nodejs /home/hira/check_pup.js https://" + domain
        args = shlex.split(cmd)
        proc = Popen(args, stdout=PIPE, stderr=PIPE)
        out, err = proc.communicate()
        exitcode = proc.returncode
        
        if "ERR_CERT_DATE_INVALID" in out:
            f.write("Chrome," + test_type + "," + str(notAfter_date) + "," + thresholds[index], ",fail")
            f.write("\n")
            
        elif len(out) == 0:
            f.write("Chrome," + test_type + "," + str(notAfter_date) + "," + thresholds[index], ",pass")
            f.write("\n")
        
def sign_certificate_request(csr, rootkey, rootcrt, client_key, domain_name, notBefore, notAfter):
    """
    generate the certificate based on the csr created
    """

    serial_number = int(str(uuid.uuid4().int)[:20])
    crt = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        rootcrt.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        serial_number  # pylint: disable=no-member
    ).not_valid_before(
        notBefore
    ).not_valid_after(
        notAfter
    ).add_extension(
        extension=x509.KeyUsage(
            digital_signature=True, key_encipherment=True, content_commitment=True,
            data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False, key_cert_sign=False, crl_sign=False
        ),
        critical=True
    ).add_extension(
        extension=x509.BasicConstraints(ca=False, path_length=None),
        critical=True
    ).add_extension(
        extension=x509.AuthorityKeyIdentifier.from_issuer_public_key(rootkey.public_key()),
        critical=False
    ).add_extension(
       csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value,
       critical=False,
    ).sign(
        private_key=rootkey,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    ##storing client's .crt
    with open(domain_name + ".crt", 'wb') as f:
        f.write(crt.public_bytes(encoding=serialization.Encoding.PEM))

def deploy_apps(domain_names):
    cmd = "echo gandalf287 | ./create_apps.sh " + str(len(domain_names))
    args = shlex.split(cmd)
    proc = Popen(args, stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate()
    exitcode = proc.returncode
    x = subprocess.check_output(cmd, shell=True)
    
def output_result_in_log(result):
    pass
    

def run_firefox_automation(domain):
    pass

def wait_unti_time(wait_till):
    
    current_time = datetime.datetime.now()
    delta = current_time - wait_till
    sleep(delta.seconds)

def main():

    parser = argparse.ArgumentParser(description='Launch the grace period experiment')
    parser.add_argument('--device', help='the device to check', type=str, nargs='?', default=0)
    parser.add_argument('--domain_num', help='number of domains', type=str, nargs='?', default=0)
    parser.add_argument('--domain_name', help='domain_name', type=str, nargs='?', default=0)
    parser.add_argument('--timetorun', help='number of minutes from now', type=str, nargs='?', default=0)
    parser.add_argument('--test_type', help='type of test i.e whether its a test to check a notBefore grace period or a notAfter grace period', type=str, nargs='?', default=0)

    args = parser.parse_args()
    domain_names = []
    thresholds = []

    if not os.path.isfile('rootCA.crt'):
        root_key, root_crt = generate_root_CA()

    else:
        root_key, root_crt = load_root_CA()

    if args.test_type == "notBefore":
        ##generate certs
        ##create and launch apps on localhost

        if args.device == "Chrome":
            pass

        if args.device == "Firefox":
            pass

    if args.test_type == "notAfter":

        ##after the notAfter date
        for i in range((int(args.domain_num)//2) + 1):
            split_name = args.domain_name.split(".")
            domain_name = split_name[0] + str(i + 1) + "." + ".".join(split_name[1:])
            domain_key = generate_key(domain_name)
            domain_csr = generate_csr(domain_key, domain_name)
            notBefore = datetime.datetime.utcnow()
            notAfter = datetime.datetime.utcnow() + datetime.timedelta(minutes = int(args.timetorun) + i)
            sign_certificate_request(domain_csr, root_key, root_crt, domain_key, domain_name, notBefore, notAfter)
            domain_names.append(domain_name)
            thresholds.append(str(i))

        ##create domains after notAfter date
        for i in range((int(args.domain_num)//2) - 1):
            split_name = args.domain_name.split(".")
            domain_name = split_name[0] + str((int(args.domain_num) // 2) + i + 2) + "." + ".".join(split_name[1:])
            domain_key = generate_key(domain_name)
            domain_csr = generate_csr(domain_key, domain_name)
            notBefore = datetime.datetime.utcnow()
            notAfter = datetime.datetime.utcnow() + datetime.timedelta(minutes = int(args.timetorun) - (i+1))
            sign_certificate_request(domain_csr, root_key, root_crt, domain_key, domain_name, notBefore, notAfter)
            domain_names.append(domain_name)
            thresholds.append("-" + str((i+1)))

        deploy_apps(domain_names)

        if args.device == "Chrome":
            wait_unti_time(notAfter)
            run_chrome_automation(domain_names)
            
        if args.device == "Firefox":
            pass


if __name__ == "__main__":
    main()
