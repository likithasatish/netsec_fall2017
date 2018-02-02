import os


def getPrivateKeyForAddr(addr):
    pwd = os.path.dirname(__file__)
    with open(pwd + '/certificates/clientkey', 'r+b') as root_cert_file:
        return root_cert_file.read()


def getCertsForAddr(addr):
    cert = []
    pwd = os.path.dirname(__file__)
    with open(pwd + '/certificates/client_certificate', 'r+b') as cert_file:
        cert.append(cert_file.read())
    with open(pwd + '/certificates/intermediatecert.cert', 'r+b') as int_cert_file:
        cert.append(int_cert_file.read())
    with open(pwd + '/certificates/root.crt', 'r+b') as root_cert_file:
        cert.append(root_cert_file.read())
    return cert


def getRootCert():
    pwd = os.path.dirname(__file__)
    with open(pwd + '/certificates/root.crt', 'r+b') as root_cert_file:
        return root_cert_file.read()
