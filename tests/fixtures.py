"""Disposable Penguin Mail store and S/MIME listing fixture for native UI QA."""
import hashlib,json,os,ssl,subprocess
from pathlib import Path

def penguin_fixture(folder,data,certificate,key):
    second_certificate=folder/'penguin-fixture.pem'
    second_key=folder/'penguin-fixture.key'
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
        '-subj','/UID=penguin/CN=Penguin fixture','-addext','subjectAltName=DNS:localhost',
        '-keyout',str(second_key),'-out',str(second_certificate)],check=True,
        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    second_key.chmod(0o600)
    def identity(cert,private,address):
        return dict(id=hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest(),
                    certificate=cert.read_text(),key=private.read_text(),address=address)
    entries=[identity(certificate,key,'fixture@localhost'),
             identity(second_certificate,second_key,'penguin@localhost')]
    source=data/'penguin-mail/misfin/state.json'
    source.parent.mkdir(parents=True,mode=0o700)
    fd=os.open(source,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as output:json.dump(dict(identities=entries,messages=[],pins={}),output)
    executables=folder/'fixture-bin';executables.mkdir()
    marker=folder/'gpgsm-listed'
    shim=executables/'gpgsm'
    shim.write_text('#!/usr/bin/python3\nfrom pathlib import Path\nimport sys\nPath('+repr(str(marker))+').write_text(" ".join(sys.argv[1:]))\n')
    shim.chmod(0o700)
    return dict(source=source,source_bytes=source.read_bytes(),id=entries[1]['id'],
                key_sha256=hashlib.sha256(second_key.read_bytes()).hexdigest(),
                executables=executables,smime_marker=marker)
