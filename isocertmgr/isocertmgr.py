"""
Simple cryptography tool for accessing the local certificates
and generating reports/output to aid in certificate renewals.
"""
import ssl
import re
import csv
import logging
from cryptography import x509
from cryptography.x509.oid import NameOID
import yaml


with open('config.yaml', 'r', encoding='utf-8') as fp:
    config = yaml.load(fp, Loader=yaml.FullLoader)

# create logger
logger = logging.getLogger('isocertmgr')
logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.DEBUG)


def parse_cert(cert):
    """Given a certificate, get all of the interesting information we want
    in order to help manage the renewal process for energy markets."""
    # pylint: disable=consider-using-f-string

    results = {}

    # We'll look for the DUNS number in a few places.  If it exists - store it.
    results['DUNS'] = re.search(r"DUNS Number - ([0-9]{13})", str(cert.subject))
    if results['DUNS']:
        results['DUNS'] = results['DUNS'][1]
    else:
        results['DUNS'] = re.search(r"OU=([0-9]{13})", str(cert.subject))
        if results['DUNS']:
            results['DUNS'] = results['DUNS'][1]

    # Everything else is straightforward.
    results.update({
        'Name': cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
        'Serial Number': '{0:x}'.format(cert.serial_number),
        'Valid From': cert.not_valid_before,
        'Valid To': cert.not_valid_after,
        'Subject': cert.subject,
        'Organization': cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
    })

    return results


def find_certs():
    """Search the local machine stores for certificates and store the
    interesting ones in a .csv file."""
    # pylint: disable=unused-variable

    fieldnames = [
                  'Market',
                  'Name',
                  'Issuer',
                  'Serial Number',
                  'Valid From',
                  'Valid To',
                  'Subject',
                  'Organization',
                  'DUNS',
                  'Store'
                  ]

    export_filename = 'export.csv'
    with open(export_filename, 'w', newline='', encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, delimiter=',',
                                quotechar='"', quoting=csv.QUOTE_ALL, fieldnames=fieldnames)

        writer.writeheader()

        for store in config['stores']:
            for cert, encoding, trust in ssl.enum_certificates(store):
                certificate = x509.load_der_x509_certificate(cert, backend=None)

                try:
                    issuer = certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                except IndexError:
                    continue

                # Keep any of the matching issuers
                for market in config['filters']:

                    for issuer_filter in config['filters'][market]['issuer']:
                        if re.search(issuer_filter, issuer):
                            cert_info = parse_cert(certificate)
                            cert_info.update({
                                'Store': store,
                                'Issuer': issuer,
                                'Market': market.upper()
                            })
                            writer.writerow(cert_info)
                        else:
                            continue
                        break


if __name__ == '__main__':
    find_certs()
