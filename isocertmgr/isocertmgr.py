"""
Simple cryptography tool for accessing the local certificates
and generating reports/output to aid in certificate renewals.
"""
import ssl
import re
import sys
import os
import csv
import argparse
import logging
from cryptography import x509
from cryptography.x509.oid import NameOID
import yaml

__author__ = "Caffeine Lab"
__version__ = "0.3.0"
__license__ = "GNU General Public License v3.0"


# create logger
logger = logging.getLogger('isocertmgr')
logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.DEBUG)


def parse_cert(cert):
    """Given a certificate, get all of the interesting information we want
    in order to help manage the renewal process for energy markets.

    Currently very ERCOT centric...
    """

    # We'll look for the DUNS number in a few places.  If it exists - store it.
    duns = re.search(r"DUNS Number - ([0-9]{13})", str(cert.subject))

    if duns:
        duns = '="' + str(duns[1]) + '"'

    else:
        duns = re.search(r"OU=([0-9]{13})", str(cert.subject))
        if duns:
            duns = str(duns[1])

    # Everything else is straightforward.
    results = {
        'DUNS': duns,
        'Name': cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
        'Serial Number': '{0:x}'.format(cert.serial_number),
        'Valid From': cert.not_valid_before.strftime('%Y-%m-%d'),
        'Valid To': cert.not_valid_after.strftime('%Y-%m-%d'),
        'Subject': cert.subject,
        'Organization': cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
    }

    return results


def find_certs(options):
    """Search the local machine stores for certificates and store the
    interesting ones in a .csv file."""
    # pylint: disable=unused-variable

    if options.config is not None:
        try:
            with open(options.config, 'r', encoding='utf-8') as fp:
                config = yaml.load(fp, Loader=yaml.FullLoader)
        except FileNotFoundError as e:
            logger.debug(str(e))
            sys.exit('Cannot find config file: %s' % args.config)
    else:
        sys.exit('For now, you need to have a config file.')

    config['args'] = args

    fieldnames = [
                  'Store',
                  'Market',
                  'DUNS',
                  'Name',
                  'Issuer',
                  'Serial Number',
                  'Valid To',
                  'Valid From',
                  'Subject',
                  'Organization'
                  ]

    export_filename = 'export.csv'

    rows = []
    for store in config['stores']:
        for cert, encoding, trust in ssl.enum_certificates(store):
            certificate = x509.load_der_x509_certificate(cert, backend=None)

            try:
                issuer = certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            except IndexError:
                continue

            # Keep any of the matching issuers
            for market in config['filters']:

                if config['args'].market is not None and market != config['args'].market:
                    # Skip market filter for this certificate
                    # since we're filtering for something specific
                    # and this isn't it.
                    continue

                for issuer_filter in config['filters'][market]['issuer']:
                    if re.search(issuer_filter, issuer):
                        cert_info = parse_cert(certificate)
                        cert_info.update({
                            'Store': store,
                            'Issuer': issuer,
                            'Market': market.upper()
                        })
                        rows.append(cert_info)
                    else:
                        continue
                    break

    if len(rows) == 0:
        print('nothing found')
        return

    try:
        with open(export_filename, 'w', newline='', encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, delimiter=',',
                                    quotechar='"', quoting=csv.QUOTE_ALL, fieldnames=fieldnames)

            writer.writeheader()
            for cert_info in rows:
                writer.writerow({k: cert_info[k] for k in fieldnames})
    except PermissionError as e:
        logger.debug(str(e))
        print('Cannot write to file - it may be open.')
        return

    try:
        os.startfile(export_filename)
    except FileNotFoundError as e:
        logger.info(str(e))
        print('Cannot find file - it may not have been written')


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    # Required positional argument
    # parser.add_argument("arg", help="Required positional argument")

    # Optional argument flag which defaults to False
    parser.add_argument("-c", "--config", action="store", dest="config", default=None)

    # Optional argument flag which defaults to False
    parser.add_argument("-m", "--market", action="store", dest="market", default=None)

    # Optional verbosity counter (eg. -v, -vv, -vvv, etc.)
    parser.add_argument('-v', '--verbose', action="count", dest="verbose",
                        default=2, help="Increase the verbosity. Can be used twice for extra effect.")
    parser.add_argument('-q', '--quiet', action="count", dest="quiet",
                        default=0, help="Decrease the verbosity. Can be used twice for extra effect.")

    # Specify output of "--version"
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s (version {version})".format(version=__version__))

    args = parser.parse_args()

    log_levels = [logging.CRITICAL, logging.ERROR, logging.WARNING,
                  logging.INFO, logging.DEBUG]

    args.verbose = min(args.verbose - args.quiet, len(log_levels) - 1)
    args.verbose = max(args.verbose, 0)
    logger.setLevel(log_levels[args.verbose])

    find_certs(args)
