#!/usr/bin/python

import logging
import os
import subprocess
import sys

log = logging.getLogger(__name__)


class OpenFileOrStdin(object):
    """File open context manager that knows '-' means to use stdin."""
    def __init__(self, name, *args, **kwargs):
        if name == '-':
            self.f = sys.stdin
        else:
            self.f = open(name, *args, **kwargs)

    def __enter__(self):
        return self.f

    def __exit__(self, exc_type, exc_value, exc_tb):
        self.f.close()
        if exc_type:
            return False
        return True


# A PemFile will generate 0 or more PemBlobs
class PemFile(object):
    def __init__(self, filename=None, data=None):
        self.name = filename
        self.data = data

    def __iter__(self):
        if self.name == '-':
            fo = sys.stdin
        try:
            with OpenFileOrStdin(self.name, 'r') as fo:
                for line in fo.readlines():
                    yield line
        except EnvironmentError as e:
            log.error(e)
            raise StopIteration


# A Pem is the data inside a PemFile or String.
# It may well include multiple certs/keys But it is
# also useful for a PemBlob to know it's original filename.
#
# A Pem is a generate that will generate 0 or more
# PemBlobData
class Pem(object):
    pem_begin = '-----BEGIN '
    pem_end = '-----END '

    def __init__(self, fo=None):
        """data can be a file object, real or StringIO, or really
        anything that iterates over lines by default."""
        self.fo = fo
        self.filename = self.fo.name

    def __iter__(self):
        for pem_blob_data in self.split(self.fo):
            yield pem_blob_data

    # re.finditer() isn't great for huge strings with back references.
    # A test case with a thousand pems in it uses 100% cpu for minutes.
    # However... just using re.split to match on begin lines is fast, though
    # likely uses a lot of memory. May make sense to split into small chunks
    # (say, 10 END lines) and re.finditer() in the result. Otherwise, finditer
    # blocks until it's ran over the entirestring

    # This can likely all be replaced with a re.finditer()
    # This doesn't handle bogus pem files well, with missing
    # BEGIN or END lines
    def split(self, pem_line_rdr):
        pem_counter = 0
        current_blob = None

        for line in pem_line_rdr:
            # if we are BEGIN'ing a pem, create a blob buffer
            # Note, if we see a two BEGIN in a row without an END, we ignore
            # the first one and create a new one
            if line.startswith(self.pem_begin):
                # create a buffer and do the type lookup by beginline
                current_blob = PemBlobData(filename=self.filename)
                current_blob.firstline(line)
                continue

            # this doesn't look like a pem, so ignore it
            if not current_blob:
                continue

            # log.debug(current_blob)
            # in mid-pem blob, not the end
            if not line.startswith(self.pem_end):
                current_blob.append(line)
                continue

            # mid pem, and at the end
            current_blob.end(line)
            current_blob.count = pem_counter

            log.debug("yield current_blob %s", pem_counter)
            yield current_blob

            current_blob = None
            pem_counter += 1


# could be a factory or metaclass
class PemType(object):
    def __init__(self, pem_type):
        self.pem_type = pem_type

    def __str__(self):
        return str(self.pem_type)


class PemTypes(object):
    # if we match begin_marker, the type, and '--' at the beginning of
    # a line, that should be close enough.
    marker_format = "-----BEGIN %s--"

    # from openssl pem.h
    pem_markers = [('CERTIFICATE', 'certificate'),
                   ('ENTITLEMENT DATA', 'entitlement_data'),
                   ('RSA SIGNATURE', 'rsa_signature'),
                   ('RSA PRIVATE KEY', 'rsa_private_key'),
                   ('RSA PUBLIC KEY', 'rsa_public_key'),
                   ('X509 CERTIFICATE', 'old_format_x509_certificate'),
                   ('CERTIFICATE PAIR', 'certificate_pair'),
                   ('TRUSTED CERTIFICATE', 'trusted_certificate'),
                   ('NEW CERTIFICATE REQUEST', 'old_format_csr'),
                   ('CERTIFICATE REQUEST', 'csr'),
                   ('X509 CRL', 'x509_crl'),
                   ('ANY PRIVATE KEY', 'any_private_key'),
                   ('PUBLIC KEY', 'public_key'),
                   ('DSA PRIVATE KEY', 'dsa_private_key'),
                   ('DSA PUBLIC KEY', 'dsa_public_key'),
                   ('PKCS7', 'pkcs7'),
                   ('PKCS #7 SIGNED DATA', 'pkcs7_signed_data'),
                   ('ENCRYPTED PRIVATE KEY', 'pkcs8'),
                   ('PRIVATE KEY', 'pkcs8_inf'),
                   ('DH PARAMETERS', 'dh_params'),
                   ('SSL SESSION PARAMETERS', 'ssl_session_params'),
                   ('DSA PARAMETERS', 'dsa_params'),
                   ('ECDSA PUBLIC KEY', 'ecdsa_public_key'),
                   ('EC PARAMETERS', 'ec_paramaters'),
                   ('EC PRIVATE KEY', 'ec_private_key'),
                   ('PARAMETERS', 'paramaters'),
                   ('CMS', 'cms')]

    # build a map of marker string -> our pem type label
    # mapper = dict([(marker_format % type_marker, type_label)
    #               for (type_marker, type_label) in pem_markers])
    # print(marker_format)
    mapper = dict([("-----BEGIN %s--" % type_tuple[0], type_tuple[1])
                   for type_tuple in pem_markers])
    # print(mapper)

    @classmethod
    def lookup_by_beginline(cls, beginline):
        """Pass in the BEGIN line, and we'll try to figure it out."""
        # print(beginline)
        for type_marker in cls.mapper:
            # print("type_marker: %s" % type_marker)
            # print("begin_line : %s" % beginline[0:len(type_marker)])
            if beginline[0:len(type_marker)] == type_marker:
                return PemType(cls.mapper[type_marker])

        return PemType('unknown')


# pem blobs represent one pem... blob. One chunk between BEGIN and END lines.
class PemBlobData(object):
    """PEM blob data and metadata.

    filename, pem_type, and count are metadata used in generating the
    name of the file we save the chunk in.
    """
    def __init__(self, data=None, filename=None,
                 pem_type=None, count=None):
        self.data = data or []
        self.filename = filename
        self.pem_type = pem_type
        # used to uniqify each output file
        self.count = None

    def append_line(self, line):
        """Clean up trailing whitespace but preserve newline."""
        self.append("%s\n" % line.strip())

    def append(self, data):
        self.data.append(data)

    # set or start or send better?
    def firstline(self, line):
        self.append_line(line)
        self.pem_type = PemTypes.lookup_by_beginline(line)
        # print('self.pem_type: %s' % self.pem_type)

    def end(self, line):
        self.append_line(line)

    def __str__(self):
        return ''.join(self.data)

    def to_bytes(self):
        return b''.join([x.encode() for x in self.data])


# a pem writer that didn't block would be faster...
# thread pool? names should be uniq, but we could gen
# them first to verify (though that means waiting for all
# before we proceed). Or just assume we are picking names
# that won't clobber
def write_pem(pem_blob):
    path = pem_blob.filename

    # give files from stdin a more useful name than '-'
    if path == '-':
        path = 'pem_from_stdin.pem'

    basename = os.path.basename(path)
    parts = basename.split('.')
    orig_filename = ''.join(parts[:-1])

    # part_name = "{count:d}-{orig_filename}.{pem_type}.pem"
    part_name = "{count:d}-{pem_type}-{orig_filename}.pem"
    new_file_name = part_name.format(count=pem_blob.count,
                                     orig_filename=orig_filename,
                                     pem_type=pem_blob.pem_type)

    log.debug("path %s, basename %s, parts %s, orig_filename %s, "
              "part_name %s new_file_name %s",
              path, basename, parts, orig_filename, part_name, new_file_name)

    fo = open(new_file_name, 'w')
    fo.write(str(pem_blob))
    fo.close()


def concat_pem(pem_blob, dest_fo):
    dest_fo.write(str(pem_blob))


def invoke_x509(pem_string):
    "Takes pem string, invoke 'openssl x509' on it with the string as stdin."
    cmd = ["openssl", "x509", "-text", "-noout"]

    p = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    output = p.communicate(input=pem_string)[0]
    print(output.decode())


def open_pem_files(filenames):
    """return a generator that generates PemFile objects."""
    for filename in filenames:
        yield PemFile(filename)


def main():
    log.setLevel(logging.INFO)
    logging.basicConfig()

    filenames = sys.argv[1:]

    # add stdout if no files specified
    if not filenames:
        filenames.append('-')

    pem_fos = open_pem_files(filenames)

    # for 2.7, could use generator expr, sorta like
    # pem_gen = (Pem(pem_fo) for pem_fo in pem_fos)
    # [[log.debug(pem_blob) for pem_blob in pem] for pem in pem_gen]

    dest_fo = open('pem_from_stdout.pem', 'w')

    for pem_fo in pem_fos:
        pem = Pem(pem_fo)
        for pem_blob in pem:
            log.debug("filename=%s type=%s",
                      pem_blob.filename,
                      pem_blob.pem_type)
            write_pem(pem_blob)
            # invoke_x509(str(pem_blob))
            invoke_x509(pem_blob.to_bytes())

            dest_fo.write(str(pem_blob))
    dest_fo.close()


if __name__ == "__main__":
    main()
