'''
parse SavedState artifacts extracted from OSX.
author: Willi Ballenthin (william.ballenthin@fireeye.com)
license: Apache 2.0
'''
'''
modified by h00die for eventual import into Metasploit Framework
'''

import re
import sys
import json
import struct
import logging
import binascii
import collections
# zbplist.py imports
import os
import os.path
import datetime
from io import BytesIO
import glob

logger = logging.getLogger('osx.savedstate')
logging.basicConfig(level=logging.INFO)

try:
    import hexdump
except ImportError:
    logger.error('please install `hexdump` via pip')
    sys.exit(-1)

try:
    import zbplist as bplist
except ImportError:
    logger.error('zbplist.py not found in the same directory')
    sys.exit(-1)
except SyntaxError:
    logger.error('python3 required')
    sys.exit(-1)

inputpaths = glob.glob('/users/*/Library/Saved Application State/com.apple.Terminal.savedState/')
outputpath = '/tmp'


########################################################
# start of zbplist.py files
########################################################
#
# Binary Plist
#


class UID:
    def __init__(self, data):
        if not isinstance(data, int):
            raise TypeError("data must be an int")
        if data >= 1 << 64:
            raise ValueError("UIDs cannot be >= 2**64")
        if data < 0:
            raise ValueError("UIDs must be positive")
        self.data = data

    def __index__(self):
        return self.data

    def __repr__(self):
        return "%s(%s)" % (self.__class__.__name__, repr(self.data))

    def __reduce__(self):
        return self.__class__, (self.data,)

    def __eq__(self, other):
        if not isinstance(other, UID):
            return NotImplemented
        return self.data == other.data

    def __hash__(self):
        return hash(self.data)


class Data:
    """
    Wrapper for binary data.

    This class is deprecated, use a bytes object instead.
    """

    def __init__(self, data):
        if not isinstance(data, bytes):
            raise TypeError("data must be as bytes")
        self.data = data

    @classmethod
    def fromBase64(cls, data):
        # base64.decodebytes just calls binascii.a2b_base64;
        # it seems overkill to use both base64 and binascii.
        return cls(_decode_base64(data))

    def asBase64(self, maxlinelength=76):
        return _encode_base64(self.data, maxlinelength)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.data == other.data
        elif isinstance(other, bytes):
            return self.data == other
        else:
            return NotImplemented

    def __repr__(self):
        return "%s(%s)" % (self.__class__.__name__, repr(self.data))


def _encode_base64(s, maxlinelength=76):
    # copied from base64.encodebytes(), with added maxlinelength argument
    maxbinsize = (maxlinelength//4)*3
    pieces = []
    for i in range(0, len(s), maxbinsize):
        chunk = s[i: i + maxbinsize]
        pieces.append(binascii.b2a_base64(chunk))
    return b''.join(pieces)


def _decode_base64(s):
    if isinstance(s, str):
        return binascii.a2b_base64(s.encode("utf-8"))

    else:
        return binascii.a2b_base64(s)


class InvalidFileException (ValueError):
    def __init__(self, message="Invalid file"):
        ValueError.__init__(self, message)


_BINARY_FORMAT = {1: 'B', 2: 'H', 4: 'L', 8: 'Q'}

_undefined = object()


class _BinaryPlistParser:
    """
    Read or write a binary plist file, following the description of the binary
    format.  Raise InvalidFileException in case of error, otherwise return the
    root object.

    see also: http://opensource.apple.com/source/CF/CF-744.18/CFBinaryPList.c
    """
    def __init__(self, use_builtin_types, dict_type):
        self._use_builtin_types = use_builtin_types
        self._dict_type = dict_type

    def parse(self, fp):
        try:
            # The basic file format:
            # HEADER
            # object...
            # refid->offset...
            # TRAILER
            self._fp = fp
            self._fp.seek(-32, os.SEEK_END)
            trailer = self._fp.read(32)
            if len(trailer) != 32:
                raise InvalidFileException()
            (
                offset_size, self._ref_size, num_objects, top_object,
                offset_table_offset
            ) = struct.unpack('>6xBBQQQ', trailer)
            self._fp.seek(offset_table_offset)
            self._object_offsets = self._read_ints(num_objects, offset_size)
            self._objects = [_undefined] * num_objects
            return self._read_object(top_object)

        except (OSError, IndexError, struct.error, OverflowError,
                UnicodeDecodeError):
            raise InvalidFileException()

    def _get_size(self, tokenL):
        """ return the size of the next object."""
        if tokenL == 0xF:
            m = self._fp.read(1)[0] & 0x3
            s = 1 << m
            f = '>' + _BINARY_FORMAT[s]
            return struct.unpack(f, self._fp.read(s))[0]

        return tokenL

    def _read_ints(self, n, size):
        data = self._fp.read(size * n)
        if size in _BINARY_FORMAT:
            return struct.unpack('>' + _BINARY_FORMAT[size] * n, data)
        else:
            if not size or len(data) != size * n:
                raise InvalidFileException()
            return tuple(int.from_bytes(data[i: i + size], 'big')
                         for i in range(0, size * n, size))

    def _read_refs(self, n):
        return self._read_ints(n, self._ref_size)

    def _read_object(self, ref):
        """
        read the object by reference.

        May recursively read sub-objects (content of an array/dict/set)
        """
        result = self._objects[ref]
        if result is not _undefined:
            return result

        offset = self._object_offsets[ref]
        self._fp.seek(offset)
        token = self._fp.read(1)[0]
        tokenH, tokenL = token & 0xF0, token & 0x0F

        if token == 0x00:
            result = None

        elif token == 0x08:
            result = False

        elif token == 0x09:
            result = True

        # The referenced source code also mentions URL (0x0c, 0x0d) and
        # UUID (0x0e), but neither can be generated using the Cocoa libraries.

        elif token == 0x0f:
            result = b''

        elif tokenH == 0x10:  # int
            result = int.from_bytes(self._fp.read(1 << tokenL),
                                    'big', signed=tokenL >= 3)

        elif token == 0x22:  # real
            result = struct.unpack('>f', self._fp.read(4))[0]

        elif token == 0x23:  # real
            result = struct.unpack('>d', self._fp.read(8))[0]

        elif token == 0x33:  # date
            f = struct.unpack('>d', self._fp.read(8))[0]
            # timestamp 0 of binary plists corresponds to 1/1/2001
            # (year of Mac OS X 10.0), instead of 1/1/1970.
            result = (datetime.datetime(2001, 1, 1) +
                      datetime.timedelta(seconds=f))

        elif tokenH == 0x40:  # data
            s = self._get_size(tokenL)
            if self._use_builtin_types:
                result = self._fp.read(s)
            else:
                result = Data(self._fp.read(s))

        elif tokenH == 0x50:  # ascii string
            s = self._get_size(tokenL)
            result = self._fp.read(s).decode('ascii')

        elif tokenH == 0x60:  # unicode string
            s = self._get_size(tokenL)
            result = self._fp.read(s * 2).decode('utf-16be')

        elif tokenH == 0x80:  # UID
            # used by Key-Archiver plist files
            result = UID(int.from_bytes(self._fp.read(1 + tokenL), 'big'))

        elif tokenH == 0xA0:  # array
            s = self._get_size(tokenL)
            obj_refs = self._read_refs(s)
            result = []
            self._objects[ref] = result
            result.extend(self._read_object(x) for x in obj_refs)

        # tokenH == 0xB0 is documented as 'ordset', but is not actually
        # implemented in the Apple reference code.

        # tokenH == 0xC0 is documented as 'set', but sets cannot be used in
        # plists.

        elif tokenH == 0xD0:  # dict
            s = self._get_size(tokenL)
            key_refs = self._read_refs(s)
            obj_refs = self._read_refs(s)
            result = self._dict_type()
            self._objects[ref] = result
            for k, o in zip(key_refs, obj_refs):
                result[self._read_object(k)] = self._read_object(o)

        else:
            raise InvalidFileException()

        self._objects[ref] = result
        return result


def _count_to_size(count):
    if count < 1 << 8:
        return 1

    elif count < 1 << 16:
        return 2

    elif count << 1 << 32:
        return 4

    else:
        return 8


def _is_fmt_binary(header):
    return header[:8] == b'bplist00'


#
# Generic bits
#


_FORMATS = {
    'FMT_BINARY': dict(
        detect=_is_fmt_binary,
        parser=_BinaryPlistParser,
    )
}


def load(fp, *, fmt=None, use_builtin_types=True, dict_type=dict):
    """Read a .plist file. 'fp' should be (readable) file object.
    Return the unpacked root object (which usually is a dictionary).
    """
    if fmt is None:
        header = fp.read(32)
        fp.seek(0)
        for info in _FORMATS.values():
            if info['detect'](header):
                P = info['parser']
                break

        else:
            raise InvalidFileException()

    else:
        P = _FORMATS[fmt]['parser']

    p = P(use_builtin_types=use_builtin_types, dict_type=dict_type)
    return p.parse(fp)


def loads(value, *, fmt=None, use_builtin_types=True, dict_type=dict):
    """Read a .plist file from a bytes object.
    Return the unpacked root object (which usually is a dictionary).
    """
    fp = BytesIO(value)
    return load(
        fp, fmt=fmt, use_builtin_types=use_builtin_types, dict_type=dict_type)


def json_encode(z):
    '''
    used when serializing a decoded bplist into json.
    '''
    if isinstance(z, UID):
        return z.data
    else:
        type_name = z.__class__.__name__
        raise TypeError(f"Object of type '{type_name}' is not JSON serializable")
########################################################
# end of zbplist.py files
########################################################

def aes_decrypt(key, ciphertext, iv=b'\x00' * 0x10):
    # AES128-CBC

    import cryptography.hazmat.backends
    import cryptography.hazmat.primitives.ciphers
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    backend = cryptography.hazmat.backends.default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


WindowState = collections.namedtuple('WindowState',
                                     [
                                         # size of the byte array in `data.data` for this window.
                                         'size',
                                         # the parsed metadata associated with this window from `windows.plist`
                                         'meta',
                                         # the decrypted window state byte array.
                                         'plaintext',
                                         # the deserialized NSKeyedArchiver window state.
                                         'state'
                                     ])


def parse_plaintext(buf):
    '''
    parse the decrypted window state extracted from `data.data`.
    args:
      buf (bytes): the decrypted window state byte array.
    returns:
      Dict[any: any]: the deserialized bplist contents.
    '''
    # layout:
    #
    #   struct S {
    #      // often 0x0
    #      uint32_t unk1;
    #      uint32_t class_name_size;
    #      char     class_name[magic_size];
    #      // seems to be "rchv"
    #      char     magic[4];
    #      uint32_t size;
    #      // this is an NSKeyedArchiver serialized datastructure.
    #      // in practice, a bplist with specific interpretation.
    #      uint8_t  buf[size];
    #   }
    unk1, class_name_size = struct.unpack_from('>II', buf, 0x0)
    class_name, magic, size = struct.unpack_from('>%ds4sI' % (class_name_size), buf, 8)
    if magic != b'rchv':
        raise ValueError('unexpected magic')

    class_name = class_name.decode('ascii')
    logger.debug('found archived class: %s', class_name)

    header_size = 8 + class_name_size + 8

    plistbuf = buf[header_size:header_size + size]
    return bplist.loads(plistbuf)


def parse_window_state(plist, buf):
    magic, version, window_id, size = struct.unpack_from('>4s4sII', buf, 0x0)
    if magic != b'NSCR':
        raise ValueError('invalid magic')

    if version != b'1000':
        raise ValueError('invalid version')

    ciphertext = buf[0x10:size]

    try:
        window = [d for d in plist if d.get('NSWindowID') == window_id][0]
    except IndexError:
        window_ids = ', '.join(list(sorted(map(lambda p: str(p.get('NSWindowID', 'unknown')), plist))))
        raise ValueError('missing window metadata, wanted: %d, found: %s' % (window_id, window_ids), size)
    else:
        logger.debug('found window: %d', window_id)

    plaintext = aes_decrypt(window['NSDataKey'], ciphertext)
    state = parse_plaintext(plaintext)

    return WindowState(size, window, plaintext, state)


def parse_window_states(plist, data):
    '''
    decrypt and parse the serialized window state stored in `data.data` and `windows.plist`.
    args:
      plist (Dict[any, any]): parsed plist `windows.plist`.
      data (bytes): the contents of `data.data`.
    returns:
      List[WindowState]: decrypted window state instances, with fields:
        size (int): the size of the window state blob.
        meta (Dict[any, any]): the relevant metadata from `windows.plist`.
        plaintext (bytes): the decrypted windows state structure.
        state (Dict[any, any]): the deserialized window state.
    '''
    buf = data

    while len(buf) > 0x10:
        if not buf.startswith(b'NSCR'):
            raise ValueError('invalid magic')

        try:
            window_state = parse_window_state(plist, buf)
        except ValueError as e:
            logger.warning('failed to parse window state: %s', e.args[0])
            if len(e.args) > 1:
                size = e.args[1]
                buf = buf[size:]
                continue
            else:
                break

        buf = buf[window_state.size:]
        yield window_state


def main():

    for inputpath in inputpaths:
        logger.info('input: %s', inputpath)

        with open(os.path.join(inputpath, 'windows.plist'), 'rb') as f:
            windows = bplist.load(f)

        with open(os.path.join(inputpath, 'data.data'), 'rb') as f:
            data = f.read()

        for i, window in enumerate(parse_window_states(windows, data)):
            if not window.meta:
                logger.info('no data for window%d', i)
                continue
            if not 'NSTitle' in window.meta:
                logger.info('skipping window, no title')
                continue
            filename = 'window%d' % (i)
            filepath = os.path.join(outputpath, filename + '.json')
            logger.info('writing: %s', filepath)
            print('Window %s Title: %s' %(i,window.meta['NSTitle']))
            # the 33rd object is the start of the window data, so if less than that, we can safely skip
            if len(window.state['$objects']) <= 32 :
                continue
            shell_content = window.state['$objects'][33:]
            output = []
            for line in shell_content:
                if isinstance(line, bytes):
                    output.append(line.decode('utf-8'))
                    with open('/tmp/%s' %(i), 'w') as w:
                        w.write(''.join(output))


if __name__ == '__main__':
    main()
