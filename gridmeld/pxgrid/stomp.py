# From:
#   https://github.com/alei121/python-stomp/blob/master/stomp.py
# Apache License 2.0:
#   https://github.com/alei121/python-stomp/blob/master/LICENSE

# Simple parser and writer for STOMP message
# See https://stomp.github.io/ for specification

from enum import Enum
import logging

LOG = logging.getLogger(__name__).log


class StompFrame:
    def __init__(self, headers=None, command=None, content=None):
        if headers is None:
            headers = {}
        self.headers = headers
        self.command = command
        self.content = content

    def get_command(self):
        return self.command

    def set_command(self, command):
        self.command = command

    def get_header(self, key):
        return self.headers.get(key)

    def set_header(self, key, value):
        self.headers[key] = value

    def get_content(self):
        return self.content

    def set_content(self, content):
        self.content = content

    # Writes to a file-like object
    def write(self, f_output):
        f_output.write(self.command.value)
        f_output.write('\n')
        for key in self.headers:
            f_output.write(key)
            f_output.write(':')
            f_output.write(self.headers[key])
            f_output.write('\n')
        f_output.write('\n')
        if self.content is not None:
            f_output.write(self.content)
        f_output.write('\0')

    # Parses a file-like object and creates StompFrame
    @staticmethod
    def parse(f_input):
        def byteshex(x):
            return ' '.join('%02x' % n for n in x.encode('utf-8'))

        content_length = None
        stomp = StompFrame()
        stomp.set_command(StompCommand(f_input.readline().rstrip('\r\n')))
        for line in f_input:
            line = line.rstrip('\r\n')
            if line == '':
                break
            (name, value) = line.split(':')
            stomp.set_header(name, value)
            if name == 'content-length':
                content_length = int(value)
        if content_length is not None:
            content = f_input.read(content_length)
            if len(content) != content_length:
                LOG(logging.WARN, 'len %d != content_length %d',
                    len(content), content_length)
            if content and content[-1] == '\0':
                # XXX bug seen for some messages in
                # ISE 2.4.0.357 Cumulative Patch 8
                LOG(logging.WARN, 'STOMP Body last byte is NULL: %d',
                    content_length)
                content = content.rstrip('\0')
            x = f_input.read(1)
            if x and x != '\0':
                LOG(logging.WARN, 'Byte after STOMP Body not NULL: %s',
                    byteshex(x))
            if not x:
                LOG(logging.WARN, 'EOF after content-length')
            x = f_input.read()
            if x:
                LOG(logging.WARN, 'Bytes after NULL: %s',
                    byteshex(x))
        else:
            remaining = f_input.read()
            content = remaining[:-1]
            if content and content[-1] == '\0':
                LOG(logging.WARN, 'STOMP Body last byte is NULL')
            if remaining[-1] != '\0':
                LOG(logging.WARN, 'Byte after STOMP Body not NULL: %s',
                    byteshex(remaining[-1]))
        if len(content) > 0:
            stomp.set_content(content)
        return stomp


class StompCommand(Enum):
    CONNECT = 'CONNECT'
    STOMP = 'STOMP'
    CONNECTED = 'CONNECTED'
    SEND = 'SEND'
    SUBSCRIBE = 'SUBSCRIBE'
    UNSUBSCRIBE = 'UNSUBSCRIBE'
    ACK = 'ACK'
    NACK = 'NACK'
    BEGIN = 'BEGIN'
    COMMIT = 'COMMIT'
    ABORT = 'ABORT'
    DISCONNECT = 'DISCONNECT'
    MESSAGE = 'MESSAGE'
    RECEIPT = 'RECEIPT'
    ERROR = 'ERROR'
