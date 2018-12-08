# From:
#   https://github.com/alei121/python-stomp/blob/master/stomp.py
# Apache License 2.0:
#   https://github.com/alei121/python-stomp/blob/master/LICENSE

# Simple parser and writer for STOMP message
# See https://stomp.github.io/ for specification

from enum import Enum


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
            if f_input.read() != '\0':
                raise ValueError('Byte after STOMP Body not NULL')
        else:
            remaining = f_input.read()
            content = remaining[:-1]
            if remaining[-1] != '\0':
                raise ValueError('Byte after STOMP Body not NULL')
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
