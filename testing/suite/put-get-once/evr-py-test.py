#!/usr/bin/python3
import evr
import sys

content = b''.join(evr.get_blob(sys.argv[1])).decode('utf-8')
if content != 'hello world!\n':
    print(f'Retrieved content: {content}')
    sys.exit(1)
