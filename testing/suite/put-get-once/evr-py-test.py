#!/usr/bin/python3
import evr
import sys

content = b''.join(evr.get_blob(sys.argv[1])).decode('utf-8')
if content != 'hello world!\n':
    print(f'Retrieved content: {content}')
    sys.exit(1)

print('watching all blobs')
for blob in evr.watch(last_modified_after=0):
    if blob.watch_flags != 0:
        print('retrieved last existing blob')
        # this should break the loop after all existing blobs in the
        # storage have been visited.
        break
