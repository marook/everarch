# everarch - the hopefully ever lasting archive
# Copyright (C) 2021-2024  Markus Peröbner
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import chromadb
import json
import os
from requests import post

ollama_base_url = 'http://localhost:11434'
ollama_model = 'mistral'
state_dir_path = 'embeddings'

def add_embeddings_args(p):
    p.add_argument('--ollama-base-url',
                   default=ollama_base_url,
                   help=f'Base URL of the ollama server. The server should expose the ollama API at /api below this base URL. The default base URL is {ollama_base_url}')
    p.add_argument('--ollama-model',
                   default=ollama_model,
                   help=f'The ollama model used for generating the embeddings. The default model is {ollama_model}')
    p.add_argument('--state-dir',
                   metavar='DIR',
                   default=state_dir_path,
                   help=f'The path to the embeddings index directory. The directory will be created if it does not exist. The default path is {state_dir_path}')

def connect_chroma(args):
    chroma_db_path = os.path.join(args.state_dir, 'chromadb')
    c = chromadb.PersistentClient(path=chroma_db_path)
    return c.get_or_create_collection(name='evr')

def build_embeddings(args, prompt):
    # the ollama API documentation for that service is at
    # https://github.com/ollama/ollama/blob/main/docs/api.md#generate-embeddings
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }
    body = json.dumps({
        'model': args.ollama_model,
        'prompt': prompt,
    })
    resp = post(f'{args.ollama_base_url}/api/embeddings', data=body, headers=headers)
    if resp.status_code != 200:
        raise Exception(f'Unable to generate embeddings: {resp.status_code}')
    content = json.loads(resp.text)
    return content['embedding']

def text_splitter(source, block_len=200, window_len=7):
    return text_block_weaver(text_block_splitter(source, block_len=block_len), window_len=window_len)

def text_block_splitter(source, block_len=200):
    backlog = ''
    for s in source:
        backlog += s
        while len(backlog) > block_len:
            yield backlog[0:block_len]
            backlog = backlog[block_len:]
    if len(backlog) > 0:
        yield backlog

def text_block_weaver(blocks, window_len=7):
    off = 0
    window = []
    for block in blocks:
        window.append(block)
        if len(window) >= window_len:
            yield (off, ''.join(window))
            for b in window[0:-1]:
                off += len(b)
            window = window[-1:]
    if len(window) > 1:
        yield (off, ''.join(window))
