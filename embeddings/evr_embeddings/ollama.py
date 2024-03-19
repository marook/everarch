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

import json
from requests import post

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

