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

from .chroma import connect_chroma
from .ollama import build_embeddings
from .splitter import pdf_splitter, text_splitter

ollama_base_url = 'http://localhost:11434'
ollama_model = 'all-minilm'
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
                   help=f'The path to the embeddings index directory. The directory will be created if it does not exist. The default path is \'{state_dir_path}\'')
