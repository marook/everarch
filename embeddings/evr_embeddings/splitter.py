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

def pdf_splitter(pdf_reader, block_len=64, window_len=4):
    '''pdf_splitter splits text from a pdf into segments.

    pdf_reader is assumed to be a pypdf.PdfReader instance.
    '''
    for page in pdf_reader.pages:
        page_no = page.page_number
        page_text = page.extract_text()
        for sec_off, sec_text in text_splitter(page_text, block_len=block_len, window_len=window_len):
            yield (page_no, sec_text)

def text_splitter(source, block_len=64, window_len=4):
    '''text_splitter splits the text from source into even and
    overlapping blocks.

    Choose block_len and window_len so that the context size of the
    used LLM model is saturated. If you assume that for example 1500
    characters fit into your LLM's model make sure that
    block_len*window_len is <= 1500.
    '''
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
