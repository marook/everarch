/*
 * everarch - the hopefully ever lasting archive
 * Copyright (C) 2021-2023  Markus Peröbner
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import { instantiateTemplate } from '../mvc.js';

export class SeedDetailsController {
    constructor(seedDesc){
        this.seedDesc = seedDesc;
        this.element = instantiateTemplate('seed-details');
        this.element.setAttribute('data-seed', seedDesc.ref);
        let fileRef = this.getAttr('file');
        let isImage = fileRef && seedDesc.attrs.some(([key, val]) => key === 'mime-type' && val.startsWith('image/'));
        if(isImage){
            let pixelCount = this.getImgPixelCount();
            if(pixelCount <= 1000*1000){
                let imgEl = document.createElement('img');
                imgEl.setAttribute('src', `/evr-glacier-fs/file/${fileRef}`);
                this.element.querySelector('.preview-img-container').appendChild(imgEl);
            }
        }
        let title = seedDesc.firstAttr('title');
        if(title){
            this.element.setAttribute('title', title);
            this.element.querySelector('.title').textContent = title;
        }
        let ul = this.element.querySelector('.attrs');
        for(let [key, val] of seedDesc.attrs){
            ul.appendChild(renderAttrElement(key, val));
        }
    }

    getAttr(lookupKey) {
        for(let [key, val] of this.seedDesc.attrs){
            if(key === lookupKey){
                return val;
            }
        }
        return undefined;
    }

    getNumberAttr(key) {
        let val = this.getAttr(key);
        if (val === undefined) {
            return undefined;
        }
        return parseFloat(val);
    }

    getImgPixelCount() {
        let w = this.getNumberAttr('image-width');
        let h = this.getNumberAttr('image-height');
        if(w === undefined || h === undefined) {
            return undefined;
        }
        return w * h;
    }
}

function renderAttrElement(key, val){
    switch(key) {
    default:
        return renderPlainValueAttr(key, val);
    case 'file':
        return renderFileClaimAttr(key, val);
    }
}

function renderPlainValueAttr(key, val){
    let li = document.createElement('li');
    li.textContent = `${key} = ${val}`;
    return li;
}

let fileRefPattern = /^(sha3-224-[a-z0-9]{4})[a-z0-9]*([a-z0-9]{4}-[a-z0-9]{4})$/;

function renderFileClaimAttr(key, val){
    let m = val.match(fileRefPattern);
    let url;
    let label;
    if(m){
        url = `/evr-glacier-fs/file/${val}`;
        label = `${m[1]}…${m[2]}`;
    } else {
        url = null;
        label = val;
    }
    let li = document.createElement('li');
    li.appendChild(document.createTextNode(`${key} = `));
    let labelEl;
    if(url){
        labelEl = document.createElement('a');
        labelEl.setAttribute('title', val);
        labelEl.setAttribute('href', url);
        labelEl.textContent = label;
    } else {
        labelEl = document.createTextNode(label);
    }
    li.appendChild(labelEl);
    return li;
}
