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

import { BehaviorSubject, EMPTY, fromEvent, merge, of } from 'rxjs';
import { distinctUntilChanged, filter, switchMap, tap, map } from 'rxjs/operators';

import { createRouter } from '../routers.js';
import { instantiateTemplate, wireControllers } from '../mvc.js';
import { NavController } from '../nav.js';

let uploadQueue = new BehaviorSubject([]);

uploadQueue.pipe(
    switchMap(queue => {
        if(queue.length === 0){
            return EMPTY;
        }
        let firstEntry = queue[0];
        if(firstEntry.status.value === 'queued'){
            uploadQueueEntry(firstEntry);
        }
        return firstEntry.status;
    }),
    filter(status => status === 'uploaded'),
    tap(() => uploadQueue.next(uploadQueue.value.slice(1))),
).subscribe();

function uploadQueueEntry(queueEntry){
    let authToken = localStorage.getItem('evr-upload-httpd-auth-token');
    if(!authToken){
        return;
    }
    queueEntry.status.next('uploading');
    fetch(`/evr-upload-httpd/files/${queueEntry.file.name}`, {
        method: 'POST',
        headers: {
            Authorization: `Bearer AT${authToken}`,
        },
        body: queueEntry.file,
    })
        .then(res => {
            if(res.ok){
                queueEntry.status.next('uploaded');
            } else {
                queueEntry.status.next('error');
            }
        });
}

class UploadController {
    constructor(){
        this.element = instantiateTemplate('upload');
        let renderNav = wireControllers(of([new NavController()]), this.element.querySelector('.nav-container'));
        let queueUploads = fromEvent(this.element.querySelector('form[name=fileUpload]'), 'submit').pipe(
            tap(event => {
                event.preventDefault();
                let fileInput = this.element.querySelector('form[name=fileUpload] input[name=file]');
                let files = fileInput.files;
                let newUploads = [];
                for(let file of files){
                    newUploads.push({
                        fileName: file.name,
                        status: new BehaviorSubject('queued'),
                        file,
                    });
                }
                uploadQueue.next(uploadQueue.value.concat(newUploads));
                fileInput.value = '';
            }),
        );
        let uploadQueueControllers = uploadQueue.pipe(
            map(queue => queue.map(e => new UploadEntryController(e))),
        );
        let renderUploadQueue = wireControllers(uploadQueueControllers, this.element.querySelector('.uploads-queue-container'));
        this.active = merge(renderNav, queueUploads, renderUploadQueue);
    }
}

let statusIcons = {
    queued: '😴',
    uploading: '😬',
    uploaded: '😌',
    error: '🙀',
};

class UploadEntryController {
    constructor(uploadEntry){
        this.element = instantiateTemplate('upload-entry');
        this.element.querySelector('.file-name').textContent = uploadEntry.fileName;
        let renderStatus = uploadEntry.status.pipe(
            distinctUntilChanged(),
            tap(status => {
                let statEl = this.element.querySelector('.status');
                statEl.textContent = statusIcons[status] || '😐';
                statEl.setAttribute('title', status);
            }),
        );
        this.active = renderStatus;
    }
    
}

let router = createRouter(document.getElementById('viewport'), routePath => {
    return new UploadController();
});
router.subscribe();
