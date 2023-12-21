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

import { fromEvent, merge, of } from 'rxjs';
import { tap } from 'rxjs/operators';

import { createRouter } from '../routers.js';
import { instantiateTemplate, wireControllers } from '../mvc.js';

let allTokenOpPrefix = 'A';

let tokenConfig = [
    {
        name: 'evr-upload-httpd-auth-token',
        opPrefix: 'u',
    },
    {
        name: 'evr-attr-index-auth-token',
        opPrefix: 'i',
    },
];

class JoiningController {
    constructor(tokenOps){
        this.element = instantiateTemplate('joining');
        for(let op of tokenOps){
            if(op.length === 0){
                continue;
            }
            if(op.startsWith(allTokenOpPrefix)){
                // use same token for all services
                let token = op.substring(allTokenOpPrefix.length);
                for(let cfg of tokenConfig){
                    localStorage.setItem(cfg.name, token);
                }
            } else {
                // set an individual token for one service
                let cfg = findTokenConfig(op);
                if(!cfg){
                    throw new Error(`Unknown token operation: ${op}`);
                }
                let token = op.substring(cfg.opPrefix.length);
                localStorage.setItem(cfg.name, token);
            }
        }
        window.location.hash = '';
    }
}

function findTokenConfig(tokenOp){
    for(let cfg of tokenConfig){
        if(tokenOp.startsWith(cfg.opPrefix)){
            return cfg;
        }
    }
    return null;
}

class StatusController {
    constructor(){
        this.element = instantiateTemplate('status');
        let tokenStatusControllers = of(tokenConfig.map(cfg => new TokenStatusController(cfg)));
        let renderTokenStatus = wireControllers(tokenStatusControllers, this.element.querySelector('.token-status-container'));
        let startClicked = fromEvent(this.element.querySelector('.start'), 'click').pipe(
            tap(() => window.location = '/'),
        );
        this.active = merge(renderTokenStatus, startClicked);
    }
}

class TokenStatusController {
    constructor(tokenCfg){
        this.element = instantiateTemplate('token-status');
        this.element.querySelector('.status').textContent = localStorage.getItem(tokenCfg.name) ? '✓' : '🗙';
        this.element.querySelector('.token-name').textContent = tokenCfg.name;
    }
}

let router = createRouter(document.getElementById('viewport'), routePath => {
    if(routePath.startsWith('j/')){
        let args = routePath.split('/').slice(1);
        return new JoiningController(args);
    }
    return new StatusController();
});
router.subscribe();
