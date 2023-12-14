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

import { from, Observable, of, throwError } from 'rxjs';
import { catchError, map, switchMap } from 'rxjs/operators';

export class SeedDescription {
    constructor(ref){
        this.ref = ref;
        this.attrs = [];
    }

    firstAttr(name){
        for(let [key, value] of this.attrs){
            if(key === name){
                return value;
            }
        }
        return undefined;
    }
}

export class ClientError extends Error {
}

export function search(query){
    return rxFetch(`/evr-attr-index/search?q=${encodeURIComponent(query)}`).pipe(
        map(parseSearchResponse),
    );
}

function rxFetch(url, opts={}){
    return new Observable(observer => {
        let authToken = localStorage.getItem('evr-attr-index-auth-token');
        if(!authToken){
            observer.error('No auth token found in local storage key evr-attr-index-auth-token');
            return undefined;
        }

        let ctrl = new AbortController();
        fetch(url, {
            headers: {
                Authorization: `Bearer AT${authToken}`,
            },
            ...opts,
            signal: ctrl.signal,
        })
            .then(resp => {
                if(resp.ok){
                    return resp.text().then(text => {
                        observer.next(text);
                        observer.complete();
                    });
                } else if(resp.status === 400) {
                    return resp.text().then(text => {
                        observer.error(new ClientError(text));
                    });
                } else {
                    observer.error(resp);
                    return undefined;
                }
            })
            .catch(err => observer.error(err));
        return () => ctrl.abort();
    });
}

function parseSearchResponse(body){
    let seeds = [];
    let currentSeedDesc = null;
    for(let line of body.split('\n')){
        if(line.length === 0){
            // ignore empty lines
        } else if(line[0] == '\t'){
            // line describes an attribute
            let sepPos = line.indexOf('=');
            if(sepPos === -1){
                throw new Error(`Unexpected attribute syntax: ${line}`);
            }
            let key = line.substring(1, sepPos);
            let value = line.substring(sepPos + 1);
            currentSeedDesc.attrs.push([key, value]);
        } else {
            // line is the next seed
            currentSeedDesc = new SeedDescription(line);
            seeds.push(currentSeedDesc);
        }
    }
    return seeds;
}
