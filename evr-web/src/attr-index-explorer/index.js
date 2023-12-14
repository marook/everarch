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

import { BehaviorSubject, EMPTY, fromEvent, merge, of, throwError } from 'rxjs';
import { catchError, debounceTime, delay, distinctUntilChanged, map, switchMap, tap } from 'rxjs/operators';

import { createRouter } from '../routers.js';
import { instantiateTemplate, wireControllers } from '../mvc.js';
import { search, ClientError } from '../evr-attr-index.js';

class SearchController {
    constructor(){
        this.element = instantiateTemplate('search');
        let queryInput = this.element.querySelector('form[name=search] input[name=query]');
        setTimeout(() => queryInput.focus(), 0);
        let query = merge(
            // fire the initial query value
            of(undefined),
            // paste events via context menu or middle mouse button
            fromEvent(queryInput, 'paste'),
            // keyboard input or pasting via keyboard shortcut
            fromEvent(queryInput, 'keyup').pipe(debounceTime(300)),
            // avoid default browser submit from the form
            fromEvent(this.element.querySelector('form[name=search'), 'submit').pipe(
                tap(event => event.preventDefault()),
            ),
        ).pipe(
            // give the events some time to let the changed values
            // tickle into the input.value property
            delay(0),
            map(event => queryInput.value.trim()),
            distinctUntilChanged(),
        );
        let loading = new BehaviorSubject(false);
        let validQuery = new BehaviorSubject(true);
        let seeds = query.pipe(
            tap(() => loading.next(true)),
            switchMap(query => search(`select * where ${query}`).pipe(
                tap(() => {
                    loading.next(false);
                    validQuery.next(true);
                }),
                catchError(err => {
                    loading.next(false);
                    if(err instanceof ClientError){
                        validQuery.next(false);
                        console.warn(err);
                        return EMPTY;
                    }
                    return throwError(err);
                }),
            )),
        );
        let seedTiles = seeds.pipe(
            map(seeds => seeds.map(s => new SeedTileController(s))),
        );
        let renderFoundSeeds = wireControllers(seedTiles, this.element.querySelector('.found-seeds'));
        let showLoadingOverlay = loading.pipe(
            distinctUntilChanged(),
            tap(loading => {
                this.element.querySelector('.loading-indicator').style.display = loading ? 'block' : 'none';
            }),
        );
        let indicateValidQuery = validQuery.pipe(
            distinctUntilChanged(),
            tap(valid => {
                if(valid){
                    queryInput.classList.remove('invalid');
                } else {
                    queryInput.classList.add('invalid');
                }
            }),
        );
        this.active = merge(renderFoundSeeds, showLoadingOverlay, indicateValidQuery);
    }
}

class SeedTileController {
    constructor(seedDesc){
        this.element = instantiateTemplate('seed-tile');
        this.element.setAttribute('data-seed', seedDesc.ref);
        let title = seedDesc.firstAttr('title');
        if(title){
            this.element.setAttribute('title', title);
            this.element.querySelector('.title').textContent = title;
        }
        let expanded = new BehaviorSubject(false);
        let clickHandler = fromEvent(this.element, 'click').pipe(
            tap(() => expanded.next(!expanded.value)),
        );
        let renderExpanded = expanded.pipe(
            distinctUntilChanged(),
            tap(expanded => {
                if(expanded){
                    this.element.classList.add('expanded');
                    let ul = this.element.querySelector('.attrs');
                    for(let [key, val] of seedDesc.attrs){
                        let li = document.createElement('li');
                        li.textContent = `${key} = ${val}`;
                        ul.appendChild(li);
                    }
                } else {
                    this.element.classList.remove('expanded');
                    this.element.querySelector('.attrs').innerHTML = '';
                }
            }),
        );
        this.active = merge(clickHandler, renderExpanded);
    }
}

let router = createRouter(document.getElementById('viewport'), routePath => {
    return new SearchController();
});
router.subscribe();
