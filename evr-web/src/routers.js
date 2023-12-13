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

import { EMPTY, fromEvent, merge, Observable, of, ReplaySubject } from 'rxjs';
import { distinctUntilChanged, map, startWith, switchMap } from 'rxjs/operators';

export function createRouter(viewport, routeResolver){
    return of(undefined).pipe(
        switchMap(() => fromEvent(window, 'hashchange')),
        startWith(undefined),
        map(() => window.location.hash),
        distinctUntilChanged(),
        map(hash => {
            if(hash.startsWith('#')){
                return hash.substring(1);
            }
            return hash;
        }),
        map(routeResolver),
        switchMap(controller => merge(
            new Observable(observer => {
                document.documentElement.scrollTop = 0;
                viewport.appendChild(controller.element);
                return () => viewport.removeChild(controller.element);
            }),
            controller.active || EMPTY,
            new Observable(observer => {
                return () => {
                    controller.tearDown && controller.tearDown.subscribe();
                };
            }),
        )),
    );    
}
