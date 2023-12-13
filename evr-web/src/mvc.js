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

import { EMPTY, merge, Observable } from 'rxjs';
import { map, switchMap } from 'rxjs/operators';

export function instantiateTemplate(id){
    let template = document.getElementById(`${id}-view`);
    if(!template){
        throw new Error(`No template found for ID ${id}`);
    }
    let rootNode = null;
    for(let n of template.content.childNodes){
        switch(n.nodeType){
        default:
            throw new Error(`Unexpected nodeType ${n.nodeType}`);
        case Node.TEXT_NODE:
            if(n.textContent.trim().length > 0){
                rootNode = undefined;
            }
            break;
        case Node.ELEMENT_NODE:
            if(rootNode === null){
                rootNode = n;
            } else {
                rootNode = undefined;
            }
            break;
        }
    }
    let container;
    if(rootNode){
        container = rootNode.cloneNode(true);
    } else {
        container = document.createElement('div');
        container.appendChild(template.content.cloneNode(true));
    }
    container.classList.add(`${id}-view`);
    return container;
}

export function wireControllers(controllersSource, containerElement){
    return controllersSource.pipe(
        switchMap(controllers => merge(
            ...controllers.map(c => c.active || EMPTY),
            new Observable(observer => {
                for(let c of controllers){
                    containerElement.appendChild(c.element);
                }
                return () => {
                    for(let c of controllers){
                        containerElement.removeChild(c.element);
                    }
                };
            }),
        )),
    );
}
