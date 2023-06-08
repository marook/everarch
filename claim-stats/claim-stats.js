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
(function(){
    let { EMPTY, fromEvent, merge, of, ReplaySubject, Subject } = rxjs;
    let { distinctUntilChanged, first, map, mergeMap, share, switchMap, tap } = rxjs.operators;
    let { webSocket } = rxjs.webSocket;

    let xmlNamespaces = new Map([
        ['evr', 'https://evr.ma300k.de/claims/'],
        ['dc', 'http://purl.org/dc/terms/'],
    ]);

    let stats = fromEvent(document.forms.target, 'submit')
        .pipe(
            map(event => {
                event.preventDefault();
                let form = event.target;
                return {
                    server: {
                        url: form.evrWebsocketServerUrl.value || 'ws://localhost:8030',
                        user: form.evrWebsocketServerUser.value,
                        password: form.evrWebsocketServerPassword.value,
                    },
                };
            }),
            switchMap(config => collectStats(config)),
            share({
                connector: () => new ReplaySubject(1),
                resetOnError: true,
                resetOnComplete: true,
                resetOnRefCountZero: true,
            }),
        );

    let claimSetsPerDay = stats
        .pipe(
            map(stats => {
                let earliest = null;
                let latest = null;
                for(let ns of Object.keys(stats.claims)){
                    let nsObj = stats.claims[ns];
                    for(let name of Object.keys(nsObj)){
                        let nameObj = nsObj[name];
                        if(earliest === null || nameObj.earliestCreated < earliest){
                            earliest = nameObj.earliestCreated;
                        }
                        if(latest === null || nameObj.latestCreated > latest){
                            latest = nameObj.latestCreated;
                        }
                    }
                }
                let dt = (latest.getTime() - earliest.getTime()) / (24*60*60*1000);
                return stats.claimSetCount / dt;
            }),
            share({
                connector: () => new ReplaySubject(1),
                resetOnError: true,
                resetOnComplete: true,
                resetOnRefCountZero: true,
            }),
        );

    merge(
        stats.pipe(
            first(),
            tap(() => document.getElementById('stats').classList.remove('hidden')),
        ),
        stats.pipe(
            map(stats => '' + stats.claimSetCount),
            writeTextContent('.stats-claim-set-count'),
        ),
        stats.pipe(
            map(stats => stats.startTime.toLocaleString()),
            writeTextContent('.stats-start-time'),
        ),
        stats.pipe(
            observable => {
                let tbody = document.getElementById('stats-claims');
                let rows = new Map();
                return observable
                    .pipe(
                        tap(stats => {
                            let surplus = new Set(rows.keys());
                            for(let ns of Object.keys(stats.claims)){
                                let nsObj = stats.claims[ns];
                                for(let name of Object.keys(nsObj)){
                                    let nameObj = nsObj[name];
                                    let rowKey = `${name}:${ns}`;
                                    surplus.delete(rowKey);
                                    let row = rows.get(rowKey);
                                    if(!row){
                                        let rowEl = document.createElement('tr');
                                        row = {
                                            rowEl,
                                        };
                                        for(let k of ['name', 'namespace', 'count', 'earliest', 'latest']){
                                            let el = document.createElement('td');
                                            rowEl.appendChild(el);
                                            row[k] = el;
                                        }
                                        for(let k of ['count', 'earliest', 'latest']){
                                            row[k].classList.add('number-slot');
                                        }
                                        row.name.textContent = name;
                                        row.namespace.textContent = ns;
                                        rows.set(rowKey, row);
                                        tbody.appendChild(rowEl);
                                    }
                                    row.count.textContent = '' + nameObj.count;
                                    row.earliest.textContent = nameObj.earliestCreated.toLocaleString();
                                    row.latest.textContent = nameObj.latestCreated.toLocaleString();
                                }
                            }
                            for(let rowKey of surplus){
                                tbody.removeChild(rows.get(rowKey).rowEl);
                                rows.delete(rowKey);
                            }
                        }),
                    );
            },
        ),
        claimSetsPerDay.pipe(
            map(claimSetsPerDay => claimSetsPerDay.toFixed(1)),
            writeTextContent('.stats-claims-per-day'),
        ),
        claimSetsPerDay.pipe(
            map(claimSetsPerDay => (365*claimSetsPerDay).toFixed(0)),
            writeTextContent('.stats-claims-per-year'),
        ),
    )
    // TODO catch errors
        .subscribe();

    function collectStats(config){
        let nextCh = 1;
        let ws = webSocket(config.server.url);
        let stats = {
            startTime: new Date(),
            claimSetCount: 0,
            claims: {},
        };
        let scannedRefs = new Subject();
        ws.next({
            ch: nextCh++,
            cmd: 'auth',
            type: 'basic',
            user: config.server.user,
            password: config.server.password,
        });
        ws.next({
            ch: nextCh++,
            cmd: 'watch',
            lastModifiedAfter: 0,
            flags: 1,
        });
        let scan = scannedRefs
            .pipe(
                mergeMap(ref => {
                    let ch = nextCh++;
                    ws.next({
                        ch,
                        cmd: 'get-verify',
                        ref,
                    });
                    return ws
                        .pipe(
                            mergeMap(msg => {
                                if(msg.status !== 'get'){
                                    return EMPTY;
                                }
                                if(msg.ch !== ch){
                                    return EMPTY;
                                }
                                return of(msg.body);
                            }),
                            first(),
                            map(claimSetStr => {
                                let doc = new DOMParser().parseFromString(claimSetStr, 'text/xml');
                                return {
                                    ref,
                                    doc,
                                };
                            }),
                        );
                }, undefined, 1),
                map(blob => {
                    stats = {
                        ...stats,
                    };
                    stats.claimSetCount += 1;
                    let claimSet = findClaimSet(blob.doc);
                    if(claimSet){
                        let createdAttr = claimSet.getAttributeNS(xmlNamespaces.get('dc'), 'created');
                        if(createdAttr){
                            let created = new Date(createdAttr);
                            // TODO validate created
                            for(let claim of queryXPath(blob.doc, '*', claimSet)){
                                let ns = claim.namespaceURI;
                                let name = claim.localName;
                                let nsObj = stats.claims[ns];
                                if(!nsObj){
                                    nsObj = {};
                                    stats.claims[ns] = nsObj;
                                }
                                let nameObj = nsObj[name];
                                if(nameObj){
                                    nameObj.count += 1;
                                    if(nameObj.earliestCreated > created){
                                        nameObj.earliestCreated = created;
                                    }
                                    if(nameObj.latestCreated < created){
                                        nameObj.latestCreated = created;
                                    }
                                } else {
                                    nameObj = {
                                        count: 1,
                                        earliestCreated: created,
                                        latestCreated: created,
                                    };
                                    nsObj[name] = nameObj;
                                }
                            }

                        }
                    }
                    return stats;
                }),
            );
        let processMessages = ws
            .pipe(
                mergeMap(msg => {
                    switch(msg.status){
                    default:
                        throw new Error(`Unknown message status with message: ${JSON.stringify(msg)}`);
                    case 'authenticated':
                        return EMPTY;
                    case 'blob-modified':
                        scannedRefs.next(msg.ref);
                        return EMPTY;
                    case 'get':
                        return EMPTY;
                    }
                }),
            );
        return merge(
            scan,
            processMessages,
        );
    }

    function writeTextContent(selector, parent=document){
        return observer => {
            let elements = parent.querySelectorAll(selector);
            return observer
                .pipe(
                    distinctUntilChanged(),
                    tap(value => {
                        for(let el of elements){
                            el.textContent = value;
                        }
                    }),
                );
        };
    }

    function findClaimSet(doc){
        return queryXPath(doc, '/evr:claim-set').next()?.value;
    }

    function* queryXPath(doc, xpath, context=undefined){
        let it = doc.evaluate(xpath, context || doc, resolveXmlPrefix, XPathResult.UNORDERED_NODE_ITERATOR_TYPE);
        while(true){
            let node = it.iterateNext();
            if(!node){
                break;
            }
            yield node;
        }
    }

    function resolveXmlPrefix(prefix){
        return xmlNamespaces.get(prefix) || null;
    }
}());
