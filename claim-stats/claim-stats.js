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
    let { connect } = evrWebsocketClient;
    let { combineLatest, EMPTY, fromEvent, merge, of, ReplaySubject, Subject, throwError } = rxjs;
    let { auditTime, catchError, distinctUntilChanged, first, map, mergeMap, share, switchMap, tap } = rxjs.operators;
    let { webSocket } = rxjs.webSocket;

    let xmlNamespaces = new Map([
        ['evr', 'https://evr.ma300k.de/claims/'],
        ['dc', 'http://purl.org/dc/terms/'],
    ]);

    let errorCodes = {
        userDataInvalid: 5,
    };

    let maxClaimExampleCount = 7;

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
                    namespaceFilter: form.namespaceFilter.value,
                };
            }),
            switchMap(config => collectStats(config)),
            auditTime(1000/10),
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
        stats.pipe(
            observable => {
                let container = document.getElementById('claim-examples-container');
                let claimKindContainers = new Map();
                return observable.pipe(
                    tap(stats => {
                        container.innerHTML = '';
                        for(let ns of Object.keys(stats.claims)){
                            let nsObj = stats.claims[ns];
                            for(let name of Object.keys(nsObj)){
                                let nameObj = nsObj[name];
                                let h = document.createElement('h4');
                                h.textContent = `${ns} ${name}`;
                                container.appendChild(h);
                                let list = document.createElement('ul');
                                for(let exampleRef of nameObj.exampleClaimSetRefs){
                                    let item = document.createElement('li');
                                    item.textContent = exampleRef;
                                    list.appendChild(item);
                                }
                                container.appendChild(list);
                            }
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
        combineLatest([
            stats,
            claimSetsPerDay,
        ])
            .pipe(
                map(([stats, claimSetsPerDay]) => {
                    if(stats.oneHundredClaimSetsTime === null){
                        return 'a not yet known amount of';
                    }
                    let dt = (stats.oneHundredClaimSetsTime.getTime() - stats.startTime.getTime()) / (60*1000);
                    let claimSetsPerYear = claimSetsPerDay * 365;
                    return (dt / 100 * claimSetsPerYear).toFixed(0);
                }),
                writeTextContent('.stats-one-year-scan-duration'),
            ),
    )
    // TODO catch errors
        .subscribe();

    function collectStats(config){
        let stats = {
            startTime: new Date(),
            oneHundredClaimSetsTime: null,
            claimSetCount: 0,
            claims: {},
        };
        let scannedRefs = new Subject();
        return connect(config.server)
            .pipe(
                switchMap(con => {
                    let watchOpts = {
                        lastModifiedAfter: 0,
                        flags: 1,
                    };
                    if(config.namespaceFilter){
                        watchOpts.filter = {
                            type: 'namespace',
                            ns: config.namespaceFilter,
                        };
                    }
                    return con.watchClaims(watchOpts, catchError(err => {
                        if(err?.status === 'error' && err.errorCode === errorCodes.userDataInvalid){
                            // TODO count claim sets with invalid user data in stats
                            return EMPTY;
                        }
                        return throwError(err);
                    }))
                        .pipe(
                            map(blob => {
                                stats = {
                                    ...stats,
                                };
                                stats.claimSetCount += 1;
                                if(stats.claimSetCount === 100){
                                    stats.oneHundredClaimSetsTime = new Date();
                                }
                                let doc = new DOMParser().parseFromString(blob.body, 'text/xml');
                                let claimSet = findClaimSet(doc);
                                if(claimSet){
                                    let createdAttr = claimSet.getAttributeNS(xmlNamespaces.get('dc'), 'created');
                                    if(createdAttr){
                                        let created = new Date(createdAttr);
                                        // TODO validate created
                                        for(let claim of queryXPath(doc, '*', claimSet)){
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
                                                    exampleClaimSetRefs: [],
                                                };
                                                nsObj[name] = nameObj;
                                            }
                                            let exampleClaimSetRefs = nameObj.exampleClaimSetRefs;
                                            if(exampleClaimSetRefs.indexOf(blob.ref) === -1){
                                                let chance = (exampleClaimSetRefs.length < maxClaimExampleCount) ? 1 : (maxClaimExampleCount / nameObj.count);
                                                if(chance >= 1 || Math.random() < chance){
                                                    if(exampleClaimSetRefs.length >= maxClaimExampleCount){
                                                        exampleClaimSetRefs.splice(Math.floor(Math.random() * exampleClaimSetRefs.length), 1, blob.ref);
                                                    } else {
                                                        exampleClaimSetRefs.push(blob.ref);
                                                    }
                                                }
                                            }
                                        }

                                    }
                                }
                                return stats;
                            }),
                        );
                }),
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
