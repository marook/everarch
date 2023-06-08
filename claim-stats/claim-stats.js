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
    let { first, map, mergeMap, share, switchMap, tap } = rxjs.operators;
    let { webSocket } = rxjs.webSocket;

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
            map(stats => '' + stats.startTime),
            writeTextContent('.stats-start-time'),
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
                    tap(value => {
                        for(let el of elements){
                            el.textContent = value;
                        }
                    }),
                );
        };
    }
}());
