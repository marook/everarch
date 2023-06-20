/**
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
 *
 * @license
 */

let evrWebsocketClient = (function(){
    let { combineLatest, merge, Observable, of, ReplaySubject, Subject, throwError } = rxjs;
    let { filter, first, map, mergeMap, share, switchMap, takeUntil, tap } = rxjs.operators;

    /**
     * Connects to a evr-websocket-server.
     *
     * opts may look like:
     *
     * {
     *   url: 'wss://some.where',
     *   user: 'ye-user',
     *   password: 'pazz',
     * }
     *
     * The function returns an Observable which emits an EvrConnection
     * when connected. The Observable completes when the connetion is
     * closed.
     */
    function connect(opts){
        return new Observable(observer => {
            let wantClose = false;
            let ws = new WebSocket(opts.url);
            ws.addEventListener('error', event => observer.error(event));
            ws.addEventListener('close', () => {
                if(wantClose){
                    observer.complete();
                } else {
                    observer.error(new Error(`Server closed connection ${opts.url}`));
                }
            });
            ws.addEventListener('open', () => {
                let con = new EvrConnection(ws);
                con._send({
                    cmd: 'auth',
                    type: 'basic',
                    user: opts.user,
                    password: opts.password,
                });
                observer.next(con);
            });
            return () => {
                wantClose = true;
                ws.close();
            };
        });
    }

    class EvrConnection {
        constructor(ws){
            this._ws = ws;
            this._nextChannel = 1;
            this.messages = new Observable(observer => {
                this._ws.addEventListener('message', handle);
                function handle(event){
                    observer.next(event);
                }
                return () => this._ws.removeEventListener('message', handle);
            })
                .pipe(
                    map(event => JSON.parse(event.data)),
                    share({
                        connector: () => new Subject(),
                        resetOnError: true,
                        resetOnComplete: true,
                        resetOnRefCountZero: true,
                    }),
                );
        }

        watch(opts={}){
            return this._fetch({
                cmd: 'watch',
                ...opts,
            })
                .pipe(
                    expectMessageStatus('blob-modified'),
                );
        }

        watchClaims(watchOpts={}, claimErrorsHandler=tap, maxParallelFetch=8, meta=false){
            return this.watch({
                ...watchOpts,
                flags: watchOpts.flags || 1,
            })
                .pipe(
                    map(blobModified => blobModified.ref),
                    this.getVerifyMany(claimErrorsHandler, maxParallelFetch, meta),
                );
        }

        getVerifyMany(claimErrorsHandler=undefined, maxParallelFetch=8, meta=false){
            return fetchedRefSource => {
                // TODO convert claimsBacklog into a ring buffer approach
                let destroy = new Subject();
                let claimsBacklog = [];
                return fetchedRefSource
                    .pipe(
                        tap(ref => {
                            let index = claimsBacklog.length;
                            claimsBacklog.push(this.getVerify(ref, meta).pipe(
                                map(blob => ({
                                    ...blob,
                                    ref,
                                })),
                                claimErrorsHandler || tap(),
                                takeUntil(destroy),
                                share({
                                    connector: () => new ReplaySubject(1),
                                    resetOnError: false,
                                    resetOnComplete: false,
                                    resetOnRefCountZero: false,
                                }),
                            ));
                            if(index < maxParallelFetch){
                                // prefetch some claims
                                claimsBacklog[index].subscribe();
                            }
                        }),
                        claimsBacklogPushTrigger => {
                            return new Observable(observer => {
                                let fetching = false;
                                triggerFetch();
                                claimsBacklogPushTrigger
                                    .pipe(
                                        takeUntil(destroy),
                                    )
                                    .subscribe({
                                        next: () => triggerFetch(),
                                        complete: () => observer.complete(),
                                        error: e => observer.error(e),
                                    });
                                return () => {
                                    destroy.next(undefined);
                                    destroy.complete();
                                };

                                function triggerFetch(){
                                    if(fetching){
                                        return;
                                    }
                                    if(claimsBacklog.length === 0){
                                        return;
                                    }
                                    fetching = true;
                                    claimsBacklog[0]
                                        .pipe(
                                            takeUntil(destroy),
                                        )
                                        .subscribe({
                                            next: claim => observer.next(claim),
                                            complete: () => {
                                                claimsBacklog.splice(0, 1);
                                                if(claimsBacklog.length >= maxParallelFetch){
                                                    // prefetch some claims
                                                    claimsBacklog[maxParallelFetch - 1].subscribe();
                                                }
                                                fetching = false;
                                                triggerFetch();
                                            },
                                            error: e => {
                                                fetching = false;
                                                observer.error(e);
                                            },
                                        });
                                }
                            });
                        },
                    );
            };
        }

        getVerify(ref, meta=false){
            return this._fetch({
                cmd: 'get-verify',
                ref,
                meta,
            })
                .pipe(
                    first(),
                    expectMessageStatus('get'),
                    map(msg => ({
                        body: msg.body,
                        meta: msg.meta,
                    })),
                );
        }

        signPut(body){
            return this._fetch({
                cmd: 'sign-put',
                body,
            })
                .pipe(
                    first(),
                    expectMessageStatus('put'),
                    map(msg => msg.ref),
                );
        }

        _fetch(cmd){
            let chSubject = new ReplaySubject(1);
            return merge(
                combineLatest([
                    chSubject,
                    this.messages,
                ])
                    .pipe(
                        filter(([ch, msg]) => msg.ch === ch),
                        map(([ch, msg]) => msg),
                    ),
                new Observable(observer => {
                    chSubject.next(this._send(cmd));
                    chSubject.complete();
                    observer.complete();
                }),
            );
        }

        _send(cmd){
            let ch = this._nextChannel++;
            this._ws.send(JSON.stringify({
                ch,
                ...cmd,
            }));
            return ch;
        }
    }

    function expectMessageStatus(status, errorMessageHandler=throwError){
        return mergeMap(msg => {
            if(msg.status === 'error'){
                return errorMessageHandler(msg);
            }
            if(msg.status !== status){
                return throwError(new Error(`Expected command status ${JSON.stringify(status)} but got message: ${JSON.stringify(msg)}`));
            }
            return of(msg);
        });
    }

    return {
        connect,
    };
}());
