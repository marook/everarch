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

let childProcess = require('child_process');

let { Observable } = require('rxjs');

class ChildProcessError extends Error{
    constructor(exitCode, stderr){
        super(`Child process failed with exit code ${exitCode}: ${stderr}`);
        this.exitCode = exitCode;
        this.stderr = stderr;
    }
}

function spawn(cmd, args=[]){
    return new Observable(observer => {
        let proc = childProcess.spawn(cmd, args);
        let errout = [];
        proc.stderr.on('data', handleData);
        function handleData(data){
            if(errout.length > 20){
                errout.splice(0, errout.length - 20);
            }
            errout.push(data);
        }
        proc.on('close', exitCode => {
            if(exitCode){
                observer.error(new ChildProcessError(exitCode, errout.join('')));
            } else {
                observer.complete();
            }
        });
        observer.next(proc);
        return () => {
            proc.stderr.off('data', handleData);
            proc.kill();
        };
    });
}

module.exports = {
    ChildProcessError,
    spawn,
};
