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

let { execFile } = require('child_process');
let { randomBytes } = require('crypto');
let { readFile, stat, writeFile } = require('node:fs/promises');

let { serve } = require('/opt/evr/evr-websocket-server/lib/server');

let gpgPubExportPath = '/pub/my-identity.pub.gpg';
let gpgSecExportPath = '/data/my-identity.sec.gpg';
let gpgTrustDbPath = '/data/gpg-ownertrust.txt';

main()
    .catch(e => {
        console.error(e);
        process.exitCode = 1;
    });

async function main(){
    process.chdir('/opt/evr');
    await waitForConfig();
    await importSigningKeys();
    let signingKey = await getSigningKey();
    await exportGpgIdentity(signingKey);
    let configPath = await buildWebsocketServerConfig(signingKey);
    await buildEvrConfig(configPath);
    await new Promise((resolve, reject) => {
        serve(configPath).subscribe({
            complete: resolve,
            error: reject,
        });
    });
}

async function waitForConfig(){
    let firstTry = true;
    
    return new Promise((resolve, reject) => {
        checkAndSchedule(err => {
            if(err) {
                reject(err);
            } else {
                console.log('Found config files provided by evr-glacier-storage');
                resolve();
            }
        });
    });
    
    function checkAndSchedule(onReady){
        checkReady()
            .then(ready => {
                if(ready) {
                    onReady(null);
                } else {
                    if(firstTry){
                        firstTry = false;
                        console.log('Waiting for config files provided by evr-glacier-storage...');
                    }
                    setTimeout(() => checkAndSchedule(onReady), 500);
                }
            })
            .catch(err => onReady(err));
    }

    async function checkReady(){
        for(let fn of ['/pub/evr-glacier-storage-cert.pem', '/pub/auth-token']){
            if(!await exists(fn)){
                return false;
            }
        }
        return true;
    }
}

async function importSigningKeys(){
    if(await exists(gpgPubExportPath)){
        console.log('Importing public GPG key...');
        await gpg(['--import', gpgPubExportPath]);
    }
    if(await exists(gpgSecExportPath)){
        console.log('Import secret GPG key...');
        await gpg(['--import', gpgSecExportPath]);
    }
    if(await exists(gpgTrustDbPath)){
        console.log('Import GPG owner trust...');
        let trustDb = await readFile(gpgTrustDbPath, { encoding: 'utf-8' });
        await gpg(['--import-ownertrust', gpgTrustDbPath], trustDb);
    }
}

async function getSigningKey(){
    let secretKey = await getSecretKey();
    if(secretKey){
        return secretKey;
    }
    console.log('Generating GPG key...');
    await gpg(['--quick-gen-key', '--batch', '--passphrase', '', 'evr-websocket-server@example.org', 'default', 'default', '3650d']);
    secretKey = await getSecretKey();
    if(secretKey){
        return secretKey;
    }
    throw new Error(`No GPG secret key found`);
}

async function getSecretKey(){
    for(let line of (await gpg(['--list-secret-keys', '--with-colons'])).split('\n')){
        let cols = line.split(':');
        if(cols[0] !== 'fpr'){
            continue;
        }
        let fpr = cols[9];
        return fpr;
    }
    return null;
}

async function exportGpgIdentity(key){
    if(!await exists(gpgPubExportPath)){
        console.log('Exporting public GPG key...');
        await gpg(['--export', '--output', gpgPubExportPath, key]);
    }
    if(!await exists(gpgSecExportPath)){
        console.log('Exporting secret GPG key...');
        await gpg(['--export-secret-keys', '--output', gpgSecExportPath, key]);
    }
    if(!await exists(gpgTrustDbPath)){
        console.log('Export GPG owner trust...');
        let trustDb = await gpg(['--export-ownertrust']);
        await writeFile(gpgTrustDbPath, trustDb, { encoding: 'utf-8' });
    }
}

function gpg(args, stdin=undefined){
    return new Promise((resolve, reject) => {
        let p = execFile('gpg', args, { encoding: 'utf-8'}, (err, stdout, stderr) => {
            if(err){
                console.log(`GPG ${JSON.stringify(args)} failed: ${stderr}`, err);
                reject(err);
            } else {
                resolve(stdout);
            }
        });
        if(stdin !== undefined){
            p.stdin.end(stdin, 'utf-8');
        }
    });
}

async function buildWebsocketServerConfig(signingKey){
    let configPath = '/pub/evr-websocket-server.conf.json';
    if(!await exists(configPath)){
        let config = {
            user: {
                kim: {
                    password: randomPassword(),
                    'signing-key': signingKey,
                    'gpg-keys': [
                        signingKey,
                    ],
                },
            },
        };
        await writeFile(configPath, JSON.stringify(config, undefined, '\t'), {
            encoding: 'utf-8',
        });
    }
    return configPath;
}

function randomPassword(){
    let len = 32;
    return randomBytes(Math.ceil(len / 2)).toString('hex').slice(0, len);
}

async function buildEvrConfig(serverConfigPath){
    let evrConfigPath = '/opt/evr/evr.conf';
    let storageHost = process.env['EVR_GLACIER_STORAGE_HOST'];
    if(!storageHost){
        throw new Error(`Environment variable EVR_GLACIER_STORAGE_HOST must specify hosname of evr-glacier-storage server.`);
    }
    let storagePort = process.env['EVR_GLACIER_STORAGE_PORT'] || '2361';
    let authToken = await readFile('/pub/auth-token', { encoding: 'utf-8' });
    let evrConfig = [
        `storage-host=${storageHost}`,
        `storage-port=${storagePort}`,
        `ssl-cert=${storageHost}:${storagePort}:/pub/evr-glacier-storage-cert.pem`,
        `auth-token=${storageHost}:${storagePort}:${authToken}`,
    ];
    let serverConfig = JSON.parse(await readFile(serverConfigPath, {encoding: 'utf-8'}));
    let visitedKeys = new Set();
    for(let userName of Object.keys(serverConfig.user)){
        let user = serverConfig.user[userName];
        if(user.hasOwnProperty('gpg-keys')){
            for(let gpgKey of user['gpg-keys']){
                if(visitedKeys.has(gpgKey)){
                    continue;
                }
                visitedKeys.add(gpgKey);
                evrConfig.push(`accepted-gpg-key=${gpgKey}`);
            }
        }
    }
    await writeFile(evrConfigPath, evrConfig.map(l => `${l}\n`).join(''), { encoding: 'utf-8' });
    return evrConfigPath;
}

async function exists(pathName){
    try {
        await stat(pathName);
        return true;
    } catch(e) {
        if(e?.code === 'ENOENT'){
            return false;
        }
        throw e;
    }
}
