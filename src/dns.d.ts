declare module "dns" {
    export interface MxRecord {
        exchange: string,
        priority: number
    }

    export function getServers(): string[];
    export function lookup(domain: string, family: number, callback: (err: Error, address: string, family: number) => void): string;
    export function lookup(domain: string, callback: (err: Error, address: string, family: number) => void): string;
    export function resolve(domain: string, rrtype: string, callback: (err: Error, addresses: string[]) => void): string[];
    export function resolve(domain: string, callback: (err: Error, addresses: string[]) => void): string[];
    export function resolve4(domain: string, callback: (err: Error, addresses: string[]) => void): string[];
    export function resolve6(domain: string, callback: (err: Error, addresses: string[]) => void): string[];
    export function resolveMx(domain: string, callback: (err: Error, addresses: MxRecord[]) => void): string[];
    export function resolveTxt(domain: string, callback: (err: Error, addresses: string[][]) => void): string[][];
    export function resolveSrv(domain: string, callback: (err: Error, addresses: string[]) => void): string[];
    export function resolveNs(domain: string, callback: (err: Error, addresses: string[]) => void): string[];
    export function resolveCname(domain: string, callback: (err: Error, addresses: string[]) => void): string[];
    export function reverse(ip: string, callback: (err: Error, domains: string[]) => void): string[];
    export function setServers(servers: string[]): void;

    //Error codes
    export var NODATA: string;
    export var FORMERR: string;
    export var SERVFAIL: string;
    export var NOTFOUND: string;
    export var NOTIMP: string;
    export var REFUSED: string;
    export var BADQUERY: string;
    export var BADNAME: string;
    export var BADFAMILY: string;
    export var BADRESP: string;
    export var CONNREFUSED: string;
    export var TIMEOUT: string;
    export var EOF: string;
    export var FILE: string;
    export var NOMEM: string;
    export var DESTRUCTION: string;
    export var BADSTR: string;
    export var BADFLAGS: string;
    export var NONAME: string;
    export var BADHINTS: string;
    export var NOTINITIALIZED: string;
    export var LOADIPHLPAPI: string;
    export var ADDRGETNETWORKPARAMS: string;
    export var CANCELLED: string;
}
