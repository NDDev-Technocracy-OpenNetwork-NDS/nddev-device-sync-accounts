// browser_credentials.js is generated from this TypeScript source. Do not edit its output.
// Browser credential adapter only. Domain, identity and replication policy stay
// in Rust. No credential is logged or placed in the replica/application cache.
const DATABASE = "nds-credentials-v1";
const MAX_BYTES = 65536;
const SERVICES = new Set([
    "ai.nddev.nds.device.v2",
    "ai.nddev.nds.vault.v1",
    "ai.nddev.nds.offline.v1",
    "ai.nddev.nds.rds.v1",
]);
const failure = () => new Error("credential_store_unavailable");
const identityLeases = new Map();
export function releaseIdentity(id) {
    const lease = identityLeases.get(id);
    if (!lease)
        return;
    identityLeases.delete(id);
    lease.controller.abort();
    lease.release();
}
export function acquireIdentity(id, key) {
    if (!/^[A-Za-z0-9_-]{43}$/.test(id) ||
        !/^[a-f0-9]{64}$/.test(key) ||
        identityLeases.has(id) ||
        identityLeases.size >= 16 ||
        !navigator.locks)
        return Promise.reject(failure());
    return new Promise((resolve, reject) => {
        const controller = new AbortController();
        const ownership = {};
        const held = new Promise((done) => {
            ownership.release = done;
        });
        const release = ownership.release;
        if (!release)
            throw failure();
        const lease = { controller, release };
        identityLeases.set(id, lease);
        const timeout = setTimeout(() => {
            if (identityLeases.get(id) === lease) {
                controller.abort();
                reject(new Error("credential_store_busy"));
            }
        }, 500);
        navigator.locks
            .request(`nds-identity:${key}`, { mode: "exclusive", signal: controller.signal }, async (lock) => {
            if (!lock || !identityLeases.has(id))
                throw failure();
            clearTimeout(timeout);
            resolve();
            await held;
        })
            .catch(() => {
            if (identityLeases.get(id) === lease)
                identityLeases.delete(id);
            release();
            reject(new Error("credential_store_busy"));
        });
        // Bound admission separately from the caller's overall request deadline.
        held.then(() => clearTimeout(timeout));
    });
}
function requestResult(request) {
    return new Promise((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(failure());
    });
}
function completion(transaction) {
    return new Promise((resolve, reject) => {
        transaction.oncomplete = () => resolve();
        transaction.onabort = transaction.onerror = () => reject(failure());
    });
}
function open() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DATABASE, 2);
        let rejected = false;
        request.onupgradeneeded = (event) => {
            const db = request.result;
            if (event.oldVersion < 1) {
                db.createObjectStore("keys");
                db.createObjectStore("credentials");
            }
            if (event.oldVersion < 2)
                db.createObjectStore("authorization");
        };
        request.onblocked = request.onerror = () => {
            rejected = true;
            reject(failure());
        };
        request.onsuccess = () => {
            const db = request.result;
            db.onversionchange = () => db.close();
            if (rejected)
                db.close();
            else
                resolve(db);
        };
    });
}
// The generation fence contains no credential or authorization payload. A
// protected offline grant is usable only if it names this exact Ready generation.
// IndexedDB owns the compare-and-set transaction across every tab/worker.
export async function authorizationFence(key, changeJson) {
    if (!/^[a-f0-9]{64}$/.test(key) || changeJson.length > 1024)
        throw failure();
    const input = JSON.parse(changeJson);
    const fence = (value) => {
        if (typeof value !== "object" ||
            value === null ||
            !("generation" in value) ||
            typeof value.generation !== "string" ||
            !/^[A-Za-z0-9_-]{43}$/.test(value.generation) ||
            !("mode" in value) ||
            typeof value.mode !== "string" ||
            !["checking", "denied", "ready", "signed_out", "pending_logout"].includes(value.mode) ||
            !("slot" in value) ||
            (value.slot !== 0 && value.slot !== 1) ||
            Object.keys(value).length !== 3)
            throw failure();
        return { generation: value.generation, mode: value.mode, slot: value.slot };
    };
    let change = null;
    if (input !== null) {
        if (!Array.isArray(input) || input.length !== 2)
            throw failure();
        change = { expected: input[0] === null ? null : fence(input[0]), next: fence(input[1]) };
    }
    const db = await open();
    try {
        const tx = db.transaction("authorization", change === null ? "readonly" : "readwrite", {
            durability: "strict",
        });
        const done = completion(tx);
        let outcome = null;
        let mismatch = false;
        const request = tx.objectStore("authorization").get(key);
        // Keep the write in the request callback while the IDB transaction is active;
        // awaiting crypto or unrelated work here could commit an incomplete operation.
        request.onsuccess = () => {
            let current;
            try {
                current = request.result == null ? null : fence(request.result);
            }
            catch {
                tx.abort();
                return;
            }
            if (change === null) {
                outcome = current;
                return;
            }
            const { expected, next } = change;
            if ((expected === null && current !== null) ||
                (expected !== null &&
                    (current?.generation !== expected.generation ||
                        current?.mode !== expected.mode ||
                        current?.slot !== expected.slot))) {
                mismatch = true;
                tx.abort();
                return;
            }
            tx.objectStore("authorization").put(next, key);
            outcome = next;
        };
        try {
            await done;
        }
        catch {
            throw new Error(mismatch ? "credential_store_busy" : "credential_store_unavailable");
        }
        return JSON.stringify(outcome);
    }
    finally {
        db.close();
    }
}
function validKey(key) {
    return (key instanceof CryptoKey &&
        key.type === "secret" &&
        !key.extractable &&
        key.algorithm.name === "AES-GCM" &&
        "length" in key.algorithm &&
        key.algorithm.length === 256 &&
        key.usages.length === 2 &&
        key.usages.includes("encrypt") &&
        key.usages.includes("decrypt"));
}
// Explicit local sign-out removes browser copies of vault keys and offline
// grants. It preserves the stable device key and encrypted OPFS replica/outbox;
// a later authenticated active device obtains the same owner key from NDS.
export async function clearOfflineAccess() {
    return navigator.locks.request("nds-credentials-v1", { ifAvailable: true }, async (lock) => {
        if (!lock)
            throw new Error("credential_store_busy");
        const db = await open();
        try {
            const tx = db.transaction("credentials", "readwrite", { durability: "strict" });
            const done = completion(tx);
            const cursor = tx.objectStore("credentials").openCursor();
            let count = 0;
            cursor.onsuccess = () => {
                const row = cursor.result;
                if (!row)
                    return;
                if (++count > 256 || typeof row.key !== "string") {
                    tx.abort();
                    return;
                }
                if (row.key.startsWith("ai.nddev.nds.vault.v1:") ||
                    row.key.startsWith("ai.nddev.nds.offline.v1:"))
                    row.delete();
                row.continue();
            };
            await done;
        }
        finally {
            db.close();
        }
    });
}
/** Only Rust's credential boundary receives the transient decrypted byte array;
 *  it copies into zeroizing memory and wipes this array immediately. */
export async function credentialOperation(action, service, key, input) {
    if (!["read", "write", "delete"].includes(action) ||
        !SERVICES.has(service) ||
        !/^[a-f0-9]{64}$/.test(key) ||
        !(input instanceof Uint8Array) ||
        input.length > MAX_BYTES ||
        !globalThis.isSecureContext ||
        !navigator.locks ||
        !crypto.subtle)
        throw failure();
    // Copy before the first await: a borrowed WASM view cannot outlive its call.
    const secret = new Uint8Array(input);
    try {
        return await navigator.locks.request("nds-credentials-v1", { ifAvailable: true }, async (lock) => {
            if (!lock)
                throw new Error("credential_store_busy");
            const db = await open();
            const id = `${service}:${key}`;
            const aad = new TextEncoder().encode(`NDS-BROWSER-CREDENTIAL-V1\0${id}`);
            try {
                const read = db.transaction(["keys", "credentials"], "readonly");
                const finished = completion(read);
                const [storedKey, entry, count] = await Promise.all([
                    requestResult(read.objectStore("keys").get("wrapping")),
                    requestResult(read.objectStore("credentials").get(id)),
                    requestResult(read.objectStore("credentials").count()),
                    finished,
                ]);
                if (storedKey === undefined && count !== 0)
                    throw failure();
                if (storedKey !== undefined && !validKey(storedKey))
                    throw failure();
                if (action === "read") {
                    if (entry === undefined)
                        return null;
                    if (!storedKey ||
                        typeof entry !== "object" ||
                        entry === null ||
                        !("nonce" in entry) ||
                        !(entry.nonce instanceof Uint8Array) ||
                        entry.nonce.length !== 12 ||
                        !("ciphertext" in entry) ||
                        !(entry.ciphertext instanceof ArrayBuffer) ||
                        entry.ciphertext.byteLength < 16 ||
                        entry.ciphertext.byteLength > MAX_BYTES + 16)
                        throw failure();
                    return new Uint8Array(await crypto.subtle.decrypt({
                        name: "AES-GCM",
                        iv: new Uint8Array(entry.nonce),
                        additionalData: aad,
                        tagLength: 128,
                    }, storedKey, entry.ciphertext));
                }
                if (action === "delete") {
                    const tx = db.transaction("credentials", "readwrite", { durability: "strict" });
                    const committed = completion(tx);
                    tx.objectStore("credentials").delete(id);
                    await committed;
                    return null;
                }
                if (entry === undefined && count >= 256)
                    throw failure();
                const wrapping = storedKey ??
                    (await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
                        "encrypt",
                        "decrypt",
                    ]));
                const nonce = crypto.getRandomValues(new Uint8Array(12));
                const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 }, wrapping, secret);
                const tx = db.transaction(["keys", "credentials"], "readwrite", { durability: "strict" });
                const committed = completion(tx);
                if (storedKey === undefined)
                    tx.objectStore("keys").put(wrapping, "wrapping");
                tx.objectStore("credentials").put({ nonce, ciphertext }, id);
                await committed;
                return null;
            }
            finally {
                db.close();
            }
        });
    }
    catch (error) {
        // Browser/provider details may contain data or URLs. Only these fixed codes
        // cross the adapter boundary; the shared Rust SDK supplies correlation.
        throw new Error(typeof error === "object" &&
            error !== null &&
            "message" in error &&
            error.message === "credential_store_busy"
            ? "credential_store_busy"
            : "credential_store_unavailable");
    }
    finally {
        secret.fill(0);
    }
}
