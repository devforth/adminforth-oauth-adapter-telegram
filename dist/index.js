import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
const TELEGRAM_AUTH_URL = "https://oauth.telegram.org/auth";
const TELEGRAM_TOKEN_URL = "https://oauth.telegram.org/token";
const TELEGRAM_ISSUER = "https://oauth.telegram.org";
const DEFAULT_SCOPES = ["openid", "profile"];
function base64UrlEncode(input) {
    return input.toString("base64url");
}
function base64Encode(input) {
    return input.toString("base64");
}
function createCodeChallenge(codeVerifier) {
    return base64UrlEncode(createHash("sha256").update(codeVerifier).digest());
}
function createDefaultCodeVerifier(clientID, clientSecret) {
    return base64UrlEncode(createHash("sha256").update(`${clientID}:${clientSecret}`).digest());
}
function decodeJwtPayload(token) {
    const [, payload] = token.split(".");
    return JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
}
export default class AdminForthAdapterTelegramOauth2 {
    constructor(options) {
        var _a, _b;
        this.clientID = options.clientID;
        this.clientSecret = options.clientSecret;
        this.redirectUri = options.redirectUri;
        this.scopes = (_a = options.scopes) !== null && _a !== void 0 ? _a : DEFAULT_SCOPES;
        this.codeVerifier = (_b = options.codeVerifier) !== null && _b !== void 0 ? _b : createDefaultCodeVerifier(options.clientID, options.clientSecret);
    }
    getAuthUrl() {
        const params = new URLSearchParams({
            client_id: this.clientID,
            response_type: "code",
            scope: this.scopes.join(" "),
            code_challenge: createCodeChallenge(this.codeVerifier),
            code_challenge_method: "S256",
        });
        if (this.redirectUri) {
            params.set("redirect_uri", this.redirectUri);
        }
        return `${TELEGRAM_AUTH_URL}?${params.toString()}`;
    }
    async getTokenFromCode(code, redirect_uri) {
        const tokenResponse = await fetch(TELEGRAM_TOKEN_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                Authorization: `Basic ${base64Encode(Buffer.from(`${this.clientID}:${this.clientSecret}`))}`,
            },
            body: new URLSearchParams({
                grant_type: "authorization_code",
                code,
                redirect_uri,
                client_id: this.clientID,
                code_verifier: this.codeVerifier,
            }),
        });
        const tokenData = await tokenResponse.json();
        if (tokenData.error) {
            throw new Error(tokenData.error_description || tokenData.error);
        }
        if (!tokenData.id_token) {
            throw new Error("Telegram OAuth response does not include id_token");
        }
        const claims = decodeJwtPayload(tokenData.id_token);
        if (claims.iss !== TELEGRAM_ISSUER) {
            throw new Error(`Telegram OAuth id_token has invalid issuer "${claims.iss}"`);
        }
        if (`${claims.aud}` !== `${this.clientID}`) {
            throw new Error(`Telegram OAuth id_token has invalid audience "${claims.aud}"`);
        }
        if (claims.exp * 1000 < Date.now()) {
            throw new Error("Telegram OAuth id_token is expired");
        }
        return {
            provider: this.constructor.name,
            subject: claims.sub,
            phone: claims.phone_number,
            fullName: claims.name,
            profilePictureUrl: claims.picture,
            externalUserId: claims.id,
            meta: {
                username: claims.preferred_username,
            },
        };
    }
    getName() {
        return "Telegram";
    }
    getIcon() {
        return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 240 240"><circle cx="120" cy="120" r="120" fill="#2AABEE"/><path fill="#fff" d="M98.4 155.1 94.4 211c5.8 0 8.3-2.5 11.3-5.5l27.1-25.9 56.2 41.2c10.3 5.7 17.6 2.7 20.4-9.5l37-173.4.1-.1c3.3-15.2-5.5-21.2-15.5-17.5L13.5 104.1C-1.4 109.9-1.2 118.2 11 122l55.6 17.3L195.8 57.7c6.1-4 11.6-1.8 7.1 2.3L98.4 155.1Z" transform="translate(15 28) scale(0.76)"/></svg>`;
    }
}
