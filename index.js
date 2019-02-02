const { Fido2Lib } = require("fido2-lib")
const express = require("express")
var bodyParser = require("body-parser")

const app = express()
app.use(bodyParser.json())
const port = 3000

var f2l = new Fido2Lib()

function ab2str(buf) {
    return String.fromCharCode.apply(null, new Uint8Array(buf))
}
function str2ab(str) {
    return Uint8Array.from(str, c => c.charCodeAt(0))
}

let challenge
function storeUserChallenge(str) {
    challenge = str
}

app.get("/subscribe", async (req, res) => {
    var registrationOptions = await f2l.attestationOptions()

    registrationOptions.challenge = ab2str(registrationOptions.challenge)
    storeUserChallenge(registrationOptions.challenge)
    registrationOptions.rp = { name: "test" }
    registrationOptions.user = { id: "teee", name: "a", displayName: "a" }
    registrationOptions.pubKeyCredParams = [{ alg: -7, type: "public-key" }]
    registrationOptions.authenticatorSelection = {
        authenticatorAttachment: "cross-platform",
    }
    registrationOptions.timeout = 60000
    registrationOptions.attestation = "none"

    res.send(registrationOptions)
})

function getUserChallenge() {
    return challenge
}

let pubKey
function recordPublicKey(pk) {
    pubKey = pk
}

let id
function recordCredId(k) {
    id = k
}
app.post("/subscribeChallengeResponse", async (req, res) => {
    var clientAttestationResponse = req.body
    clientAttestationResponse.rawId = new Int8Array(
        clientAttestationResponse.rawId
    ).buffer
    clientAttestationResponse.response.attestationObject = new Int8Array(
        clientAttestationResponse.response.attestationObject
    ).buffer
    clientAttestationResponse.response.clientDataJSON = new Int8Array(
        clientAttestationResponse.response.clientDataJSON
    ).buffer

    var attestationExpectations = {
        challenge: str2ab(getUserChallenge()),
        origin: "https://webauthn.localtunnel.me", // TODO: replace with real URL
        factor: "either",
    }
    try {
        var regResult = await f2l.attestationResult(
            clientAttestationResponse,
            attestationExpectations
        ) // will throw on error

        const publicKey = regResult.authnrData.get("credentialPublicKeyPem")
        const credId = regResult.authnrData.get("credId")
        const counter = regResult.authnrData.get("counter")

        recordPublicKey(publicKey)
        recordCredId(ab2str(credId))
        res.send("OK")
    } catch (e) {
        console.log(e)
        res.send(e.message)
    }
})

let signInChallenge
function storeSignInChallenge(str) {
    signInChallenge = str
}
function getLogInChallenge() {
    return signInChallenge
}

function getPublicKey() {
    return pubKey
}

function getCredID() {
    return id
}

app.get("/signIn", async (req, res) => {
    var authnOptions = await f2l.assertionOptions()

    authnOptions.challenge = ab2str(authnOptions.challenge)
    authnOptions.allowCredentials = [
        { type: "public-key", alg: -7, id: getCredID() },
        { type: "public-key", alg: -257, id: getCredID() },
    ]
    authnOptions.rp = { name: "test" }
    authnOptions.user = { id: "teee", name: "a", displayName: "a" }
    authnOptions.userVerification = "discouraged"
    storeSignInChallenge(authnOptions.challenge)

    res.send(authnOptions)
})
app.post("/signInChallengeResponse", async (req, res) => {
    var clientAssertionResponse = req.body
    clientAssertionResponse.rawId = new Int8Array(
        clientAssertionResponse.rawId
    ).buffer
    clientAssertionResponse.response.clientDataJSON = new Int8Array(
        clientAssertionResponse.response.clientDataJSON
    ).buffer
    clientAssertionResponse.response.authenticatorData = new Int8Array(
        clientAssertionResponse.response.authenticatorData
    ).buffer
    clientAssertionResponse.response.signature = new Int8Array(
        clientAssertionResponse.response.signature
    ).buffer

    var assertionExpectations = {
        challenge: str2ab(getLogInChallenge()),
        origin: "https://webauthn.localtunnel.me", // TODO: replace with real URL
        factor: "either",
        publicKey: getPublicKey(),
        userHandle: null,
        prevCounter: 0,
    }

    try {
        var authnResult = await f2l.assertionResult(
            clientAssertionResponse,
            assertionExpectations
        )

        res.send("OK")
    } catch (e) {
        console.log(e)
        res.send(e.message)
    }
})

app.get("/", function(req, res) {
    res.sendfile("default.html", { root: __dirname + "/public" })
})
app.get("/client.js", function(req, res) {
    res.sendfile("client.js", { root: __dirname + "/public" })
})

app.listen(port, () => console.log(`Example app listening on port ${port}!`))
