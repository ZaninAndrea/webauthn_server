const { Fido2Lib } = require("fido2-lib")
const express = require("express")
var bodyParser = require("body-parser")

const app = express()
app.use(bodyParser.json())
const port = 3000

app.listen(port, () => console.log(`Example app listening on port ${port}!`))
var f2l = new Fido2Lib()

function ab2str(buf) {
    return String.fromCharCode.apply(null, new Uint16Array(buf))
}
function str2ab(str) {
    var buf = new ArrayBuffer(str.length * 2) // 2 bytes for each char
    var bufView = new Uint8Array(buf)
    for (var i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i)
    }
    return bufView
}

let challenge
function storeUserChallenge(str) {
    challenge = str
    console.log("stored")
    console.log(challenge)
}

app.get("/subscribe", async (req, res) => {
    var registrationOptions = await f2l.attestationOptions()

    registrationOptions.challenge = ab2str(registrationOptions.challenge)
    storeUserChallenge(registrationOptions.challenge)
    registrationOptions.rp = { name: "test" }
    registrationOptions.user = { id: "teee", name: "a", displayName: "a" }

    res.send(registrationOptions)
})

function getUserChallenge() {
    return "꺆뮄粷㆏Ⱌ灃뮿̗□�ᙏ㔅￯앢䢩鲁㾘ⅼ㪂밯迺ꌤ׷�鏁唔禢"
    console.log("retrieved")
    console.log(challenge)
    return challenge
}

let pubKey
function recordPublicKey(pk) {
    pubKey = pk
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
        origin: "https://github.com", // TODO: replace with real URL
        factor: "either",
    }
    var regResult = await f2l.attestationResult(
        clientAttestationResponse,
        attestationExpectations
    ) // will throw on error

    const publicKey = regResult.authnrData.get("credentialPublicKeyPem")
    const counter = regResult.authnrData.get("counter")

    recordPublicKey(publicKey)
    res.send("OK")
})
