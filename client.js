function registerSecurityKey() {
    function str2ab(str) {
        var buf = new ArrayBuffer(str.length * 2) // 2 bytes for each char
        var bufView = new Uint8Array(buf)
        for (var i = 0, strLen = str.length; i < strLen; i++) {
            bufView[i] = str.charCodeAt(i)
        }
        return bufView
    }

    function ab2str(ab) {
        return Array.from(new Int8Array(ab))
    }

    let response = {
        rp: { name: "test" },
        user: { id: "teee", name: "a", displayName: "a" },
        challenge: "鲓韲쾧贶ꭳᏞ䂪癑念藃쯻댍棪阢聑뒝씿✡�ビ雕壅⸹軞䲐䏲寚䣰⌞몕蔻",
        pubKeyCredParams: [
            { type: "public-key", alg: -7 },
            { type: "public-key", alg: -257 },
        ],
        timeout: 60000,
        attestation: "direct",
    }

    response.challenge = str2ab(response.challenge)
    response.user.id = new TextEncoder("utf-8").encode(response.user.id)

    function sendResponse(res) {
        let payload = { response: {} }
        payload.rawId = ab2str(res.rawId)
        payload.response.attestationObject = ab2str(
            res.response.attestationObject
        )
        payload.response.clientDataJSON = ab2str(res.response.clientDataJSON)

        console.log(JSON.stringify(payload))
    }
    navigator.credentials
        .create({ publicKey: response })
        .catch(e => alert(e))
        .then(sendResponse)
}
