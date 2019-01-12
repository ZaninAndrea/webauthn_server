function str2ab(str) {
    var buf = new ArrayBuffer(str.length) // 2 bytes for each char
    var bufView = new Uint8Array(buf)
    for (var i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i)
    }
    return bufView
}

function ab2str(ab) {
    return Array.from(new Int8Array(ab))
}

async function registerSecurityKey() {
    const rawGetResponse = await fetch(
        "https://perfect-badger-36.localtunnel.me/subscribe",
        {
            method: "GET",
            headers: {
                Accept: "application/json",
                "Content-Type": "application/json",
            },
        }
    )
    const response = await rawGetResponse.json()

    response.challenge = str2ab(response.challenge)
    response.user.id = new TextEncoder("utf-8").encode(response.user.id)

    async function sendResponse(res) {
        let payload = { response: {} }
        payload.rawId = ab2str(res.rawId)
        payload.response.attestationObject = ab2str(
            res.response.attestationObject
        )
        payload.response.clientDataJSON = ab2str(res.response.clientDataJSON)

        const rawResponse = await fetch(
            "https://perfect-badger-36.localtunnel.me/subscribeChallengeResponse",
            {
                method: "POST",
                headers: {
                    Accept: "application/json",
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(payload),
            }
        )
        const content = await rawResponse.text()

        console.log(content)
    }

    navigator.credentials
        .create({ publicKey: response })
        .catch(e => alert(e))
        .then(sendResponse)
}

async function signIn() {
    const rawGetResponse = await fetch(
        "https://perfect-badger-36.localtunnel.me/signIn",
        {
            method: "GET",
            headers: {
                Accept: "application/json",
                "Content-Type": "application/json",
            },
        }
    )
    const response = await rawGetResponse.json()

    response.challenge = str2ab(response.challenge)
    response.user.id = new TextEncoder("utf-8").encode(response.user.id)
    response.pubKeyCredParams = response.pubKeyCredParams.map(cred => ({
        ...cred,
        id: str2ab(cred.id),
    }))

    async function sendResponse(res) {
        console.log(res)
        let payload = { response: {} }
        payload.rawId = ab2str(res.rawId)
        payload.response.attestationObject = ab2str(
            res.response.attestationObject
        )
        payload.response.clientDataJSON = ab2str(res.response.clientDataJSON)

        const rawResponse = await fetch(
            "https://perfect-badger-36.localtunnel.me/signInChallengeResponse",
            {
                method: "POST",
                headers: {
                    Accept: "application/json",
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(payload),
            }
        )
        const content = await rawResponse.text()

        console.log(content)
    }

    navigator.credentials
        .create({ publicKey: response })
        .then(sendResponse)
        .catch(e => alert(e))
}
