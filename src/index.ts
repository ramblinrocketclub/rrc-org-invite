import { Router } from 'itty-router'
import 'bindings.d.ts'
//import '@cloudflare/workers-types'

/* global SLACK_SIGNING_SECRET */

const SIGN_VERSION = 'v0' // per documentation, this is always "v0"
// const SLACK_SIGNING_SECRET_RRC
// const SLACK_SIGNING_SECRET_HAB
// const SLACK_SIGNING_SECRET_GTXR
// const GITHUB_USERNAME
// const GITHUB_TOKEN

/**
 * Verify that a request actually came from Slack using our Signing Secret
 * and HMAC-SHA256.
 *
 * Based on code examples found in Cloudflare's documentation:
 * https://developers.cloudflare.com/workers/examples/signing-requests
 *
 * @param {Request} request incoming request purportedly from Slack
 * @returns {Promise<boolean>} true if the signature verification was valid
 */
async function verifySlackSignature(request: Request, secret: string) {
    const timestamp = request.headers.get('x-slack-request-timestamp')

    console.log("verifySlackSignature")
    console.log(timestamp)

    // remove starting 'v0=' from the signature header
    const header = request.headers.get('x-slack-signature');
    if (!header) {
        return false;
    }
    const signatureStr = header.substring(3)
    // convert the hex string of x-slack-signature header to binary
    const signature = hexToBytes(signatureStr)

    const content = await request.clone().text()
    const authString = `${SIGN_VERSION}:${timestamp}:${content}`
    let encoder = new TextEncoder()
    const key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['verify']
    )
    const verified = await crypto.subtle.verify(
        'HMAC',
        key,
        signature,
        encoder.encode(authString)
    )

    console.log(verified)

    return verified
}

interface GithubResponse {
    id: string
}

/**
 * Modified version of hex to bytes function posted here:
 * https://stackoverflow.com/a/34356351/489667
 *
 * @param {string} hex a string of hexadecimal characters
 * @returns {ArrayBuffer} binary form of the hexadecimal string
 */
function hexToBytes(hex: string) {
    const bytes = new Uint8Array(hex.length / 2)
    for (let c = 0; c < hex.length; c += 2) {
        bytes[c / 2] = parseInt(hex.substr(c, 2), 16)
    }

    return bytes.buffer
}

const verifySlackSignatureRRC = async (request: Request) => {
    const verified = await verifySlackSignature(
        request,
        SLACK_SIGNING_SECRET_RRC
    )
    if (!verified) {
        console.log("not authenticated")
        return new Response('Not Authenticated', { status: 401 })
    }
}

const verifySlackSignatureHAB = async (request: Request) => {
    const verified = await verifySlackSignature(
        request,
        SLACK_SIGNING_SECRET_HAB
    )
    if (!verified) {
        return new Response('Not Authenticated', { status: 401 })
    }
}

const verifySlackSignatureGTXR = async (request: Request) => {
    const verified = await verifySlackSignature(
        request,
        SLACK_SIGNING_SECRET_GTXR
    )
    if (!verified) {
        return new Response('Not Authenticated', { status: 401 })
    }
}

async function handleInviteRequest(request: Request) {
    const body = await request.text()
    const formData = new URLSearchParams(body)
    const username = formData.get('text')
    const usernameUrl = 'https://api.github.com/users/' + username
    const orgUrl = 'https://api.github.com/orgs/ramblinrocketclub/invitations'

    console.log("handleInviteRequest")
    console.log("username " + username)

    const githubUsername = await fetch(usernameUrl, {
        method: 'GET',
        headers: {
            'User-Agent': 'aditsachde',
            'Accept': 'application/vnd.github.v3+json',
            'Authorization':
                'token ' + GITHUB_TOKEN,
        },
    })

    const status = githubUsername.status
    console.log(status)
    console.log(githubUsername)

    if (status !== 200) {
        return new Response('Username not found!', { status: 200 })
    }

    const githubUsernameJson = await githubUsername.json()
    if (!(githubUsernameJson as GithubResponse).hasOwnProperty('id')) {
        return new Response('Bad response from GitHub!!', { status: 200 })
    }
    let id = (githubUsernameJson as GithubResponse).id
    //console.log('github username headers: ' + JSON.stringify(githubUsername.headers))
    //console.log("github username json response: " + JSON.stringify(githubUsernameJson))

    console.log("inviting user: " + id)

    const stringifiedBody = JSON.stringify({
        invitee_id: id,
    })
    console.log(stringifiedBody)

    const githubInvite = await fetch(orgUrl, {
        method: 'POST',
        headers: {
            'User-Agent': 'aditsachde',
            'Accept': 'application/vnd.github.v3+json',
            'Authorization':
                'token ' + GITHUB_TOKEN,
        },
        body: stringifiedBody,
    })

    const inviteStatus = githubInvite.status
    console.log(inviteStatus)
    console.log(githubInvite)

    if (inviteStatus !== 201) {
        return new Response('Failed to create invite! You may already be in the organization!', { status: 200 })
    }

    return new Response(
        'User ' +
        username +
        'invited to the RRC organization. Please check your email!',
        { status: 200 }
    )
}

// Create a new router
const router = Router()

router.post('/rrc', verifySlackSignatureRRC, async request => {
    console.log("handling invite request @ rrc")
    return await handleInviteRequest(request)
})

router.post('/hab', verifySlackSignatureHAB, async request => {
    console.log("handling invite request @ hab")
    return await handleInviteRequest(request)
})

router.post('/gtxr', verifySlackSignatureGTXR, async request => {
    console.log("handling invite request @ gtxr")
    return await handleInviteRequest(request)
})

/*
This is the last route we define, it will match anything that hasn't hit a route we've defined
above, therefore it's useful as a 404 (and avoids us hitting worker exceptions, so make sure to include it!).

Visit any page that doesn't exist (e.g. /foobar) to see it in action.
*/
router.all('*', () => new Response('404, not found!', { status: 404 }))

/*
This snippet ties our worker to the router we deifned above, all incoming requests
are passed to the router where your routes are called and the response is sent.
*/
addEventListener('fetch', e => {
    e.respondWith(router.handle(e.request))
})
