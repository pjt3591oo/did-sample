import axios from 'axios';
import { createVerifiablePresentationJwt } from 'did-jwt-vc';
import { generateKeyPair } from 'jose';
import { base58btc } from 'multiformats/bases/base58';

let holder;

// 1. Holder Setup
async function setupHolder() {
    const { publicKey, privateKey } = await generateKeyPair('Ed25519');
    
    const rawPublicKey = new Uint8Array(await crypto.subtle.exportKey('raw', publicKey));

    // Create a did:key from the public key using base58btc
    // The multicodec prefix for Ed25519 is 0xed01
    const multicodec = new Uint8Array([0xed, 0x01, ...rawPublicKey]);
    const didKey = `did:key:${base58btc.encode(multicodec)}`;

    const signer = async (data) => {
        const dataBuffer = typeof data === 'string' ? new TextEncoder().encode(data) : data;
        const signatureBytes = await crypto.subtle.sign('Ed25519', privateKey, dataBuffer);
        return Buffer.from(signatureBytes).toString('base64url');
    };

    holder = {
        did: didKey,
        signer,
        alg: 'EdDSA'
    };
    console.log('Holder DID created:', holder.did);
}

async function main() {
    await setupHolder();

    // 2. Request Credential from Server
    console.log('\n--- Requesting Credential from Server ---');
    try {
        const response = await axios.post('http://localhost:4000/issue-credential', {
            holderDid: holder.did,
        });
        const { vcJwt } = response.data;
        console.log('VC JWT Received:', vcJwt);

        // 3. Create Verifiable Presentation
        console.log('\n--- Creating Verifiable Presentation ---');
        const vpPayload = {
            vp: {
                '@context': ['https://www.w3.org/2018/credentials/v1'],
                type: ['VerifiablePresentation'],
                verifiableCredential: [vcJwt],
            },
        };
        const vpJwt = await createVerifiablePresentationJwt(vpPayload, holder);
        console.log('VP JWT Created:', vpJwt);

        // 4. Verify Presentation with Server
        console.log('\n--- Verifying Presentation with Server ---');
        const verificationResponse = await axios.post('http://localhost:4000/verify-presentation', {
            presentation: vpJwt,
        });
        const verificationResult = verificationResponse.data;
        console.log('Server Verification Result:', JSON.stringify(verificationResult, null, 2));

        if (verificationResult.verified && verificationResult.vcVerified) {
            console.log('\nSuccessfully verified by the server!');
        } else {
            console.log('\nVerification failed.');
        }

    } catch (error) {
        console.error('\n--- An error occurred ---');
        if (error.response) {
            console.error('Error Data:', error.response.data);
            console.error('Error Status:', error.response.status);
        } else {
            console.error('Error Message:', error.message);
        }
    }
}

main().catch(console.error);
