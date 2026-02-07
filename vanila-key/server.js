import express from 'express';
import cors from 'cors';
import { createVerifiableCredentialJwt, verifyPresentation, verifyCredential } from 'did-jwt-vc';
import { Resolver } from 'did-resolver';
import { getResolver as getKeyResolver } from 'key-did-resolver';
import { generateKeyPair } from 'jose';
import { base58btc } from 'multiformats/bases/base58';

const app = express();
app.use(cors());
app.use(express.json());

let issuer;
const keyResolver = getKeyResolver();
const didResolver = new Resolver(keyResolver);

// 1. Issuer Setup
async function setupIssuer() {
    const { publicKey, privateKey } = await generateKeyPair('Ed25519');
    
    const rawPublicKey = new Uint8Array(await crypto.subtle.exportKey('raw', publicKey));

    // Create a did:key from the public key using base58btc
    const multicodec = new Uint8Array([0xed, 0x01, ...rawPublicKey]);
    const didKey = `did:key:${base58btc.encode(multicodec)}`;
    
    const signer = async (data) => {
        const dataBuffer = typeof data === 'string' ? new TextEncoder().encode(data) : data;
        const signatureBytes = await crypto.subtle.sign('Ed25519', privateKey, dataBuffer);
        return Buffer.from(signatureBytes).toString('base64url');
    };

    issuer = {
        did: didKey,
        signer,
        alg: 'EdDSA'
    };

    console.log('Issuer DID:', issuer.did);
}

// vc
app.post('/issue-credential', async (req, res) => {
    try {
        const { holderDid } = req.body;
        if (!holderDid) {
            return res.status(400).send({ error: 'holderDid is required' });
        }

        console.log(`Issuing credential for holder: ${holderDid}`);

        const vcPayload = {
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            type: ['VerifiableCredential'],
            issuer: { id: issuer.did },
            credentialSubject: {
                id: holderDid,
                name: 'Alice',
            },
            issuanceDate: new Date().toISOString(),
        };

        // sign the VC to create a JWT
        const vcJwt = await createVerifiableCredentialJwt(vcPayload, issuer);
        console.log('VC JWT created:', vcJwt);
        res.send({ vcJwt });

    } catch (error) {
        console.error('Error issuing credential:', error);
        res.status(500).send({ error: error.message });
    }
});

// vp
app.post('/verify-presentation', async (req, res) => {
    try {
        const { presentation } = req.body;
        if (!presentation) {
            return res.status(400).send({ error: 'presentation is required' });
        }

        console.log('Verifying presentation...');
        const verificationResult = await verifyPresentation(presentation, didResolver);
        
        // Also verify the credential inside the presentation
        if (verificationResult.verified) {
            const vcInVp = verificationResult.payload.vp.verifiableCredential[0];
            const vcVerificationResult = await verifyCredential(vcInVp, didResolver);
            console.log('VC Verification Result:', vcVerificationResult);
            verificationResult.vcVerified = vcVerificationResult.verified;
        }

        console.log('Presentation verification result:', verificationResult);
        res.send(verificationResult);

    } catch (error) {
        console.error('Error verifying presentation:', error);
        res.status(500).send({ error: error.message });
    }
});

// Start Server
app.listen(4000, async () => {
    await setupIssuer();
    console.log('Vanilla Server listening on port 4000');
});
