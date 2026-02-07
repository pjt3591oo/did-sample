
import express from 'express';
import cors from 'cors';
// 필요한 고수준 라이브러리들을 임포트합니다.
import { createVerifiableCredentialJwt, verifyPresentation, verifyCredential } from 'did-jwt-vc';
import { Resolver } from 'did-resolver';
import { getResolver as getKeyResolver } from 'key-did-resolver';
import { getResolver as getWebResolver } from 'web-did-resolver';
import { generateKeyPair } from 'jose';

const app = express();
app.use(cors());
app.use(express.json());

// --- Issuer 및 DID Resolver 설정 ---
let issuer;
let issuerDidDocument;
const domain = 'localhost:4000';

// did:key와 did:web을 모두 해석할 수 있는 통합 DID Resolver를 생성합니다.
const didResolver = new Resolver({
    ...getKeyResolver(),
    ...getWebResolver(),
});

// --- 서버 시작 시 Issuer의 키 쌍, DID, DID Document 생성 ---
async function setupIssuer() {
    // 1. 키 생성 방식을 'jose.generateKeyPair'로 변경 (vanila-key와 동일)
    const { publicKey, privateKey } = await generateKeyPair('Ed25519');
    
    // 2. did-jwt-vc 라이브러리에서 사용할 Signer 객체 생성
    // 이 객체는 { did, signer, alg } 형태를 가집니다.
    const did = `did:web:${domain}`;
    const signer = async (data) => {
        const dataBuffer = typeof data === 'string' ? new TextEncoder().encode(data) : data;
        // crypto.subtle.sign을 사용하여 서명합니다.
        const signatureBytes = await crypto.subtle.sign('Ed25519', privateKey, dataBuffer);
        return Buffer.from(signatureBytes).toString('base64url');
    };
    issuer = { did, signer, alg: 'EdDSA' };

    // 3. did:web DID Document 생성 (이 부분은 did:web의 특성상 수동으로 유지)
    const rawPublicKey = new Uint8Array(await crypto.subtle.exportKey('raw', publicKey));
    const publicKeyJwk = {
        kty: 'OKP',
        crv: 'Ed25519',
        x: Buffer.from(rawPublicKey).toString('base64url'),
    };
    const keyId = `${did}#key-1`;
    issuerDidDocument = {
        '@context': 'https://www.w3.org/ns/did/v1',
        id: did,
        verificationMethod: [{
            id: keyId,
            type: 'JsonWebKey2020',
            controller: did,
            publicKeyJwk: publicKeyJwk,
        }],
        assertionMethod: [keyId],
        authentication: [keyId],
    };

    console.log('✅ Issuer setup complete (using did-jwt-vc style)');
    console.log('Issuer DID:', issuer.did);
}

// --- did:web의 핵심: /.well-known/did.json 경로로 DID Document 제공 ---
app.get('/.well-known/did.json', (req, res) => {
    if (!issuerDidDocument) {
        return res.status(503).send('Issuer not ready');
    }
    res.json(issuerDidDocument);
});


// --- VC 발급 엔드포인트 (리팩터링) ---
app.post('/issue-credential', async (req, res) => {
    try {
        const { holderDid } = req.body;
        if (!holderDid) return res.status(400).send({ error: 'holderDid is required' });

        console.log(`\n🔵 VC 발급 요청 받음. Holder DID: ${holderDid}`);

        const vcPayload = {
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            type: ['VerifiableCredential', 'UniversityDegreeCredential'],
            issuer: { id: issuer.did },
            credentialSubject: {
                id: holderDid,
                degree: { type: 'BachelorDegree', name: 'Computer Science' }
            },
        };

        // 수동 JWT 서명 대신 'createVerifiableCredentialJwt' 함수를 사용합니다.
        const vcJwt = await createVerifiableCredentialJwt(vcPayload, issuer);

        console.log('🟢 발급된 VC (JWT):', vcJwt);
        res.json({ vc: vcJwt });

    } catch (error) {
        console.error('VC 발급 중 오류:', error);
        res.status(500).send({ error: error.message });
    }
});


// --- VP 검증 엔드포인트 (리팩터링) ---
app.post('/verify-presentation', async (req, res) => {
    try {
        const { vp } = req.body;
        if (!vp) return res.status(400).send({ error: 'presentation is required' });
        
        console.log('\n🔵 VP 검증 요청 받음...');

        // 수동 검증 로직 대신 'verifyPresentation' 함수를 사용합니다.
        // 이 함수는 DID Resolver를 사용하여 VP와 그 안의 VC 서명을 모두 자동으로 검증합니다.
        const verificationResult = await verifyPresentation(vp, didResolver);
        
        console.log('🟢 VP 검증 최종 성공:', verificationResult);
        res.json(verificationResult);

    } catch (error) {
        console.error('VP 검증 중 오류:', error);
        res.status(500).json({ verified: false, error: error.message });
    }
});


// --- 서버 실행 ---
app.listen(4000, async () => {
    await setupIssuer();
    console.log(`\n🚀 Server listening on port 4000`);
    console.log(`DID Document available at http://${domain}/.well-known/did.json`);
});
