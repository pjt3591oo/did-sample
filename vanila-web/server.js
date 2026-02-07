
import express from 'express';
import cors from 'cors';
import * as jose from 'jose';
import nacl from 'tweetnacl';

const app = express();
app.use(cors());
app.use(express.json());

// --- Issuer 설정 ---
let issuerKeys;
let issuerDid;
let issuerDidDocument;
const domain = 'localhost:4000'; // did:web에서 사용할 도메인. 포트번호 변경

// --- 서버 시작 시 Issuer의 키 쌍, DID, DID Document 생성 ---
async function setupIssuer() {
    // 1. Ed25519 키 쌍 생성
    issuerKeys = nacl.sign.keyPair();
    
    // `jose` 라이브러리에서 사용할 수 있도록 공개키를 JWK(JSON Web Key) 형식으로 변환합니다.
    const publicKeyJwk = {
        kty: 'OKP',
        crv: 'Ed25519',
        x: Buffer.from(issuerKeys.publicKey).toString('base64url'),
    };

    // 2. did:web DID 생성
    // did:web:{domain} 형식입니다.
    issuerDid = `did:web:${domain}`;

    // 3. DID Document 생성
    // DID Document는 해당 DID의 소유자를 증명하고, 상호작용(예: 서명 검증)에 필요한 정보를 담고 있습니다.
    const keyId = `${issuerDid}#key-1`;
    issuerDidDocument = {
        '@context': 'https://www.w3.org/ns/did/v1',
        id: issuerDid,
        // 'verificationMethod'는 DID 소유자가 자신의 통제권을 증명하는 데 사용할 수 있는 공개키 등의 정보를 포함합니다.
        verificationMethod: [
            {
                id: keyId,
                type: 'JsonWebKey2020', // JWK 형식을 사용함을 명시
                controller: issuerDid,
                publicKeyJwk: publicKeyJwk,
            },
        ],
        // 'assertionMethod'는 VC를 발급(주장)할 때 사용하는 키를 지정합니다.
        assertionMethod: [keyId],
        // 'authentication'은 DID 소유자를 인증할 때 사용하는 키를 지정합니다.
        authentication: [keyId],
    };

    console.log('✅ Issuer setup complete');
    console.log('Isser DID:', issuerDid);
    console.log('Issuer DID Document:', JSON.stringify(issuerDidDocument, null, 2));
}

// --- did:web의 핵심: /.well-known/did.json 경로로 DID Document 제공 ---
// DID Resolver는 `did:web:localhost:4000`을 해석(resolve)하기 위해
// `http://localhost:4000/.well-known/did.json` 주소로 GET 요청을 보냅니다.
app.get('/.well-known/did.json', (req, res) => {
    if (!issuerDidDocument) {
        return res.status(503).send('Issuer not ready');
    }
    res.json(issuerDidDocument);
});


// --- VC 발급 엔드포인트 ---
app.post('/issue-credential', async (req, res) => {
    try {
        const { holderDid } = req.body;
        if (!holderDid) {
            return res.status(400).send({ error: 'holderDid is required' });
        }

        console.log(`\n🔵 VC 발급 요청 받음. Holder DID: ${holderDid}`);

        // 1. VC 페이로드(내용) 생성
        const vcPayload = {
            '@context': [
                'https://www.w3.org/2018/credentials/v1',
                'https://www.w3.org/2018/credentials/examples/v1'
            ],
            type: ['VerifiableCredential', 'UniversityDegreeCredential'],
            issuer: { id: issuerDid }, // 발급자 DID
            issuanceDate: new Date().toISOString(),
            credentialSubject: { // VC의 주체(소유자)에 대한 정보
                id: holderDid, // 소유자 DID
                degree: {
                    type: 'BachelorDegree',
                    name: 'Computer Science'
                }
            },
        };

        // 2. JWS(JWT) 형식으로 VC 생성 및 서명
        // Issuer의 개인키로 서명하여 VC의 무결성과 발급자 신원을 보장합니다.
        const privateKeyJwk = {
            kty: 'OKP',
            crv: 'Ed25519',
            x: Buffer.from(issuerKeys.publicKey).toString('base64url'),
            d: Buffer.from(issuerKeys.secretKey.slice(0, 32)).toString('base64url'),
        };
        const privateKey = await jose.importJWK(privateKeyJwk, 'EdDSA');
        const vcJwt = await new jose.SignJWT(vcPayload)
            .setProtectedHeader({
                alg: 'EdDSA', // 서명 알고리즘
                kid: issuerDidDocument.verificationMethod[0].id // 서명 검증에 사용할 키 ID
            })
            .setIssuer(issuerDid)
            .setSubject(holderDid)
            .setJti(crypto.randomUUID()) // JWT ID
            .sign(privateKey);

        console.log('🟢 발급된 VC (JWT):', vcJwt);
        res.json({ vc: vcJwt });

    } catch (error) {
        console.error('VC 발급 중 오류:', error);
        res.status(500).send({ error: error.message });
    }
});


// --- VP 검증 엔드포인트 ---
app.post('/verify-presentation', async (req, res) => {
    try {
        const { vp } = req.body;
        if (!vp) {
            return res.status(400).send({ error: 'presentation is required' });
        }
        console.log('\n🔵 VP 검증 요청 받음:', vp);

        // --- 1. VP 자체의 서명 검증 (Holder가 서명했는지 확인) ---
        // Holder의 DID(did:key)로부터 공개키를 추출하여 VP를 검증합니다.
        const { payload: vpPayload, protectedHeader: vpHeader } = await jose.jwtVerify(vp, async (header, token) => {
            // 헤더의 kid(Key ID)를 사용하여 키를 식별하는 것이 더 올바른 방법입니다.
            const keyId = header.kid;
            if (!keyId || !keyId.startsWith('did:key:')) {
                throw new Error("Invalid 'kid' in VP header. It must be a did:key.");
            }

            // kid에서 DID 부분만 추출합니다. (예: did:key:z...#z... -> did:key:z...)
            const holderDid = keyId.split('#')[0];
            const identifier = holderDid.split(':')[2];

            // did:key 식별자로부터 공개키를 추출합니다.
            const multicodecPublicKey = bs58.decode(identifier);
            const holderPublicKeyBytes = multicodecPublicKey.slice(2);

            const holderPublicKeyJwk = {
                kty: 'OKP',
                crv: 'Ed25519',
                x: Buffer.from(holderPublicKeyBytes).toString('base64url')
            };
            return jose.importJWK(holderPublicKeyJwk, 'EdDSA');
        });

        console.log('✅ VP 서명 검증 성공. Holder:', vpPayload.iss);

        // --- 2. VP에 포함된 VC의 서명 검증 (Issuer가 서명했는지 확인) ---
        const vcJwt = vpPayload.vp.verifiableCredential[0];
        const { payload: vcPayload, protectedHeader: vcHeader } = await jose.jwtVerify(vcJwt, async (header, token) => {
            // VC의 `kid` 헤더를 보고, Issuer의 DID Document에서 해당 키를 찾습니다.
            // 실제 환경에서는 외부 DID에 대해 DID Resolver를 사용해야 합니다.
            // 여기서는 서버 자신의 DID Document를 직접 참조합니다.
            const issuerPublicKeyJwk = issuerDidDocument.verificationMethod.find(m => m.id === header.kid).publicKeyJwk;
            return jose.importJWK(issuerPublicKeyJwk, 'EdDSA');
        });
        console.log('✅ VC 서명 검증 성공. Issuer:', vcPayload.iss);

        // --- 3. 추가 검증 (예: Holder가 VC의 주체인지) ---
        const isHolder = vcPayload.sub === vpPayload.iss;
        if (!isHolder) {
            throw new Error('Holder is not the subject of the VC');
        }
        console.log('✅ Holder가 VC의 주체임.');

        const verificationResult = { verified: true, vpPayload, vcPayload };
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

// `did:key`로부터 공개키를 추출하기 위한 의존성. 서버 검증 로직에서 사용합니다.
import { base58btc as bs58 } from 'multiformats/bases/base58';
import { Buffer } from 'buffer';
