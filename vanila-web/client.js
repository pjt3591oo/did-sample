
import axios from 'axios';
import * as jose from 'jose';
import nacl from 'tweetnacl';
import { base58btc as bs58 } from 'multiformats/bases/base58';
import { Buffer } from 'buffer';

// --- API 클라이언트 설정 ---
const api = axios.create({
    baseURL: 'http://localhost:4000',
});

// --- Holder 설정 ---
let holderKeys;
let holderDid;

// --- Holder의 키 쌍과 did:key DID 생성 ---
async function setupHolder() {
    // 1. Ed25519 키 쌍 생성
    holderKeys = nacl.sign.keyPair();

    // 2. did:key DID 생성
    // `did:key`는 공개키 정보를 DID 자체에 포함하는 방식입니다.
    // Ed25519 공개키(32바이트)에 멀티코덱 프리픽스(0xed01)를 붙인 후, Base58-btc로 인코딩합니다.
    const multicodecPublicKey = new Uint8Array(2 + holderKeys.publicKey.length);
    multicodecPublicKey.set([0xed, 0x01]); // Ed25519 public key multicodec prefix
    multicodecPublicKey.set(holderKeys.publicKey, 2);
    const didKeyIdentifier = bs58.encode(multicodecPublicKey); // z... 로 시작하는 식별자
    holderDid = `did:key:${didKeyIdentifier}`;

    console.log('✅ Holder setup complete');
    console.log('Holder DID:', holderDid);
}


// --- 전체 DID 흐름 실행 ---
async function main() {
    // 1. Holder 초기화 (DID 생성)
    await setupHolder();
    console.log(`\n(1/4)  credential 발급을 요청합니다...`);

    // 2. Issuer에게 VC 발급 요청
    // 자신의 DID를 body에 담아 서버의 `/issue-credential` 엔드포인트로 보냅니다.
    const issueResponse = await api.post('/issue-credential', {
        holderDid: holderDid,
    });
    const vcJwt = issueResponse.data.vc;
    console.log('✅ (1/4) VC를 성공적으로 발급받았습니다.');
    console.log('VC (JWT):', vcJwt);


    // 3. 발급받은 VC를 담아 VP 생성
    console.log(`\n(2/4) VP를 생성합니다...`);
    // VP는 VC의 소유권을 증명하기 위한 표현물입니다.
    // Holder는 자신의 개인키로 VP 전체를 서명합니다.
    const vpPayload = {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiablePresentation'],
        // VP에 포함시키는 VC (하나 또는 여러 개가 될 수 있음)
        verifiableCredential: [vcJwt],
    };

    const privateKeyJwk = {
        kty: 'OKP',
        crv: 'Ed25519',
        x: Buffer.from(holderKeys.publicKey).toString('base64url'),
        d: Buffer.from(holderKeys.secretKey.slice(0, 32)).toString('base64url'),
    };
    const privateKey = await jose.importJWK(privateKeyJwk, 'EdDSA');
    const vpJwt = await new jose.SignJWT({ vp: vpPayload })
        .setProtectedHeader({
            alg: 'EdDSA',
            // did:key에서 key id는 DID 자신과 동일합니다.
            kid: `${holderDid}#${holderDid.split(':')[2]}`
        })
        .setIssuer(holderDid) // VP의 발급자는 Holder 자신
        .setAudience('verifier-did') // VP를 받을 대상(검증자)
        .setJti(crypto.randomUUID())
        .sign(privateKey);

    console.log('✅ (2/4) VP를 성공적으로 생성했습니다.');
    console.log('VP (JWT):', vpJwt);


    // 4. 생성한 VP를 검증자(서버)에게 제출
    console.log(`\n(3/4) 생성된 VP의 검증을 요청합니다...`);
    const verifyResponse = await api.post('/verify-presentation', {
        vp: vpJwt,
    });
    const verificationResult = verifyResponse.data;
    console.log('✅ (3/4) VP 검증 결과를 받았습니다.');


    // 5. 최종 검증 결과 출력
    console.log(`\n(4/4) 최종 검증 결과:`);
    console.log(JSON.stringify(verificationResult, null, 2));

    if (verificationResult.verified) {
        console.log("\n🎉 모든 검증 과정을 통과했습니다!");
    } else {
        console.log("\n❌ 검증에 실패했습니다.");
    }
}

main().catch(async (error) => {
    if (error.response) {
        console.error(`\n❌ [${error.response.status}] 서버 오류:`, error.response.data);
    } else if (error.request) {
        console.error('\n❌ 서버에 연결할 수 없습니다. 서버가 실행 중인지 확인하세요. (node vanila-web/server.js)');
    } else {
        console.error('\n❌ 예기치 않은 오류 발생:', error.message);
    }
});
