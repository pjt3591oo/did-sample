
import axios from 'axios';
// 필요한 고수준 라이브러리들을 임포트합니다.
import { createVerifiablePresentationJwt } from 'did-jwt-vc';
import { generateKeyPair } from 'jose';
import { base58btc } from 'multiformats/bases/base58';

const api = axios.create({
    baseURL: 'http://localhost:4000',
});

// --- Holder 설정 ---
let holder;

// --- Holder의 키 쌍과 did:key DID 생성 (리팩터링) ---
async function setupHolder() {
    // 1. 키 생성 방식을 'jose.generateKeyPair'로 변경
    const { publicKey, privateKey } = await generateKeyPair('Ed25519');
    
    // 2. did:key DID 생성 로직을 Web Crypto API 키에 맞게 수정
    const rawPublicKey = new Uint8Array(await crypto.subtle.exportKey('raw', publicKey));
    const multicodecPublicKey = new Uint8Array(2 + rawPublicKey.length);
    multicodecPublicKey.set([0xed, 0x01]); // Ed25519 public key multicodec prefix
    multicodecPublicKey.set(rawPublicKey, 2);
    const did = `did:key:${base58btc.encode(multicodecPublicKey)}`;

    // 3. did-jwt-vc 라이브러리에서 사용할 Signer 객체 생성
    const signer = async (data) => {
        const dataBuffer = typeof data === 'string' ? new TextEncoder().encode(data) : data;
        const signatureBytes = await crypto.subtle.sign('Ed25519', privateKey, dataBuffer);
        return Buffer.from(signatureBytes).toString('base64url');
    };
    holder = { did, signer, alg: 'EdDSA' };

    console.log('✅ Holder setup complete (using did-jwt-vc style)');
    console.log('Holder DID:', holder.did);
}


// --- 전체 DID 흐름 실행 (리팩터링) ---
async function main() {
    await setupHolder();
    console.log(`\n(1/4) credential 발급을 요청합니다...`);

    // 1. Issuer에게 VC 발급 요청
    const issueResponse = await api.post('/issue-credential', {
        holderDid: holder.did,
    });
    const vcJwt = issueResponse.data.vc;
    console.log('✅ (1/4) VC를 성공적으로 발급받았습니다.');
    console.log('VC (JWT):', vcJwt);


    // 2. 발급받은 VC를 담아 VP 생성
    console.log(`\n(2/4) VP를 생성합니다...`);
    const vpPayload = {
        vp: {
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            type: ['VerifiablePresentation'],
            verifiableCredential: [vcJwt],
        },
    };
    
    // 수동 JWT 서명 대신 'createVerifiablePresentationJwt' 함수를 사용합니다.
    const vpJwt = await createVerifiablePresentationJwt(vpPayload, holder);

    console.log('✅ (2/4) VP를 성공적으로 생성했습니다.');
    console.log('VP (JWT):', vpJwt);


    // 3. 생성한 VP를 검증자(서버)에게 제출
    console.log(`\n(3/4) 생성된 VP의 검증을 요청합니다...`);
    const verifyResponse = await api.post('/verify-presentation', {
        vp: vpJwt,
    });
    const verificationResult = verifyResponse.data;
    console.log('✅ (3/4) VP 검증 결과를 받았습니다.');


    // 4. 최종 검증 결과 출력
    console.log(`\n(4/4) 최종 검증 결과:`);
    console.log(JSON.stringify(verificationResult, null, 2));

    if (verificationResult.verified) {
        console.log("\n🎉 모든 검증 과정을 통과했습니다!");
    } else {
        console.log("\n❌ 검증에 실패했습니다.", verificationResult.error || '');
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
