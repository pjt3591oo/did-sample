
import axios from 'axios';
import { createVerifiablePresentationJwt } from 'did-jwt-vc';
// 수동 검증을 위해 jose의 여러 함수들을 직접 임포트합니다.
import { generateKeyPair, jwtVerify, decodeProtectedHeader, importJWK, decodeJwt } from 'jose';
import { base58btc } from 'multiformats/bases/base58';

// did-resolver 관련 라이브러리는 더 이상 필요 없으므로 제거합니다.

const api = axios.create({
    baseURL: 'http://localhost:4000',
});

async function main() {
    // ==================================================
    // 1. Holder 역할: VC를 받고 VP를 생성하는 부분 (이전과 동일)
    // ==================================================
    console.log("---  Holder 역할 시작 ---");
    const { publicKey, privateKey } = await generateKeyPair('Ed25519');
    const rawPublicKey = new Uint8Array(await crypto.subtle.exportKey('raw', publicKey));
    const multicodecPublicKey = new Uint8Array(2 + rawPublicKey.length);
    multicodecPublicKey.set([0xed, 0x01]);
    multicodecPublicKey.set(rawPublicKey, 2);
    const did = `did:key:${base58btc.encode(multicodecPublicKey)}`;
    const signer = async (data) => {
        const dataBuffer = typeof data === 'string' ? new TextEncoder().encode(data) : data;
        const signatureBytes = await crypto.subtle.sign('Ed25519', privateKey, dataBuffer);
        return Buffer.from(signatureBytes).toString('base64url');
    };
    // 이전 수정사항: kid를 추가했지만, 라이브러리가 VP 생성 시 이를 사용하지 않는 것으로 보여 다른 접근 방식을 취합니다.
    const holder = { 
        did, 
        signer, 
        alg: 'EdDSA',
        kid: `${did}#${did.split(':')[2]}`
    };
    console.log('Holder DID 생성:', holder.did);

    console.log('\n서버에 VC를 요청합니다...');
    const issueResponse = await api.post('/issue-credential', { holderDid: holder.did });
    const vcJwt = issueResponse.data.vc;
    console.log('VC를 성공적으로 받았습니다.');

    const vpPayload = { vp: { '@context': ['https://www.w3.org/2018/credentials/v1'], type: ['VerifiablePresentation'], verifiableCredential: [vcJwt] } };
    const vpJwt = await createVerifiablePresentationJwt(vpPayload, holder);
    console.log('VP를 성공적으로 생성했습니다.');
    console.log("--- Holder 역할 종료 ---");


    // ==================================================
    // 2. Verifier 역할: VP를 수동으로 검증 (직접 호출 방식, 수정됨)
    // ==================================================
    console.log("\n--- 외부 Verifier 역할 시작 (직접 호출 방식) ---");

    try {
        // --- 2.1. VP 자체의 서명 검증 (Holder 서명 검증) ---
        console.log("\n1단계: VP 서명을 검증합니다 (Holder의 did:key 이용)...");
        
        // 헤더의 kid 대신, 페이로드의 'iss' 클레임을 사용하여 Holder를 식별합니다.
        const unverifiedVpPayload = decodeJwt(vpJwt);
        const holderDidFromVp = unverifiedVpPayload.iss;

        if (!holderDidFromVp || !holderDidFromVp.startsWith('did:key:')) {
            throw new Error("VP JWT must have an 'iss' claim with a valid did:key.");
        }
        
        // did:key로부터 공개키 추출
        const multicodecFromDid = base58btc.decode(holderDidFromVp.split(':')[2]);
        const holderPublicKeyBytes = multicodecFromDid.slice(2);
        const holderPublicKeyJwk = { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(holderPublicKeyBytes).toString('base64url') };
        const holderPublicKey = await importJWK(holderPublicKeyJwk, 'EdDSA');

        // 이제 DID로부터 생성한 공개키로 VP 서명을 검증합니다.
        const { payload: verifiedVpPayload } = await jwtVerify(vpJwt, holderPublicKey);
        console.log("✅ VP 서명 검증 성공!");

        // --- 2.2. VP에서 VC를 추출하고 Issuer 정보 확인 ---
        const vcJwtFromVp = verifiedVpPayload.vp.verifiableCredential[0];
        const vcHeader = decodeProtectedHeader(vcJwtFromVp); // 'kid'를 얻기 위해 헤더를 디코딩합니다.
        const unverifiedVcPayload = decodeJwt(vcJwtFromVp);   // 'iss'를 얻기 위해 페이로드를 디코딩합니다.
        const issuerDid = unverifiedVcPayload.iss;            // 'iss'는 페이로드에 있습니다.
        console.log(`\n2단계: VP에서 VC를 추출했습니다. VC 발급자: ${issuerDid}`);

        if (!issuerDid || !issuerDid.startsWith('did:web')) {
            throw new Error('VC issuer is not using did:web. Cannot proceed with this verifier.');
        }

        // --- 2.3. Issuer의 DID Document를 직접 HTTP로 호출 ---
        const didWebServer = issuerDid.replace('did:web:', '');
        const didDocUrl = `http://${didWebServer}/.well-known/did.json`;
        console.log(`3단계: Issuer의 DID Document를 가져옵니다. URL: ${didDocUrl}`);
        
        const didDocResponse = await axios.get(didDocUrl);
        const issuerDidDocument = didDocResponse.data;
        console.log("✅ DID Document를 성공적으로 가져왔습니다!");

        // --- 2.4. DID Document에서 공개키를 찾아 VC 서명 검증 ---
        console.log("4단계: DID Document에서 올바른 키를 찾아 VC 서명을 검증합니다...");
        const verificationMethod = issuerDidDocument.verificationMethod.find(m => m.id === vcHeader.kid);
        if (!verificationMethod) {
            throw new Error(`Key ID ${vcHeader.kid} not found in DID Document.`);
        }
        const issuerPublicKey = await importJWK(verificationMethod.publicKeyJwk, 'EdDSA');
        
        // VC 서명 검증
        await jwtVerify(vcJwtFromVp, issuerPublicKey);
        console.log("✅ VC 서명 검증 성공!");

        console.log("\n🎉 최종 결론: 모든 검증 과정을 수동으로 통과했습니다!");

    } catch (error) {
        console.error("\n❌ 검증 실패:", error.message);
    }
    console.log("--- 외부 Verifier 역할 종료 ---");
}

main().catch(async (error) => {
    if (error.response) {
        console.error(`\n❌ [${error.response.status}] 서버 오류:`, error.response.data);
    } else if (error.request) {
        console.error('\n❌ 서버에 연결할 수 없습니다. `node vanila-web/server.js`를 먼저 실행했는지 확인하세요.');
    } else {
        console.error('\n❌ 예기치 않은 오류 발생:', error.message);
    }
});
