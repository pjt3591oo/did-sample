# Veramo를 이용한 DID 흐름 구현

이 프로젝트는 Veramo 프레임워크를 사용하여 분산 신원 확인(DID) 및 검증 가능한 자격 증명(VC)의 기본적인 흐름을 보여줍니다.

## 흐름

1.  **Veramo 에이전트 생성**: 필요한 플러그인으로 Veramo 에이전트를 설정합니다.
2.  **DID 생성**: 발급자(issuer)와 보유자(holder)를 위한 `did:web` DID를 생성합니다.
3.  **검증 가능한 자격 증명(VC) 발급**: 발급자가 보유자에게 VC를 발급합니다.
4.  **검증 가능한 프레젠테이션(VP) 생성**: 보유자가 자신의 VC를 사용하여 VP를 생성합니다.
5.  **VP 검증**: 생성된 VP를 검증합니다.

## 설치

프로젝트를 실행하려면 먼저 다음 종속성을 설치해야 합니다.

```bash
npm install
```

## 실행

다음 명령어로 스크립트를 실행할 수 있습니다.

```bash
node index.js
```

## 예상 출력 및 설명

스크립트를 실행하면 발급자 및 보유자 DID, 생성된 VC 및 VP가 콘솔에 출력됩니다. 그러나 최종 검증 결과는 `false`로 표시됩니다.

```
Issuer DID: did:web:issuer
Holder DID: did:web:holder
Credential: { ... }
Presentation: { ... }
Verification result: false
```

검증이 실패하는 이유는 `did:web` 메소드의 특성 때문입니다. `did:web`은 DID 문서를解析하기 위해 공개적으로 접근 가능한 웹 서버에 의존합니다. 이 스크립트는 로컬 환경에서 실행되므로 DID 확인자가 발급자와 보유자의 DID 문서를 찾을 수 없어 서명 검증이 실패합니다.

### 검증을 성공시키는 방법

`did:web` 흐름에서 검증을 성공적으로 완료하려면 다음 단계를 따라야 합니다.

1.  **웹 서버 배포**: 접근 가능한 도메인을 가진 웹 서버를 설정합니다.
2.  **DID 문서 호스팅**:
    *   `did:web:issuer`를 위해 `https://<your-domain>/issuer/.well-known/did.json` 경로에 DID 문서를 호스팅합니다.
    *   `did:web:holder`를 위해 `https://<your-domain>/holder/.well-known/did.json` 경로에 DID 문서를 호스팅합니다.
3.  **스크립트 수정**: `index.js` 파일에서 `didManagerCreate` 함수의 `alias`를 실제 도메인으로 변경해야 합니다.

    ```javascript
    const issuer = await agent.didManagerCreate({ alias: 'your-domain:issuer' });
    const holder = await agent.didManagerCreate({ alias: 'your-domain:holder' });
    ```

또는, `did:key`와 같이 로컬에서 작동하는 다른 DID 메소드를 사용하여 즉시 성공적인 검증을 확인할 수도 있습니다.
