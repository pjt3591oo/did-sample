
import axios from 'axios'
import { createAgent } from '@veramo/core'
import { DIDManager, MemoryDIDStore } from '@veramo/did-manager'
import { KeyManager, MemoryKeyStore, MemoryPrivateKeyStore } from '@veramo/key-manager'
import { KeyManagementSystem } from '@veramo/kms-local'
import { CredentialPlugin } from '@veramo/credential-w3c'
import { DIDResolverPlugin } from '@veramo/did-resolver'
import { Resolver } from 'did-resolver'
import { getResolver as getDidKeyResolver } from 'key-did-resolver'
import { DataStore, Entities } from '@veramo/data-store'
import { KeyDIDProvider } from '@veramo/did-provider-key'
import { createConnection } from 'typeorm'

let agent;

async function main() {
    const dbConnection = await createConnection({
        type: 'sqlite',
        database: 'client-database.sqlite',
        synchronize: true,
        logging: ['error', 'info', 'warn'],
        entities: Entities,
    })

    agent = createAgent({
        plugins: [
            new KeyManager({
                store: new MemoryKeyStore(),
                kms: {
                    local: new KeyManagementSystem(new MemoryPrivateKeyStore()),
                },
            }),
            new DIDManager({
                store: new MemoryDIDStore(),
                defaultProvider: 'did:key',
                providers: {
                    'did:key': new KeyDIDProvider({
                        defaultKms: 'local'
                    })
                }
            }),
            new DIDResolverPlugin({
                resolver: new Resolver({
                    ...getDidKeyResolver(),
                }),
            }),
            new CredentialPlugin(),
            new DataStore(dbConnection),
        ],
    })
    await new Promise(resolve => setTimeout(resolve, 1000));
    const holder = await agent.didManagerCreate()
    console.log('Holder DID:', holder.did)

    console.log('Requesting credential from server...')
    const response = await axios.post('http://localhost:3000/issue-credential', {
        holderDid: holder.did,
    })
    const credential = response.data
    console.log('Credential received:', JSON.stringify(credential, null, 2))

    const presentation = await agent.createVerifiablePresentation({
        presentation: {
            holder: holder.did,
            verifiableCredential: [credential],
        },
        proofFormat: 'jwt',
    })
    console.log('Presentation created:', JSON.stringify(presentation, null, 2))

    console.log('Verifying presentation with server...')
    const verificationResponse = await axios.post('http://localhost:3000/verify-presentation', {
        presentation,
    })
    const verificationResult = verificationResponse.data
    console.log('Verification result:', verificationResult)
}

main().catch(console.error)
