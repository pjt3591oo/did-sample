
import { createAgent } from '@veramo/core'
import { DIDManager, MemoryDIDStore } from '@veramo/did-manager'
import { KeyManager, MemoryKeyStore, MemoryPrivateKeyStore } from '@veramo/key-manager'
import { KeyManagementSystem } from '@veramo/kms-local'
import { CredentialPlugin } from '@veramo/credential-w3c'
import { DIDResolverPlugin } from '@veramo/did-resolver'
import { Resolver } from 'did-resolver'
import { getResolver as webDidResolver } from 'web-did-resolver'
import { DataStore, Entities } from '@veramo/data-store'
import { WebDIDProvider } from '@veramo/did-provider-web'
import { createConnection } from 'typeorm'

const dbConnection = createConnection({
    type: 'sqlite',
    database: 'database.sqlite',
    synchronize: true,
    logging: ['error', 'info', 'warn'],
    entities: Entities,
})

const agent = createAgent({
    plugins: [
        new KeyManager({
            store: new MemoryKeyStore(),
            kms: {
                local: new KeyManagementSystem(new MemoryPrivateKeyStore()),
            },
        }),
        new DIDManager({
            store: new MemoryDIDStore(),
            defaultProvider: 'did:web',
            providers: {
                'did:web': new WebDIDProvider({
                    defaultKms: 'local'
                })
            }
        }),
        new DIDResolverPlugin({
            resolver: new Resolver({
                ...webDidResolver(),
            }),
        }),
        new CredentialPlugin(),
        new DataStore(dbConnection),
    ],
})

async function main() {
    const issuer = await agent.didManagerCreate({ alias: 'issuer' })
    const holder = await agent.didManagerCreate({ alias: 'holder' })

    console.log('Issuer DID:', issuer.did)
    console.log('Holder DID:', holder.did)

    const credential = await agent.createVerifiableCredential({
        credential: {
            issuer: { id: issuer.did },
            credentialSubject: {
                id: holder.did,
                claims: {
                    name: 'Alice',
                }
            },
        },
        proofFormat: 'jwt',
    })

    console.log('Credential:', JSON.stringify(credential, null, 2))

    const presentation = await agent.createVerifiablePresentation({
        presentation: {
            holder: holder.did,
            verifiableCredential: [credential],
        },
        proofFormat: 'jwt',
    })

    console.log('Presentation:', JSON.stringify(presentation, null, 2))

    const result = await agent.verifyPresentation({
        presentation,
    })

    console.log('Verification result:', result.verified)
}

main().catch(console.error)
