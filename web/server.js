
import express from 'express'
import cors from 'cors'
import { createAgent } from '@veramo/core'
import { DIDManager, MemoryDIDStore } from '@veramo/did-manager'
import { KeyManager, MemoryKeyStore, MemoryPrivateKeyStore } from '@veramo/key-manager'
import { KeyManagementSystem } from '@veramo/kms-local'
import { CredentialPlugin } from '@veramo/credential-w3c'
import { DIDResolverPlugin } from '@veramo/did-resolver'
import { Resolver } from 'did-resolver'
import { getResolver as getDidWebResolver } from 'web-did-resolver'
import { DataStore, Entities } from '@veramo/data-store'
import { WebDIDProvider } from '@veramo/did-provider-web'
import { createConnection } from 'typeorm'

const app = express()
app.use(cors())
app.use(express.json())

let agent;
let issuer;
let didDocument;

app.get('/.well-known/did.json', (req, res) => {
    res.json(didDocument)
})

app.post('/issue-credential', async (req, res) => {
    try {
        if (!didDocument) {
            return res.status(503).send({ error: 'DID document not ready yet' })
        }
        const { holderDid } = req.body
        if (!holderDid) {
            return res.status(400).send({ error: 'holderDid is required' })
        }

        const credential = await agent.createVerifiableCredential({
            credential: {
                issuer: { id: issuer.did },
                credentialSubject: {
                    id: holderDid,
                    claims: {
                        name: 'Alice',
                    }
                },
            },
            proofFormat: 'jwt',
        })
        res.send(credential)
    } catch (error) {
        res.status(500).send({ error: error.message })
    }
})

app.post('/verify-presentation', async (req, res) => {
    try {
        const { presentation } = req.body
        if (!presentation) {
            return res.status(400).send({ error: 'presentation is required' })
        }
        const result = await agent.verifyPresentation({
            presentation,
        })
        res.send(result)
    } catch (error) {
        res.status(500).send({ error: error.message })
    }
})


async function setup() {
    const dbConnection = await createConnection({
        type: 'sqlite',
        database: 'web/server-database.sqlite',
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
                defaultProvider: 'did:web',
                providers: {
                    'did:web': new WebDIDProvider({
                        defaultKms: 'local'
                    })
                }
            }),
            new DIDResolverPlugin({
                resolver: new Resolver({
                    ...getDidWebResolver(),
                }),
            }),
            new CredentialPlugin(),
            new DataStore(dbConnection),
        ],
    })
    issuer = await agent.didManagerCreate({ alias: 'localhost:3000' })
    console.log('Issuer DID:', issuer.did)
    app.listen(3000, () => {
        console.log('Server listening on port 3000')
        setTimeout(async () => {
            didDocument = (await agent.resolveDid({ didUrl: issuer.did })).didDocument
            console.log('DID Document:', JSON.stringify(didDocument, null, 2))
        }, 1000)
    })
}

setup()
