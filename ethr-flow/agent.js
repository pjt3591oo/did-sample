import { ethers } from 'ethers';
import { createVerifiableCredentialJwt, createVerifiablePresentationJwt, verifyPresentation } from 'did-jwt-vc';
import { Resolver } from 'did-resolver';
import { getResolver as getEthrResolver } from 'ethr-did-resolver';

// Network configuration for Sepolia Testnet
const INFURA_PROJECT_ID = ''; // <-- IMPORTANT: Replace with your Infura Project ID
const RPC_URL = `https://sepolia.infura.io/v3/${INFURA_PROJECT_ID}`;
const CHAIN_ID = 11155111;
const ETHR_DID_REGISTRY = '0x03d5003bf0e79C5F5223588F347ebA39AfbC3818';

async function runDidWorkflow() {
    const provider = new ethers.providers.JsonRpcProvider(RPC_URL);
    
    // IMPORTANT: This private key must be funded with Sepolia ETH to pay for gas.
    // You can get Sepolia ETH from a faucet, e.g., https://sepoliafaucet.com/
    const issuerPrivKey = '0x8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63';
    const wallet = new ethers.Wallet(issuerPrivKey, provider);
    
    const issuerAddress = wallet.address;
    console.log(`🔑 Issuer Address: ${issuerAddress}`);
    
    const issuerDid = `did:ethr:sepolia:${issuerAddress}`;
    console.log(`\n🆔 Issuer DID: ${issuerDid}`);

    // --- On-chain DID Registration ---
    console.log(`\nRegistering DID on Sepolia registry (${ETHR_DID_REGISTRY})...`);
    const registryAbi = [{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"identity","type":"address"},{"indexed":false,"internalType":"bytes32","name":"name","type":"bytes32"},{"indexed":false,"internalType":"bytes","name":"value","type":"bytes"},{"indexed":false,"internalType":"uint256","name":"validTo","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"previousChange","type":"uint256"}],"name":"DIDAttributeChanged","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"identity","type":"address"},{"indexed":false,"internalType":"bytes32","name":"delegateType","type":"bytes32"},{"indexed":false,"internalType":"address","name":"delegate","type":"address"},{"indexed":false,"internalType":"uint256","name":"validTo","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"previousChange","type":"uint256"}],"name":"DIDDelegateChanged","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"identity","type":"address"},{"indexed":false,"internalType":"address","name":"owner","type":"address"},{"indexed":false,"internalType":"uint256","name":"previousChange","type":"uint256"}],"name":"DIDOwnerChanged","type":"event"},{"inputs":[{"internalType":"address","name":"identity","type":"address"},{"internalType":"bytes32","name":"delegateType","type":"bytes32"},{"internalType":"address","name":"delegate","type":"address"},{"internalType":"uint256","name":"validity","type":"uint256"}],"name":"addDelegate","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"identity","type":"address"},{"internalType":"uint8","name":"sigV","type":"uint8"},{"internalType":"bytes32","name":"sigR","type":"bytes32"},{"internalType":"bytes32","name":"sigS","type":"bytes32"},{"internalType":"bytes32","name":"delegateType","type":"bytes32"},{"internalType":"address","name":"delegate","type":"address"},{"internalType":"uint256","name":"validity","type":"uint256"}],"name":"addDelegateSigned","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"identity","type":"address"},{"internalType":"address","name":"newOwner","type":"address"}],"name":"changeOwner","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"identity","type":"address"},{"internalType":"uint8","name":"sigV","type":"uint8"},{"internalType":"bytes32","name":"sigR","type":"bytes32"},{"internalType":"bytes32","name":"sigS","type":"bytes32"},{"internalType":"address","name":"newOwner","type":"address"}],"name":"changeOwnerSigned","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"changed","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"},{"internalType":"bytes32","name":"","type":"bytes32"},{"internalType":"address","name":"","type":"address"}],"name":"delegates","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"identity","type":"address"}],"name":"identityOwner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"nonce","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"owners","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"identity","type":"address"},{"internalType":"bytes32","name":"name","type":"bytes32"},{"internalType":"bytes","name":"value","type":"bytes"}],"name":"revokeAttribute","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"identity","type":"address"},{"internalType":"uint8","name":"sigV","type":"uint8"},{"internalType":"bytes32","name":"sigR","type":"bytes32"},{"internalType":"bytes32","name":"sigS","type":"bytes32"},{"internalType":"bytes32","name":"name","type":"bytes32"},{"internalType":"bytes","name":"value","type":"bytes"}],"name":"revokeAttributeSigned","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"identity","type":"address"},{"internalType":"bytes32","name":"delegateType","type":"bytes32"},{"internalType":"address","name":"delegate","type":"address"}],"name":"revokeDelegate","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"identity","type":"address"},{"internalType":"uint8","name":"sigV","type":"uint8"},{"internalType":"bytes32","name":"sigR","type":"bytes32"},{"internalType":"bytes32","name":"sigS","type":"bytes32"},{"internalType":"bytes32","name":"delegateType","type":"bytes32"},{"internalType":"address","name":"delegate","type":"address"}],"name":"revokeDelegateSigned","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"identity","type":"address"},{"internalType":"bytes32","name":"name","type":"bytes32"},{"internalType":"bytes","name":"value","type":"bytes"},{"internalType":"uint256","name":"validity","type":"uint256"}],"name":"setAttribute","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"identity","type":"address"},{"internalType":"uint8","name":"sigV","type":"uint8"},{"internalType":"bytes32","name":"sigR","type":"bytes32"},{"internalType":"bytes32","name":"sigS","type":"bytes32"},{"internalType":"bytes32","name":"name","type":"bytes32"},{"internalType":"bytes","name":"value","type":"bytes"},{"internalType":"uint256","name":"validity","type":"uint256"}],"name":"setAttributeSigned","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"identity","type":"address"},{"internalType":"bytes32","name":"delegateType","type":"bytes32"},{"internalType":"address","name":"delegate","type":"address"}],"name":"validDelegate","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"}]
    const registryContract = new ethers.Contract(ETHR_DID_REGISTRY, registryAbi, wallet);

    try {
        console.log("Checking current owner...");
        const currentOwner = await registryContract.identityOwner(issuerAddress);
        if (currentOwner.toLowerCase() === issuerAddress.toLowerCase()) {
            console.log("DID is already registered to this address. Skipping registration.");
        } else {
            console.log("DID not registered or owned by another address. Attempting to claim ownership...");
            const tx = await registryContract.changeOwner(issuerAddress, issuerAddress);
            console.log(`Transaction sent: ${tx.hash}`);
            await tx.wait();
            console.log(`✅ DID registered successfully!`);
        }
    } catch (e) {
        console.error("❌ DID registration failed:", e.message);
        console.log("Please ensure the account is funded with Sepolia ETH and the Infura Project ID is correct.");
        throw e;
    }
    // --- End of On-chain DID Registration ---

    console.log("\n📜 Step 1: Creating Verifiable Credential...");
    
    const vcPayload = {
        sub: 'did:ethr:sepolia:0x1234567890123456789012345678901234567890', // Example Holder DID
        nbf: Math.floor(Date.now() / 1000),
        vc: {
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            type: ['VerifiableCredential', 'TestCredential'],
            credentialSubject: {
                id: 'did:ethr:sepolia:0x1234567890123456789012345678901234567890',
                message: 'This is a test credential for the Sepolia network.'
            }
        }
    };

    const issuer = {
        did: issuerDid,
        signer: async (data) => {
            const hash = ethers.utils.sha256(ethers.utils.toUtf8Bytes(data));
            const signature = wallet._signingKey().signDigest(hash);
            const { r, s, v } = signature;
            const recoveryId = v - 27;
            const rBuffer = Buffer.from(r.slice(2), 'hex');
            const sBuffer = Buffer.from(s.slice(2), 'hex');
            const vBuffer = Buffer.from([recoveryId]);
            const rawSignature = Buffer.concat([rBuffer, sBuffer, vBuffer]);
            return rawSignature.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        },
        alg: 'ES256K-R'
    };

    try {
        const vcJwt = await createVerifiableCredentialJwt(vcPayload, issuer);
        console.log("✅ VC Created Successfully");

        console.log("\n🎁 Step 2: Creating Verifiable Presentation...");
        
        const vpPayload = {
            vp: {
                '@context': ['https://www.w3.org/2018/credentials/v1'],
                type: ['VerifiablePresentation'],
                verifiableCredential: [vcJwt]
            }
        };

        const vpJwt = await createVerifiablePresentationJwt(vpPayload, issuer);
        console.log("✅ VP Created Successfully");

        console.log("\n🔍 Step 3: Verifying Presentation...");
        
        const resolver = new Resolver(
            getEthrResolver({
                networks: [
                    {
                        name: "sepolia",
                        rpcUrl: RPC_URL,
                        registry: ETHR_DID_REGISTRY
                    }
                ]
            })
        );

        const verifiedVP = await verifyPresentation(vpJwt, resolver);
        
        console.log("✅ VP Verification Successful!");
        console.log("\n📋 Verified Credential Data:");
        console.log(JSON.stringify({
            issuer: verifiedVP.issuer,
            credentialType: vcPayload.vc.type,
            credentialSubject: vcPayload.vc.credentialSubject
        }, null, 2));

    } catch (error) {
        console.error("\n❌ Error in DID workflow:", error.message);
        throw error;
    }
}

runDidWorkflow().catch((error) => {
    console.error("\n❌ Workflow failed.");
    process.exit(1);
});