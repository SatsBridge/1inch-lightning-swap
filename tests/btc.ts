// Universal Miniscript Wallet Module
// Supports both Escrow and Transit wallets for partial fills

import * as secp256k1 from '@bitcoinerlab/secp256k1'
import * as descriptors from '@bitcoinerlab/descriptors'
import {compilePolicy} from '@bitcoinerlab/miniscript'
import {Psbt, networks} from 'bitcoinjs-lib'
import {readFileSync, writeFileSync} from 'fs'
import * as crypto from 'crypto'

const {Output, BIP32, ECPair} = descriptors.DescriptorsFactory(secp256k1)

export class MiniscriptWallet {
    constructor(config = {}) {
        this.network = config.network || networks.testnet
        this.explorer = config.explorer || 'https://blockstream.info/testnet'
        this.blocks = config.blocks || 2
        this.isWeb = typeof window !== 'undefined'

        // Initialize key storage
        this.keys = new Map()
        this.descriptors = new Map()
        this.outputs = new Map()
    }

    /**
     * Initialize or load a key pair
     */
    initializeKey(keyName, wifString = null) {
        if (wifString) {
            // Use provided WIF
            this.keys.set(keyName, ECPair.fromWIF(wifString))
        } else if (this.isWeb) {
            // Web storage
            const stored = localStorage.getItem(`miniscript_${keyName}`)
            if (stored) {
                this.keys.set(keyName, ECPair.fromWIF(stored))
            } else {
                const newKey = ECPair.makeRandom()
                this.keys.set(keyName, newKey)
                localStorage.setItem(`miniscript_${keyName}`, newKey.toWIF())
            }
        } else {
            // File storage
            try {
                const wif = readFileSync(`.${keyName}WIF`, 'utf8')
                this.keys.set(keyName, ECPair.fromWIF(wif))
            } catch {
                const newKey = ECPair.makeRandom()
                this.keys.set(keyName, newKey)
                writeFileSync(`.${keyName}WIF`, newKey.toWIF())
            }
        }

        return this.keys.get(keyName)
    }

    /**
     * Get a key pair by name
     */
    getKey(keyName) {
        return this.keys.get(keyName)
    }

    /**
     * Create an escrow wallet with multiple spending paths
     */
    createEscrowWallet(config) {
        const {
            hashLock100,
            hashLockPartial25,
            hashLockPartial50,
            redeemKey = 'redeem',
            refundKey = 'refund',
            transitKey1 = 'transit1',
            transitKey2 = 'transit2'
        } = config

        // Initialize all required keys
        this.initializeKey(redeemKey)
        this.initializeKey(refundKey)
        this.initializeKey(transitKey1)
        this.initializeKey(transitKey2)

        const policy = this.buildEscrowPolicy(hashLock100, this.blocks, hashLockPartial25, hashLockPartial50)

        const descriptor = this.createDescriptor(policy, {
            '@redeemKey': this.getKey(redeemKey).publicKey.toString('hex'),
            '@refundKey': this.getKey(refundKey).publicKey.toString('hex'),
            '@transitKey1': this.getKey(transitKey1).publicKey.toString('hex'),
            '@transitKey2': this.getKey(transitKey2).publicKey.toString('hex')
        })

        const walletId = `escrow_${Date.now()}`
        this.descriptors.set(walletId, descriptor)

        const output = new Output({
            descriptor,
            network: this.network
        })

        this.outputs.set(walletId, output)

        return {
            id: walletId,
            address: output.getAddress(),
            descriptor,
            policy,
            keys: {
                redeemKey: this.getKey(redeemKey),
                refundKey: this.getKey(refundKey),
                transitKey1: this.getKey(transitKey1),
                transitKey2: this.getKey(transitKey2)
            }
        }
    }

    /**
     * Create a transit wallet for partial fills
     */
    createTransitWallet(config) {
        const {instantKey = 'instant', timeLock = 1} = config

        // Initialize instant key
        this.initializeKey(instantKey)

        const policy = this.buildTransitPolicy(timeLock)

        const descriptor = this.createDescriptor(policy, {
            '@instantKey': this.getKey(instantKey).publicKey.toString('hex')
        })

        const walletId = `transit_${Date.now()}`
        this.descriptors.set(walletId, descriptor)

        const output = new Output({
            descriptor,
            network: this.network
        })

        this.outputs.set(walletId, output)

        return {
            id: walletId,
            address: output.getAddress(),
            descriptor,
            policy,
            keys: {
                instantKey: this.getKey(instantKey)
            }
        }
    }

    /**
     * Build escrow policy with multiple spending paths
     */
    buildEscrowPolicy(hashLock100, timeLock, hashLockPartial25, hashLockPartial50) {
        return (
            `thresh(1, ` +
            `and(sha256(${hashLock100}),pk(@redeemKey)),` +
            `and(after(${timeLock}),pk(@refundKey)),` +
            `and(sha256(${hashLockPartial50}),pk(@transitKey1)),` +
            `and(sha256(${hashLockPartial25}),pk(@transitKey2))` +
            `)`
        )
    }

    /**
     * Build transit policy for instant spending
     */
    buildTransitPolicy(timeLock) {
        return `pk(@instantKey)`
    }

    /**
     * Create descriptor from policy and key replacements
     */
    createDescriptor(policy, keyReplacements) {
        const {miniscript, issane} = compilePolicy(policy)
        if (!issane) {
            throw new Error('Policy is not sane')
        }

        let descriptor = `wsh(${miniscript})`

        // Replace key placeholders
        Object.entries(keyReplacements).forEach(([placeholder, pubkey]) => {
            descriptor = descriptor.replace(new RegExp(placeholder, 'g'), pubkey)
        })

        return descriptor
    }

    /**
     * Spend from escrow using specific path
     */
    async spendFromEscrow(config) {
        const {walletId, utxos, outputs, spendingPath, preimage, hashLock, signingKey} = config

        const output = this.outputs.get(walletId)
        if (!output) {
            throw new Error(`Wallet ${walletId} not found`)
        }

        const psbt = new Psbt({network: this.network})

        // Add inputs
        for (const utxo of utxos) {
            const txHex = await this.getTransactionHex(utxo.txid)

            const outputConfig = {
                descriptor: this.descriptors.get(walletId),
                network: this.network,
                signersPubKeys: [signingKey.publicKey]
            }

            // Add preimage if spending hash-locked path
            if (preimage && hashLock) {
                outputConfig.preimages = [
                    {
                        digest: `sha256(${hashLock})`,
                        preimage: preimage
                    }
                ]
            }

            const spendOutput = new Output(outputConfig)

            const inputFinalizer = spendOutput.updatePsbtAsInput({
                psbt,
                txHex,
                vout: utxo.vout
            })

            // Store finalizer for later use
            utxo._finalizer = inputFinalizer
        }

        // Add outputs
        outputs.forEach((output) => {
            new Output({
                descriptor: `addr(${output.address})`,
                network: this.network
            }).updatePsbtAsOutput({
                psbt,
                value: output.value
            })
        })

        // Sign transaction
        descriptors.signers.signECPair({psbt, ecpair: signingKey})

        // Finalize inputs
        utxos.forEach((utxo, index) => {
            if (utxo._finalizer) {
                utxo._finalizer({psbt})
            }
        })

        return psbt.extractTransaction()
    }

    /**
     * Spend from transit wallet
     */
    async spendFromTransit(config) {
        const {walletId, utxos, outputs, signingKey, preimage, hashLock} = config

        return this.spendFromEscrow({
            walletId,
            utxos,
            outputs,
            spendingPath: 'instant',
            signingKey,
            preimage,
            hashLock
        })
    }

    /**
     * Check balance for any wallet address
     */
    async checkBalance(address) {
        console.log(`Checking balance for address: ${address}`)
        const response = await fetch(`${this.explorer}/api/address/${address}/utxo`)
        const utxo = await response.json()

        const hasFunds = utxo && utxo.length > 0

        if (hasFunds) {
            console.log(`Successfully funded with ${utxo.length} UTXO(s)`)
        } else {
            console.log(`Not yet funded!`)
            //throw new Error(`Add funds to ${address}`, 500);
        }

        const totalValue = utxo.reduce((sum: number, utxoItem: any) => sum + utxoItem.value, 0)

        return {utxo, totalValue}
    }

    /**
     * Broadcast transaction
     */
    async broadcastTransaction(txHex) {
        console.log(`Broadcasting transaction: ${txHex}`)

        const response = await fetch(`${this.explorer}/api/tx`, {
            method: 'POST',
            body: txHex
        })

        const result = await response.text()
        console.log(`Broadcast result: ${result}`)

        if (result.match('non-BIP68-final') || result.match('non-final')) {
            return {
                success: false,
                error: 'Transaction is time-locked. Wait for more blocks to be mined.'
            }
        } else if (result.length === 64) {
            return {success: true, txId: result}
        } else {
            return {success: false, error: result}
        }
    }

    /**
     * Get transaction hex from explorer
     */
    async getTransactionHex(txid) {
        const response = await fetch(`${this.explorer}/api/tx/${txid}/hex`)
        return response.text()
    }

    /**
     * Generate hash and preimage pair
     */
    generateHashLock() {
        const preimage = crypto.randomBytes(32).toString('hex')
        const hash = crypto.createHash('sha256').update(Buffer.from(preimage, 'hex')).digest('hex')
        return {hash, preimage}
    }

    /**
     * Validate preimage against hash
     */
    validatePreimage(preimage, expectedHash) {
        const actualHash = crypto.createHash('sha256').update(Buffer.from(preimage, 'hex')).digest('hex')
        return actualHash === expectedHash
    }
}

// Specialized Escrow Wallet
export class EscrowWallet extends MiniscriptWallet {
    constructor(config = {}) {
        super(config)
        this.escrowWallet = null
    }

    /**
     * Initialize escrow with hash locks
     */
    async initialize(hashLocks) {
        const {hashLock100, hashLockPartial25, hashLockPartial50} = hashLocks

        this.escrowWallet = this.createEscrowWallet({
            hashLock100,
            hashLockPartial25,
            hashLockPartial50
        })

        console.log(`Escrow wallet created: ${this.escrowWallet.address}`)
        console.log(`Descriptor: ${this.escrowWallet.descriptor}`)

        return this.escrowWallet
    }

    /**
     * Spend full amount (100%)
     */
    async spendFull(utxos, outputs, preimage, hashLock) {
        if (!this.escrowWallet) throw new Error('Escrow wallet not initialized')

        const tx = await this.spendFromEscrow({
            walletId: this.escrowWallet.id,
            utxos,
            outputs,
            spendingPath: 'full',
            preimage,
            hashLock,
            signingKey: this.escrowWallet.keys.redeemKey
        })

        return this.broadcastTransaction(tx.toHex())
    }

    /**
     * Spend partial amount (50% or 25%)
     */
    async spendPartial(utxos, outputs, percentage, preimage, hashLock) {
        if (!this.escrowWallet) throw new Error('Escrow wallet not initialized')

        const signingKey = percentage === 50 ? this.escrowWallet.keys.transitKey1 : this.escrowWallet.keys.transitKey2

        const tx = await this.spendFromEscrow({
            walletId: this.escrowWallet.id,
            utxos,
            outputs,
            spendingPath: `partial${percentage}`,
            preimage,
            hashLock,
            signingKey
        })

        return this.broadcastTransaction(tx.toHex())
    }

    /**
     * Refund after timeout
     */
    async refund(utxos, outputs) {
        if (!this.escrowWallet) throw new Error('Escrow wallet not initialized')

        const tx = await this.spendFromEscrow({
            walletId: this.escrowWallet.id,
            utxos,
            outputs,
            spendingPath: 'refund',
            signingKey: this.escrowWallet.keys.refundKey
        })

        return this.broadcastTransaction(tx.toHex())
    }
}

// Specialized Transit Wallet
export class TransitWallet extends MiniscriptWallet {
    constructor(config = {}) {
        super(config)
        this.transitWallets = new Map()
    }

    /**
     * Create transit wallet for specific percentage
     */
    async createForPercentage(percentage, instantKeyName = null) {
        const keyName = instantKeyName || `instant${percentage}`

        const transitWallet = this.createTransitWallet({
            instantKey: keyName,
            timeLock: 1
        })

        this.transitWallets.set(percentage, transitWallet)

        console.log(`Transit wallet ${percentage}% created: ${transitWallet.address}`)
        console.log(`Descriptor: ${transitWallet.descriptor}`)

        return transitWallet
    }

    /**
     * Spend from transit wallet
     */
    async spendFromTransit(percentage, utxos, outputs, preimage = null, hashLock = null) {
        const transitWallet = this.transitWallets.get(percentage)
        if (!transitWallet) {
            throw new Error(`Transit wallet for ${percentage}% not found`)
        }

        const tx = await super.spendFromTransit({
            walletId: transitWallet.id,
            utxos,
            outputs,
            signingKey: transitWallet.keys.instantKey,
            preimage,
            hashLock
        })

        return this.broadcastTransaction(tx.toHex())
    }
}

// Factory for creating wallet instances
export class WalletFactory {
    static createEscrowWallet(config = {}) {
        return new EscrowWallet(config)
    }

    static createTransitWallet(config = {}) {
        return new TransitWallet(config)
    }

    static createUniversalWallet(config = {}) {
        return new MiniscriptWallet(config)
    }
}

// Usage example based on your code
export async function createTestScenario() {
    // Create wallet instances
    const escrowWallet = WalletFactory.createEscrowWallet()
    const transitWallet = WalletFactory.createTransitWallet()

    // Generate hash locks (from your test data)
    const secrets = [
        '0x67ec47ef1944db5f897bd6a4dbe375fdde6da66f62bf5c11523bee066dd97ee5',
        '0x70c741c87bfb79ee8da3583af9c4a0b5ea5aadad387b3b69c352d80e8f93673c',
        '0xbdd41fc036dda4a0975aa611702b46b1ec071d5b940140e8fec5b8ee6096aa3a',
        '0x726cc9c6902022901f9dcf4f6677ebc012a26f1bd3c9c53cf5ee654b767e64d8'
    ]

    const shaHashes = [
        '8c55b91417bfa9d083902165ac4c717b672fab70952fd78c4c9f4866a69a8d08',
        'a0b146fc66182df53e51827475f2d17c95c038563f7c96a75f99d6f2525ef5b6',
        'f36b4d440d69462a747ee98d108de6b570f6063c43c6427835151694dfc4c9ed',
        '4ac47dfeade496c2cc6cf91dd81267b5a518dbf1962b271c1fc89be6153ec30a'
    ]

    // Initialize escrow wallet
    const escrow = await escrowWallet.initialize({
        hashLock100: shaHashes[0],
        hashLockPartial25: shaHashes[1],
        hashLockPartial50: shaHashes[2]
    })

    // Create transit wallets for partial fills
    const transit50 = await transitWallet.createForPercentage(50, 'transit1')
    const transit25 = await transitWallet.createForPercentage(25, 'transit2')

    return {
        escrowWallet,
        transitWallet,
        escrow,
        transit50,
        transit25,
        secrets,
        shaHashes
    }
}

export default {
    MiniscriptWallet,
    EscrowWallet,
    TransitWallet,
    WalletFactory,
    createTestScenario
}
