const net = require('net')
const fs = require('fs')
const crypto = require('crypto')
const EventEmitter = require('events')

/**
 * Core Lightning Raw Socket Client
 * Implements the JSON-RPC protocol over Unix domain sockets
 */
class CLNRawSocketClient extends EventEmitter {
    constructor(socketPath = '/run/media/i/hdd/Blockchain/signet-cln-beta/signet/lightning-rpc') {
        super()
        this.socketPath = socketPath.replace('~', process.env.HOME)
        this.socket = null
        this.requestId = 0
        this.pendingRequests = new Map()
        this.buffer = ''
        this.connected = false
    }

    /**
     * Connect to Core Lightning socket
     */
    async connect() {
        return new Promise((resolve, reject) => {
            // Check if socket file exists
            if (!fs.existsSync(this.socketPath)) {
                return reject(new Error(`Socket file not found: ${this.socketPath}`))
            }

            console.log(`🔌 Connecting to CLN socket: ${this.socketPath}`)

            this.socket = net.createConnection(this.socketPath)

            this.socket.on('connect', () => {
                console.log('✅ Connected to Core Lightning')
                this.connected = true
                this.emit('connected')
                resolve()
            })

            this.socket.on('data', (data) => {
                this.handleData(data)
            })

            this.socket.on('error', (error) => {
                console.error('❌ Socket error:', error)
                this.connected = false
                this.emit('error', error)
                reject(error)
            })

            this.socket.on('close', () => {
                console.log('🔌 Socket closed')
                this.connected = false
                this.emit('disconnected')
            })

            this.socket.on('end', () => {
                console.log('🔌 Socket ended')
                this.connected = false
            })

            // Connection timeout
            setTimeout(() => {
                if (!this.connected) {
                    reject(new Error('Connection timeout'))
                }
            }, 5000)
        })
    }

    /**
     * Handle incoming data from socket
     */
    handleData(data) {
        this.buffer += data.toString()

        // Process complete JSON messages
        let lines = this.buffer.split('\n')
        this.buffer = lines.pop() // Keep incomplete line in buffer

        for (let line of lines) {
            if (line.trim()) {
                try {
                    const response = JSON.parse(line)
                    this.handleResponse(response)
                } catch (error) {
                    console.error('❌ JSON parse error:', error, 'Line:', line)
                }
            }
        }
    }

    /**
     * Handle JSON-RPC response
     */
    handleResponse(response) {
        const {id, result, error} = response

        if (id && this.pendingRequests.has(id)) {
            const {resolve, reject} = this.pendingRequests.get(id)
            this.pendingRequests.delete(id)

            if (error) {
                reject(new Error(`RPC Error: ${error.message || error}`))
            } else {
                resolve(result)
            }
        } else {
            // Handle notifications or unmatched responses
            this.emit('notification', response)
        }
    }

    /**
     * Send JSON-RPC request
     */
    async sendRequest(method, params = {}) {
        if (!this.connected) {
            throw new Error('Not connected to CLN socket')
        }

        const id = ++this.requestId
        const request = {
            jsonrpc: '2.0',
            id,
            method,
            params
        }

        return new Promise((resolve, reject) => {
            this.pendingRequests.set(id, {resolve, reject})

            const requestStr = JSON.stringify(request) + '\n'

            this.socket.write(requestStr, (error) => {
                if (error) {
                    this.pendingRequests.delete(id)
                    reject(error)
                }
            })

            // Request timeout
            setTimeout(() => {
                if (this.pendingRequests.has(id)) {
                    this.pendingRequests.delete(id)
                    reject(new Error(`Request timeout for method: ${method}`))
                }
            }, 30000)
        })
    }

    /**
     * Close connection
     */
    disconnect() {
        if (this.socket) {
            this.socket.end()
            this.socket = null
            this.connected = false
        }
    }

    // ===========================================
    // CLN API METHOD WRAPPERS
    // ===========================================

    /**
     * Get node information
     */
    async getinfo() {
        return this.sendRequest('getinfo')
    }

    /**
     * List peers
     */
    async listpeers() {
        return this.sendRequest('listpeers')
    }

    /**
     * List funds (wallet balance)
     */
    async listfunds() {
        return this.sendRequest('listfunds')
    }

    /**
     * Create invoice
     */
    async invoice(amount_msat, label, description, expiry = 3600) {
        return this.sendRequest('invoice', {
            amount_msat,
            label,
            description,
            expiry
        })
    }

    /**
     * Create invoice with preimage
     */
    async invoiceWithPreimage(amount_msat, label, description, preimage, expiry = 3600) {
        return this.sendRequest('invoice', {
            amount_msat,
            label,
            description,
            preimage,
            expiry
        })
    }

    /**
     * Create hold invoice
     */
    async holdinvoice(amount_msat, label, description, cltv = 144) {
        //preimage
        return this.sendRequest('holdinvoice', {
            amount_msat,
            label,
            description,
            cltv
        })
    }

    /**
     * Pay invoice
     */
    async pay(bolt11, msatoshi = null) {
        const params = {bolt11}
        if (msatoshi) params.msatoshi = msatoshi
        return this.sendRequest('pay', params)
    }

    /**
     * Decode invoice
     */
    async decodepay(bolt11, description = null) {
        const params = {bolt11}
        if (description) params.description = description
        return this.sendRequest('decodepay', params)
    }

    /**
     * List invoices
     */
    async listinvoices(label = null) {
        const params = label ? {label} : {}
        return this.sendRequest('listinvoices', params)
    }

    /**
     * List payments
     */
    async listpayments(bolt11 = null) {
        const params = bolt11 ? {bolt11} : {}
        return this.sendRequest('listpayments', params)
    }

    async sendFromTVMChannel(receiver, hashlock, token, amount) {
        const params = {receiver, hashlock, token, amount}
        return this.sendRequest('eversettokenhtlc', params)
    }

    async settleTVMChannel(preimage) {
        const params = {preimage}
        return this.sendRequest('everredeemtokenhtlc', params)
    }
}

// ===========================================
// USAGE EXAMPLES
// ===========================================

/**
 * Basic connection and info retrieval
 */
async function basicExample() {
    const client = new CLNRawSocketClient()

    try {
        await client.connect()

        const info = await client.getinfo()
        console.log('📊 Node Info:')
        console.log(`   Node ID: ${info.id}`)
        console.log(`   Alias: ${info.alias}`)
        console.log(`   Network: ${info.network}`)
        console.log(`   Block Height: ${info.blockheight}`)
        console.log(`   Version: ${info.version}`)
    } catch (error) {
        console.error('❌ Error:', error.message)
    } finally {
        client.disconnect()
    }
}

/**
 * Invoice and payment example
 */
async function invoiceExample() {
    const client = new CLNRawSocketClient()

    try {
        await client.connect()

        // Create invoice
        const invoice = await client.invoice(
            100000, // 100k msat (0.001 sat)
            `test-${Date.now()}`,
            'Test invoice from raw socket client'
        )

        console.log('💡 Invoice Created:')
        console.log(`   Payment Hash: ${invoice.payment_hash}`)
        console.log(`   BOLT11: ${invoice.bolt11}`)
        console.log(`   Expires: ${new Date(invoice.expires_at * 1000)}`)

        // Decode the invoice
        const decoded = await client.decodepay(invoice.bolt11)
        console.log('🔍 Decoded Invoice:')
        console.log(`   Amount: ${decoded.msatoshi} msat`)
        console.log(`   Description: ${decoded.description}`)
        console.log(`   Payee: ${decoded.payee}`)
    } catch (error) {
        console.error('❌ Error:', error.message)
    } finally {
        client.disconnect()
    }
}

/**
 * Wallet balance and address example
 */
async function walletExample() {
    const client = new CLNRawSocketClient()

    try {
        await client.connect()

        // Get wallet balance
        const funds = await client.listfunds()
        console.log('💰 Wallet Funds:')

        let totalSats = 0
        funds.outputs.forEach((output) => {
            if (output.status === 'confirmed') {
                totalSats += output.amount_msat
                console.log(`   ${output.amount_msat} sats (${output.txid.slice(0, 16)}...)`)
            }
        })

        console.log(`   Total: ${totalSats} sats`)
    } catch (error) {
        console.error('❌ Error:', error.message)
    } finally {
        client.disconnect()
    }
}

/**
 * Event handling example
 */
async function eventExample() {
    const client = new CLNRawSocketClient()

    // Set up event listeners
    client.on('connected', () => {
        console.log('🔗 Event: Connected to CLN')
    })

    client.on('disconnected', () => {
        console.log('❌ Event: Disconnected from CLN')
    })

    client.on('notification', (data) => {
        console.log('📡 Event: Notification received:', data)
    })

    client.on('error', (error) => {
        console.error('💥 Event: Error occurred:', error.message)
    })

    try {
        await client.connect()

        // Keep connection alive for events
        await new Promise((resolve) => {
            setTimeout(() => {
                client.disconnect()
                resolve()
            }, 10000) // 10 seconds
        })
    } catch (error) {
        console.error('❌ Error:', error.message)
    }
}

// ===========================================
// DIAGNOSTIC FUNCTION
// ===========================================

/**
 * Test socket connectivity and basic functionality
 */
async function diagnosticTest(socketPath = null) {
    console.log('🔍 Running CLN Raw Socket Diagnostic...\n')

    const testPaths = [
        socketPath,
        '/run/media/i/hdd/Blockchain/signet-cln-beta/signet/lightning-rpc',
        '~/.lightning/signet/lightning-rpc',
        '~/.lightning/testnet/lightning-rpc',
        '/tmp/lightning-rpc'
    ].filter(Boolean)

    for (const path of testPaths) {
        const expandedPath = path.replace('~', process.env.HOME)

        console.log(`🔍 Testing: ${expandedPath}`)

        // Check if socket exists
        if (!fs.existsSync(expandedPath)) {
            console.log('   ❌ Socket file not found')
            continue
        }

        const client = new CLNRawSocketClient(path)

        try {
            await client.connect()

            const info = await client.getinfo()
            console.log('   ✅ Connection successful!')
            console.log(`   📊 Node: ${info.alias} on ${info.network}`)
            console.log(`   🔗 Version: ${info.version}`)

            client.disconnect()

            // If we get here, this socket works
            console.log(`\n🎉 Working socket found: ${expandedPath}`)
            return expandedPath
        } catch (error) {
            console.log(`   ❌ Connection failed: ${error.message}`)
            client.disconnect()
        }
    }

    console.log('\n💥 No working CLN socket found!')
    console.log('💡 Make sure Core Lightning is running')
    return null
}

// ===========================================
// RUN EXAMPLES
// ===========================================

if (require.main === module) {
    const args = process.argv.slice(2)
    const command = args[0] || 'basic'

    switch (command) {
        case 'basic':
            basicExample()
            break
        case 'invoice':
            invoiceExample()
            break
        case 'wallet':
            walletExample()
            break
        case 'events':
            eventExample()
            break
        case 'diagnostic':
            diagnosticTest(args[1])
            break
        default:
            console.log('Available commands: basic, peer, invoice, wallet, events, concurrent, diagnostic')
    }
}

module.exports = {CLNRawSocketClient}
