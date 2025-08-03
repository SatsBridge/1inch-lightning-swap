import 'dotenv/config'
import {expect, jest} from '@jest/globals'
import {WalletFactory, createTestScenario} from './btc.ts'

jest.setTimeout(1000 * 60)

// eslint-disable-next-line max-lines-per-function
describe('BTC Escrow Test', () => {
    // eslint-disable-next-line max-lines-per-function
    let scenario: any
    let escrowWallet: any
    let transitWallet: any
    let escrow: any
    let secrets: any
    let shaHashes: any

    // Move scenario creation to beforeAll
    beforeAll(async () => {
        // Create test scenario with your exact parameters
        scenario = await createTestScenario()
        // Access wallets
        ;({escrowWallet, transitWallet, escrow, secrets, shaHashes} = scenario)
    })

    describe('Fill', () => {
        ;(it('OnchainEscrowWallet: Single fill only', async () => {
            // Check balance
            console.log(`Deposit funds to ${escrow.address}`)

            let escrowUtxos: any
            let received = 0
            let funded = false

            while (!funded) {
                const {utxo, totalValue} = await escrowWallet.checkBalance(escrow.address)
                if (totalValue > 0) {
                    funded = true
                    console.log('✅ Funded! Continuing...')
                    received = totalValue
                    escrowUtxos = utxo
                } else {
                    console.log('⏳ Waiting for funding...')
                    await new Promise((resolve) => setTimeout(resolve, 10000)) // Check every 10 seconds
                }
            }

            // Continue with test
            expect(funded).toBe(true)

            //const { utxo, totalValue } = await escrowWallet.checkBalance(escrow.address);
            // Spend 50% (partial fill)

            // Calculate total value from all UTXOs
            console.log(`Total UTXO value: ${received} satoshis`)

            // Define fee (adjust as needed)
            const networkFee = 1000 // 1000 satoshis network fee
            const percentageFee = Math.floor(received * 0.001) // 0.1% fee
            const totalFee = Math.max(networkFee, percentageFee) // Use higher of fixed or percentage fee

            console.log(`Network fee: ${networkFee} satoshis`)
            console.log(`Percentage fee: ${percentageFee} satoshis`)
            console.log(`Total fee: ${totalFee} satoshis`)

            // Calculate spendable amount (after fees)
            const spendableValue = received - totalFee
            if (spendableValue <= 0) {
                throw new Error(`Insufficient funds: total ${received}, fee ${totalFee}`)
            }

            console.log(`Spendable value: ${spendableValue} satoshis`)

            const result50 = await escrowWallet.spendPartial(
                escrowUtxos,
                [
                    {
                        address: 'tb1qn8y6d039a3zlefrfh2gna4c7d3qx4n5w33p4t2ruwcjs74wnxhnsega534',
                        value: Math.floor(spendableValue * 0.5)
                    }
                ],
                50, // percentage
                secrets[2].slice(2), // preimage
                shaHashes[2] // hash lock
            )
        }, 60000),
            it('OnchainEscrowWallet: Fill 50%', async () => {
                // Check balance
                console.log(`Deposit funds to ${escrow.address}`)

                let escrowUtxos: any
                let received = 0
                let funded = false

                while (!funded) {
                    const {utxo, totalValue} = await escrowWallet.checkBalance(escrow.address)
                    if (totalValue > 0) {
                        funded = true
                        console.log('✅ Funded! Continuing...')
                        received = totalValue
                        escrowUtxos = utxo
                    } else {
                        console.log('⏳ Waiting for funding...')
                        await new Promise((resolve) => setTimeout(resolve, 10000)) // Check every 10 seconds
                    }
                }

                // Continue with test
                expect(funded).toBe(true)

                //const { utxo, totalValue } = await escrowWallet.checkBalance(escrow.address);
                // Spend 50% (partial fill)

                // Calculate total value from all UTXOs
                console.log(`Total UTXO value: ${received} satoshis`)

                // Define fee (adjust as needed)
                const networkFee = 1000 // 1000 satoshis network fee
                const percentageFee = Math.floor(received * 0.001) // 0.1% fee
                const totalFee = Math.max(networkFee, percentageFee)

                console.log(`Network fee: ${networkFee} satoshis`)
                console.log(`Percentage fee: ${percentageFee} satoshis`)
                console.log(`Total fee: ${totalFee} satoshis`)

                // Calculate spendable amount (after fees)
                const spendableValue = received - totalFee
                if (spendableValue <= 0) {
                    throw new Error(`Insufficient funds: total ${received}, fee ${totalFee}`)
                }

                console.log(`Spendable value: ${spendableValue} satoshis`)

                // Spend full amount (100%)
                const resultFull = await escrowWallet.spendFull(
                    escrowUtxos,
                    [
                        {
                            address: 'tb1qn8y6d039a3zlefrfh2gna4c7d3qx4n5w33p4t2ruwcjs74wnxhnsega534',
                            value: spendableValue
                        }
                    ],
                    secrets[0].slice(2), // preimage
                    shaHashes[0] // hash lock
                )
            }, 60000),
            it('OnchainEscrowWallet: Refund', async () => {
                // Check balance
                console.log(`Deposit funds to ${escrow.address}`)

                let escrowUtxos: any
                let received = 0
                let funded = false

                while (!funded) {
                    const {utxo, totalValue} = await escrowWallet.checkBalance(escrow.address)
                    if (totalValue > 0) {
                        funded = true
                        console.log('✅ Funded! Continuing...')
                        received = totalValue
                        escrowUtxos = utxo
                    } else {
                        console.log('⏳ Waiting for funding...')
                        await new Promise((resolve) => setTimeout(resolve, 10000)) // Check every 10 seconds
                    }
                }

                // Continue with test
                expect(funded).toBe(true)

                //const { utxo, totalValue } = await escrowWallet.checkBalance(escrow.address);
                // Spend 50% (partial fill)

                // Calculate total value from all UTXOs
                console.log(`Total UTXO value: ${received} satoshis`)

                // Define fee (adjust as needed)
                const networkFee = 1000 // 1000 satoshis network fee
                const percentageFee = Math.floor(received * 0.001) // 0.1% fee
                const totalFee = Math.max(networkFee, percentageFee) // Use higher of fixed or percentage fee

                console.log(`Network fee: ${networkFee} satoshis`)
                console.log(`Percentage fee: ${percentageFee} satoshis`)
                console.log(`Total fee: ${totalFee} satoshis`)

                // Calculate spendable amount (after fees)
                const spendableValue = received - totalFee
                if (spendableValue <= 0) {
                    throw new Error(`Insufficient funds: total ${received}, fee ${totalFee}`)
                }

                console.log(`Spendable value: ${spendableValue} satoshis`)

                // Refund after timeout
                const refundResult = await escrowWallet.refund(escrowUtxos, [
                    {address: 'tb1qn8y6d039a3zlefrfh2gna4c7d3qx4n5w33p4t2ruwcjs74wnxhnsega534', value: spendableValue}
                ])
            }, 60000))
    })
})
