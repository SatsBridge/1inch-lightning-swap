import 'dotenv/config'
import {expect, jest} from '@jest/globals'

import {createServer, CreateServerReturnType} from 'prool'
import {anvil} from 'prool/instances'

import Sdk from '@1inch/cross-chain-sdk'
import {
    computeAddress,
    ContractFactory,
    JsonRpcProvider,
    MaxUint256,
    parseEther,
    parseUnits,
    randomBytes,
    Wallet as SignerWallet
} from 'ethers'
import {uint8ArrayToHex, UINT_40_MAX} from '@1inch/byte-utils'
import assert from 'node:assert'
import {ChainConfig, config} from './config'
import {Wallet} from './wallet'
import {Resolver} from './resolver'
import {EscrowFactory} from './escrow-factory'
import factoryContract from '../dist/contracts/TestEscrowFactory.sol/TestEscrowFactory.json'
import resolverContract from '../dist/contracts/Resolver.sol/Resolver.json'

import {CLNRawSocketClient} from './cln.js'

// BTC
import * as secp256k1 from '@bitcoinerlab/secp256k1'
import * as descriptors from '@bitcoinerlab/descriptors'
import {compilePolicy} from '@bitcoinerlab/miniscript'
import {Psbt, networks} from 'bitcoinjs-lib'
import {generateMnemonic, mnemonicToSeedSync} from 'bip39'
// @ts-ignore
import {encode as encodeAfter} from 'bip65'
import {readFileSync, writeFileSync} from 'fs'
import type {ECPairInterface} from 'ecpair'
import * as crypto from 'crypto'
const { Output, BIP32, ECPair } = descriptors.DescriptorsFactory(secp256k1);
const network = networks.testnet;
const EXPLORER = 'https://blockstream.info/testnet';
const JSONf = (json: object) => JSON.stringify(json, null, '\t');
// BTC Ends

const {Address} = Sdk

jest.setTimeout(1000 * 60)

const userPk = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d'
const resolverPk = '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a'

// eslint-disable-next-line max-lines-per-function
describe('Resolving example', () => {
    const srcChainId = config.chain.source.chainId
    const dstChainId = config.chain.destination.chainId

    type Chain = {
        node?: CreateServerReturnType | undefined
        provider: JsonRpcProvider
        escrowFactory: string
        resolver: string
    }

    let src: Chain
    let dst: Chain

    let srcChainUser: Wallet
    let dstChainUser: Wallet
    let srcChainResolver: Wallet
    let dstChainResolver: Wallet

    let srcFactory: EscrowFactory
    let dstFactory: EscrowFactory
    let srcResolverContract: Wallet
    let dstResolverContract: Wallet

    let srcTimestamp: bigint

    let alice_rpc: any
    let bob_rpc: any

    // BTC Onchain
    const BLOCKS = 2;
    const POLICY = (hashLock: string, timeLock: number) =>
      `or(and(sha256(${hashLock}),pk(@redeemKey)),and(after(${timeLock}),pk(@refundKey)))`;
    const WSH_ORIGIN_PATH = `/69420'/1'/0'`; //This can be any path you like.
    const WSH_KEY_PATH = `/0/0`; //Choose any path you like.

    // Initialize keys and secrets
    let refundKeyPair: ECPairInterface;
    let redeemMnemonic: string;

    async function increaseTime(t: number): Promise<void> {
        await Promise.all([src, dst].map((chain) => chain.provider.send('evm_increaseTime', [t])))
    }

    beforeAll(async () => {
        ;[src, dst] = await Promise.all([initChain(config.chain.source), initChain(config.chain.destination)])

        srcChainUser = new Wallet(userPk, src.provider)
        dstChainUser = new Wallet(userPk, dst.provider)
        srcChainResolver = new Wallet(resolverPk, src.provider)
        dstChainResolver = new Wallet(resolverPk, dst.provider)

        srcFactory = new EscrowFactory(src.provider, src.escrowFactory)
        dstFactory = new EscrowFactory(dst.provider, dst.escrowFactory)
        // get 1000 USDC for user in SRC chain and approve to LOP
        await srcChainUser.topUpFromDonor(
            config.chain.source.tokens.USDC.address,
            config.chain.source.tokens.USDC.donor,
            parseUnits('1000', 6)
        )
        await srcChainUser.approveToken(
            config.chain.source.tokens.USDC.address,
            config.chain.source.limitOrderProtocol,
            MaxUint256
        )

        // get 2000 USDC for resolver in DST chain
        srcResolverContract = await Wallet.fromAddress(src.resolver, src.provider)
        dstResolverContract = await Wallet.fromAddress(dst.resolver, dst.provider)
        await dstResolverContract.topUpFromDonor(
            config.chain.destination.tokens.USDC.address,
            config.chain.destination.tokens.USDC.donor,
            parseUnits('2000', 6)
        )
        // top up contract for approve
        await dstChainResolver.transfer(dst.resolver, parseEther('1'))
        await dstResolverContract.unlimitedApprove(config.chain.destination.tokens.USDC.address, dst.escrowFactory)

        srcTimestamp = BigInt((await src.provider.getBlock('latest'))!.timestamp)

        alice_rpc = new CLNRawSocketClient(config.chain.source.lightningRpc)
        bob_rpc = new CLNRawSocketClient(config.chain.destination.lightningRpc)

        // Onchain BTC ops
            try {
              refundKeyPair = ECPair.fromWIF(readFileSync('.refundWIF', 'utf8'));
              redeemMnemonic = readFileSync('.redeemMnemonic', 'utf8');
            } catch {
              refundKeyPair = ECPair.makeRandom();
              redeemMnemonic = generateMnemonic();
              writeFileSync('.refundWIF', refundKeyPair.toWIF());
              writeFileSync('.redeemMnemonic', redeemMnemonic);
            }

          console.log(
            `Your BTC secrets 🤫: ${JSONf({
              refundWIF: refundKeyPair.toWIF(),
              redeemMnemonic
            })}`
          );
    })

    async function getBalances(srcToken: string): Promise<{src: {user: bigint; resolver: bigint}}> {
        return {
            user: await srcChainUser.tokenBalance(srcToken),
            resolver: await srcResolverContract.tokenBalance(srcToken)
        }
    }

async function createEscrowAddress(hashLock: string): Promise<{ address: string; wshOutput: any; timeLock: number }> {
  const currentBlockHeight = parseInt(
    await (await fetch(`${EXPLORER}/api/blocks/tip/height`)).text()
  );

  const timeLock = encodeAfter({ blocks: currentBlockHeight + BLOCKS }); //
  console.log(`Current block height: ${currentBlockHeight}`);

  // Prepare the wsh utxo
  const { miniscript, issane } = compilePolicy(POLICY(hashLock,timeLock));
  if (!issane) throw new Error(`Error: miniscript is not sane`);

  const redeemWalletMasterNode = BIP32.fromSeed(
    mnemonicToSeedSync(redeemMnemonic),
    network
  );

  const redeemKey = redeemWalletMasterNode.derivePath(
    `m${WSH_ORIGIN_PATH}${WSH_KEY_PATH}`
  ).publicKey;

  const wshDescriptor = `wsh(${miniscript
    .replace(
      '@redeemKey',
      descriptors.keyExpressionBIP32({
        masterNode: redeemWalletMasterNode,
        originPath: WSH_ORIGIN_PATH,
        keyPath: WSH_KEY_PATH
      })
    )
    .replace('@refundKey', refundKeyPair.publicKey.toString('hex'))})`;

  const wshOutput = new Output({
    descriptor: wshDescriptor,
    network,
    signersPubKeys: [redeemKey] //, refundKeyPair.publicKey
  });

  const address = wshOutput.getAddress();
  return { address, wshOutput, timeLock };
}


    afterAll(async () => {
        src.provider.destroy()
        dst.provider.destroy()
        await Promise.all([src.node?.stop(), dst.node?.stop()])
    })

    // eslint-disable-next-line max-lines-per-function
    describe('Fill', () => {
        ;(it('should swap Ethereum USDC -> Onchain BTC. Single fill only', async () => {
            const initialUsdcBalances = await getBalances(config.chain.source.tokens.USDC.address)
            console.log('✅ Initial user USDC balance:', initialUsdcBalances.user)
            console.log('✅ Initial resolver USDC balance:', initialUsdcBalances.resolver)

            // User creates order
            const sbytes = randomBytes(32)
            const secret = uint8ArrayToHex(sbytes)
            const shalock = crypto.createHash('sha256').update(sbytes).digest('hex')

            const { address, wshOutput } = await createEscrowAddress(shalock)

            console.log("BTC escrow address: ", address)
            console.log("SHA256 lock: ", shalock)

            const order = Sdk.CrossChainOrder.new(
                new Address(src.escrowFactory),
                {
                    salt: Sdk.randBigInt(1000n),
                    maker: new Address(await srcChainUser.getAddress()),
                    makingAmount: parseUnits('100', 6),
                    takingAmount: parseUnits('99', 6),
                    makerAsset: new Address(config.chain.source.tokens.USDC.address),
                    takerAsset: new Address(config.chain.destination.tokens.USDC.address)
                },
                {
                    hashLock: Sdk.HashLock.forSingleFill(secret),
                    timeLocks: Sdk.TimeLocks.new({
                        srcWithdrawal: 10n, // 10sec finality lock for test
                        srcPublicWithdrawal: 120n, // 2m for private withdrawal
                        srcCancellation: 121n, // 1sec public withdrawal
                        srcPublicCancellation: 122n, // 1sec private cancellation
                        dstWithdrawal: 10n, // 10sec finality lock for test
                        dstPublicWithdrawal: 100n, // 100sec private withdrawal
                        dstCancellation: 101n // 1sec public withdrawal
                    }),
                    srcChainId,
                    dstChainId,
                    srcSafetyDeposit: parseEther('0.001'),
                    dstSafetyDeposit: parseEther('0.001')
                },
                {
                    auction: new Sdk.AuctionDetails({
                        initialRateBump: 0,
                        points: [],
                        duration: 120n,
                        startTime: srcTimestamp
                    }),
                    whitelist: [
                        {
                            address: new Address(src.resolver),
                            allowFrom: 0n
                        }
                    ],
                    resolvingStartTime: 0n
                },
                {
                    nonce: Sdk.randBigInt(UINT_40_MAX),
                    allowPartialFills: false,
                    allowMultipleFills: false
                }
            )

            const signature = await srcChainUser.signOrder(srcChainId, order)
            const orderHash = order.getOrderHash(srcChainId)
            // Resolver fills order
            const resolverContract = new Resolver(src.resolver, dst.resolver)

            console.log(`[${srcChainId}]`, `Filling order ${orderHash}`)

            const fillAmount = order.makingAmount

            const {txHash: orderFillHash, blockHash: srcDeployBlock} = await srcChainResolver.send(
                resolverContract.deploySrc(
                    srcChainId,
                    order,
                    signature,
                    Sdk.TakerTraits.default()
                        .setExtension(order.extension)
                        .setAmountMode(Sdk.AmountMode.maker)
                        .setAmountThreshold(order.takingAmount),
                    fillAmount
                )
            )

            console.log(`[${srcChainId}]`, `Order ${orderHash} filled for ${fillAmount} in tx ${orderFillHash}`)

            const srcEscrowEvent = await srcFactory.getSrcDeployEvent(srcDeployBlock)

            const dstImmutables = srcEscrowEvent[0]
                .withComplement(srcEscrowEvent[1])
                .withTaker(new Address(resolverContract.dstAddress))

            const ESCROW_SRC_IMPLEMENTATION = await srcFactory.getSourceImpl()

            const srcEscrowAddress = new Sdk.EscrowFactory(new Address(src.escrowFactory)).getSrcEscrowAddress(
                srcEscrowEvent[0],
                ESCROW_SRC_IMPLEMENTATION
            )

            console.log(`[${dstChainId}]`, `Depositing ${dstImmutables.amount} for order ${orderHash}`)

            await increaseTime(11)

            console.log(`[${srcChainId}]`, `Withdrawing funds for resolver from ${srcEscrowAddress}`)
            const {txHash: resolverWithdrawHash} = await srcChainResolver.send(
                resolverContract.withdraw('src', srcEscrowAddress, secret, srcEscrowEvent[0])
            )
            console.log(
                `[${srcChainId}]`,
                `Withdrew funds for resolver from ${srcEscrowAddress} to ${src.resolver} in tx ${resolverWithdrawHash}`
            )

            const finalUsdcBalance = await getBalances(config.chain.source.tokens.USDC.address)
            console.log('✅ Final user USDC balance:', finalUsdcBalance.user)
            console.log('✅ Final resolver USDC balance:', finalUsdcBalance.resolver)
        })
        /*,
            it('should swap Ethereum USDC -> LN BTC. Single fill only', async () => {
                try {
                    await alice_rpc.connect()
                } catch (error) {
                    console.error('❌ Error:', error.message)
                } finally {
                    alice_rpc.disconnect()
                }

                const initialUsdcBalances = await getBalances(config.chain.source.tokens.USDC.address)
                console.log('✅ Initial user USDC balance:', initialUsdcBalances.user)
                console.log('✅ Initial resolver USDC balance:', initialUsdcBalances.resolver)

                // User creates order
                const secret = uint8ArrayToHex(randomBytes(32)) // note: use crypto secure random number in real world
                const order = Sdk.CrossChainOrder.new(
                    new Address(src.escrowFactory),
                    {
                        salt: Sdk.randBigInt(1000n),
                        maker: new Address(await srcChainUser.getAddress()),
                        makingAmount: parseUnits('100', 6),
                        takingAmount: parseUnits('99', 6),
                        makerAsset: new Address(config.chain.source.tokens.USDC.address),
                        takerAsset: new Address(config.chain.destination.tokens.USDC.address)
                    },
                    {
                        hashLock: Sdk.HashLock.forSingleFill(secret),
                        timeLocks: Sdk.TimeLocks.new({
                            srcWithdrawal: 10n, // 10sec finality lock for test
                            srcPublicWithdrawal: 120n, // 2m for private withdrawal
                            srcCancellation: 121n, // 1sec public withdrawal
                            srcPublicCancellation: 122n, // 1sec private cancellation
                            dstWithdrawal: 10n, // 10sec finality lock for test
                            dstPublicWithdrawal: 100n, // 100sec private withdrawal
                            dstCancellation: 101n // 1sec public withdrawal
                        }),
                        srcChainId,
                        dstChainId,
                        srcSafetyDeposit: parseEther('0.001'),
                        dstSafetyDeposit: parseEther('0.001')
                    },
                    {
                        auction: new Sdk.AuctionDetails({
                            initialRateBump: 0,
                            points: [],
                            duration: 120n,
                            startTime: srcTimestamp
                        }),
                        whitelist: [
                            {
                                address: new Address(src.resolver),
                                allowFrom: 0n
                            }
                        ],
                        resolvingStartTime: 0n
                    },
                    {
                        nonce: Sdk.randBigInt(UINT_40_MAX),
                        allowPartialFills: false,
                        allowMultipleFills: false
                    }
                )

                const signature = await srcChainUser.signOrder(srcChainId, order)
                const orderHash = order.getOrderHash(srcChainId)
                // Resolver fills order
                const resolverContract = new Resolver(src.resolver, dst.resolver)

                console.log(`[${srcChainId}]`, `Filling order ${orderHash}`)
                let bolt11: any

                try {
                    await alice_rpc.connect()

                    // Create invoice
                    const invoice = await alice_rpc.invoiceWithPreimage(
                        100000, // 100k msat (0.001 sat)
                        `1inch-${Date.now()}`,
                        '1inch swap invoice with preimage',
                        secret.slice(2)
                    )

                    console.log('💡 Invoice Created:')
                    console.log(`   Payment Secret: ${secret}`)
                    console.log(`   Payment Hash: ${invoice.payment_hash}`)
                    console.log(`   BOLT11: ${invoice.bolt11}`)
                    bolt11 = invoice.bolt11
                    console.log(`   Expires: ${new Date(invoice.expires_at * 1000)}`)

                    // Decode the invoice
                    const decoded = await alice_rpc.decodepay(invoice.bolt11)
                    console.log('🔍 Decoded Invoice:')
                    console.log(`   Amount: ${decoded.amount_msat} msat`)
                    console.log(`   Description: ${decoded.description}`)
                    console.log(`   Payee: ${decoded.payee}`)
                } catch (error) {
                    console.error('❌ Error:', error.message)
                } finally {
                    alice_rpc.disconnect()
                }

                const fillAmount = order.makingAmount

                const {txHash: orderFillHash, blockHash: srcDeployBlock} = await srcChainResolver.send(
                    resolverContract.deploySrc(
                        srcChainId,
                        order,
                        signature,
                        Sdk.TakerTraits.default()
                            .setExtension(order.extension)
                            .setAmountMode(Sdk.AmountMode.maker)
                            .setAmountThreshold(order.takingAmount),
                        fillAmount
                    )
                )

                console.log(`[${srcChainId}]`, `Order ${orderHash} filled for ${fillAmount} in tx ${orderFillHash}`)

                const srcEscrowEvent = await srcFactory.getSrcDeployEvent(srcDeployBlock)

                const dstImmutables = srcEscrowEvent[0]
                    .withComplement(srcEscrowEvent[1])
                    .withTaker(new Address(resolverContract.dstAddress))

                const ESCROW_SRC_IMPLEMENTATION = await srcFactory.getSourceImpl()

                const srcEscrowAddress = new Sdk.EscrowFactory(new Address(src.escrowFactory)).getSrcEscrowAddress(
                    srcEscrowEvent[0],
                    ESCROW_SRC_IMPLEMENTATION
                )

                console.log(`[${dstChainId}]`, `Depositing ${dstImmutables.amount} for order ${orderHash}`)

                await increaseTime(11)

                try {
                    await bob_rpc.connect()
                    const status = await bob_rpc.pay(bolt11)

                    console.log('💡 Pay result:')
                    console.log(`   Payment preimage: ${status.payment_preimage}`)
                } catch (error) {
                    console.error('❌ Error:', error.message)
                } finally {
                    bob_rpc.disconnect()
                }

                console.log(`[${srcChainId}]`, `Withdrawing funds for resolver from ${srcEscrowAddress}`)
                const {txHash: resolverWithdrawHash} = await srcChainResolver.send(
                    resolverContract.withdraw('src', srcEscrowAddress, secret, srcEscrowEvent[0])
                )
                console.log(
                    `[${srcChainId}]`,
                    `Withdrew funds for resolver from ${srcEscrowAddress} to ${src.resolver} in tx ${resolverWithdrawHash}`
                )

                const finalUsdcBalance = await getBalances(config.chain.source.tokens.USDC.address)
                console.log('✅ Final user USDC balance:', finalUsdcBalance.user)
                console.log('✅ Final resolver USDC balance:', finalUsdcBalance.resolver)
            }),
            it('should swap Ethereum USDT -> TVM USDT. Single fill only', async () => {
                try {
                    await alice_rpc.connect()
                } catch (error) {
                    console.error('❌ Error:', error.message)
                } finally {
                    alice_rpc.disconnect()
                }

                const addressUSDT = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48'
                const tokenTVM = '0:34eefc8c8fb2b1e8da6fd6c86c1d5bcee1893bb81d34b3a085e301f2fba8d59c'
                const receiver = '0:43514bdd8b5ce6174b8b1b6a7b61e9e92e1e8205443a06a03778f60afe508ee9'

                const initialUSDTBalances = await getBalances(addressUSDT)
                console.log('✅ Initial user USDT balance:', initialUSDTBalances.user)
                console.log('✅ Initial resolver USDT balance:', initialUSDTBalances.resolver)

                const sbytes = randomBytes(32)
                const secret = uint8ArrayToHex(sbytes)
                const shalock = createHash('sha256').update(sbytes).digest('hex')

                const order = Sdk.CrossChainOrder.new(
                    new Address(src.escrowFactory),
                    {
                        salt: Sdk.randBigInt(1000n),
                        maker: new Address(await srcChainUser.getAddress()),
                        makingAmount: parseUnits('100', 6),
                        takingAmount: parseUnits('99', 6),
                        makerAsset: new Address(config.chain.source.tokens.USDC.address),
                        takerAsset: new Address(config.chain.destination.tokens.USDC.address)
                    },
                    {
                        hashLock: Sdk.HashLock.forSingleFill(secret),
                        timeLocks: Sdk.TimeLocks.new({
                            srcWithdrawal: 10n, // 10sec finality lock for test
                            srcPublicWithdrawal: 120n, // 2m for private withdrawal
                            srcCancellation: 121n, // 1sec public withdrawal
                            srcPublicCancellation: 122n, // 1sec private cancellation
                            dstWithdrawal: 10n, // 10sec finality lock for test
                            dstPublicWithdrawal: 100n, // 100sec private withdrawal
                            dstCancellation: 101n // 1sec public withdrawal
                        }),
                        srcChainId,
                        dstChainId,
                        srcSafetyDeposit: parseEther('0.001'),
                        dstSafetyDeposit: parseEther('0.001')
                    },
                    {
                        auction: new Sdk.AuctionDetails({
                            initialRateBump: 0,
                            points: [],
                            duration: 120n,
                            startTime: srcTimestamp
                        }),
                        whitelist: [
                            {
                                address: new Address(src.resolver),
                                allowFrom: 0n
                            }
                        ],
                        resolvingStartTime: 0n
                    },
                    {
                        nonce: Sdk.randBigInt(UINT_40_MAX),
                        allowPartialFills: false,
                        allowMultipleFills: false
                    }
                )

                const signature = await srcChainUser.signOrder(srcChainId, order)
                const orderHash = order.getOrderHash(srcChainId)
                const resolverContract = new Resolver(src.resolver, dst.resolver)

                console.log(`[${srcChainId}]`, `Filling order ${orderHash}`)

                try {
                    await alice_rpc.connect()
                    // Create invoice
                    const result = await alice_rpc.sendFromTVMChannel(receiver, shalock, tokenTVM, 10000)
                    console.log('💡 TVM escrow lock submitted:')
                    console.log(`   SHA256 Hash: ${shalock}`)
                    console.log(`   Lock Message ID: ${result.message}`)
                } catch (error) {
                    console.error('❌ Error:', error.message)
                } finally {
                    alice_rpc.disconnect()
                }

                const fillAmount = order.makingAmount

                const {txHash: orderFillHash, blockHash: srcDeployBlock} = await srcChainResolver.send(
                    resolverContract.deploySrc(
                        srcChainId,
                        order,
                        signature,
                        Sdk.TakerTraits.default()
                            .setExtension(order.extension)
                            .setAmountMode(Sdk.AmountMode.maker)
                            .setAmountThreshold(order.takingAmount),
                        fillAmount
                    )
                )

                console.log(`[${srcChainId}]`, `Order ${orderHash} filled for ${fillAmount} in tx ${orderFillHash}`)

                const srcEscrowEvent = await srcFactory.getSrcDeployEvent(srcDeployBlock)

                const dstImmutables = srcEscrowEvent[0]
                    .withComplement(srcEscrowEvent[1])
                    .withTaker(new Address(resolverContract.dstAddress))

                const ESCROW_SRC_IMPLEMENTATION = await srcFactory.getSourceImpl()

                const srcEscrowAddress = new Sdk.EscrowFactory(new Address(src.escrowFactory)).getSrcEscrowAddress(
                    srcEscrowEvent[0],
                    ESCROW_SRC_IMPLEMENTATION
                )

                console.log(`[${dstChainId}]`, `Depositing ${dstImmutables.amount} for order ${orderHash}`)

                await increaseTime(11)

                try {
                    await bob_rpc.connect()
                    const status = await bob_rpc.settleTVMChannel(secret.slice(2))

                    console.log('💡 Pay result:')
                    console.log(`   Unlock Message ID: ${status.message}`)
                } catch (error) {
                    console.error('❌ Error:', error.message)
                } finally {
                    bob_rpc.disconnect()
                }

                console.log(`[${srcChainId}]`, `Withdrawing funds for resolver from ${srcEscrowAddress}`)
                const {txHash: resolverWithdrawHash} = await srcChainResolver.send(
                    resolverContract.withdraw('src', srcEscrowAddress, secret, srcEscrowEvent[0])
                )
                console.log(
                    `[${srcChainId}]`,
                    `Withdrew funds for resolver from ${srcEscrowAddress} to ${src.resolver} in tx ${resolverWithdrawHash}`
                )

                const finalUsdtBalance = await getBalances(config.chain.source.tokens.USDC.address)
                console.log('✅ Final user USDT balance:', finalUsdtBalance.user)
                console.log('✅ Final resolver USDT balance:', finalUsdtBalance.resolver)
            })*/
        )
    })
})

async function initChain(
    cnf: ChainConfig
): Promise<{node?: CreateServerReturnType; provider: JsonRpcProvider; escrowFactory: string; resolver: string}> {
    const {node, provider} = await getProvider(cnf)
    const deployer = new SignerWallet(cnf.ownerPrivateKey, provider)

    // deploy EscrowFactory
    const escrowFactory = await deploy(
        factoryContract,
        [
            cnf.limitOrderProtocol,
            cnf.wrappedNative, // feeToken,
            Address.fromBigInt(0n).toString(), // accessToken,
            deployer.address, // owner
            60 * 30, // src rescue delay
            60 * 30 // dst rescue delay
        ],
        provider,
        deployer
    )
    console.log(`[${cnf.chainId}]`, `Escrow factory contract deployed to`, escrowFactory)

    // deploy Resolver contract
    const resolver = await deploy(
        resolverContract,
        [
            escrowFactory,
            cnf.limitOrderProtocol,
            computeAddress(resolverPk) // resolver as owner of contract
        ],
        provider,
        deployer
    )
    console.log(`[${cnf.chainId}]`, `Resolver contract deployed to`, resolver)

    return {node: node, provider, resolver, escrowFactory}
}

async function getProvider(cnf: ChainConfig): Promise<{node?: CreateServerReturnType; provider: JsonRpcProvider}> {
    if (!cnf.createFork) {
        return {
            provider: new JsonRpcProvider(cnf.url, cnf.chainId, {
                cacheTimeout: -1,
                staticNetwork: true
            })
        }
    }

    const node = createServer({
        instance: anvil({forkUrl: cnf.url, chainId: cnf.chainId}),
        limit: 1
    })
    await node.start()

    const address = node.address()
    assert(address)

    const provider = new JsonRpcProvider(`http://[${address.address}]:${address.port}/1`, cnf.chainId, {
        cacheTimeout: -1,
        staticNetwork: true
    })

    return {
        provider,
        node
    }
}

/**
 * Deploy contract and return its address
 */
async function deploy(
    json: {abi: any; bytecode: any},
    params: unknown[],
    provider: JsonRpcProvider,
    deployer: SignerWallet
): Promise<string> {
    const deployed = await new ContractFactory(json.abi, json.bytecode, deployer).deploy(...params)
    await deployed.waitForDeployment()

    return await deployed.getAddress()
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function waitForFunding(address, resolver, maxAttempts = 1000, intervalMs = 5000) {
  console.log(`🔄 Polling ${address} every ${intervalMs/1000} seconds...`);

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const balance = await resolver.checkBalance(address);

      if (balance.hasFunds) {
        console.log(`\n✅ FUNDED! Found ${balance.utxo.length} UTXO(s) after ${attempt} attempts`);
        return balance;
      }

      process.stdout.write(`\r⏳ Attempt ${attempt}/${maxAttempts} - Not funded yet...`);
      await sleep(intervalMs);

    } catch (error) {
      console.log(`\n❌ Error checking balance: ${error.message}`);
      await sleep(intervalMs);
    }
  }

  throw new Error(`Timeout: Address not funded after ${maxAttempts} attempts`);
}