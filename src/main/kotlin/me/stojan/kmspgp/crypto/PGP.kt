package me.stojan.kmspgp.crypto

import me.stojan.kmspgp.cli.CLI
import org.bouncycastle.asn1.pkcs.RSAPublicKey
import org.bouncycastle.asn1.sec.SECObjectIdentifiers
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.bcpg.*
import org.bouncycastle.crypto.ExtendedDigest
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.digests.SHA384Digest
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.io.DigestOutputStream
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.operator.PGPContentSigner
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import software.amazon.awssdk.core.SdkBytes
import software.amazon.awssdk.services.kms.KmsClient
import software.amazon.awssdk.services.kms.model.*
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.math.BigInteger
import java.time.Duration
import java.time.Instant
import java.util.*

object PGP {

    fun toECDSAPublicKey(pubRes: GetPublicKeyResponse): ECDSAPublicBCPGKey =
        ECDSAPublicBCPGKey(
            when (pubRes.customerMasterKeySpec()) {
                CustomerMasterKeySpec.ECC_NIST_P256 -> SECObjectIdentifiers.secp256r1
                CustomerMasterKeySpec.ECC_NIST_P384 -> SECObjectIdentifiers.secp384r1
                CustomerMasterKeySpec.ECC_NIST_P521 -> SECObjectIdentifiers.secp521r1
                CustomerMasterKeySpec.ECC_SECG_P256_K1 -> SECObjectIdentifiers.secp256k1
                else -> throw UnsupportedOperationException("Unsupported master key spec '${pubRes.customerMasterKeySpecAsString()}'")
            },
            SubjectPublicKeyInfo.getInstance(pubRes.publicKey().asByteArray()).publicKeyData.bytes.run {
                if (4.toByte() != this[0]) {
                    throw UnsupportedOperationException("ECDSA public key of type '${pubRes.customerMasterKeySpecAsString()}' has SubjectPublicKeyInfo which does not start with 0x04, see https://datatracker.ietf.org/doc/html/rfc5480#section-2.2")
                }

                BigInteger(this, 1, size - 1)
            }
        )

    fun toRSAPublicKey(pubRes: GetPublicKeyResponse): RSAPublicBCPGKey =
        SubjectPublicKeyInfo.getInstance(pubRes.publicKey().asByteArray())
            .run {
                RSAPublicKey.getInstance(parsePublicKey()).run {
                    RSAPublicBCPGKey(modulus, publicExponent)
                }
            }

    fun bestDigest(pubRes: GetPublicKeyResponse): ExtendedDigest = pubRes.signingAlgorithms().run {
        when {
            contains(SigningAlgorithmSpec.ECDSA_SHA_384) ||
                    contains(SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_384) ->
                SHA384Digest()

            contains(SigningAlgorithmSpec.ECDSA_SHA_512) ||
                    contains(SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_512) ->
                SHA512Digest()

            contains(SigningAlgorithmSpec.ECDSA_SHA_256) ||
                    contains(SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256) ->
                SHA256Digest()

            else -> SHA384Digest()
        }
    }

    fun publicKey(desRes: DescribeKeyResponse, pubRes: GetPublicKeyResponse): PGPPublicKey =
        when (pubRes.customerMasterKeySpec()) {
            CustomerMasterKeySpec.ECC_NIST_P256,
            CustomerMasterKeySpec.ECC_NIST_P384,
            CustomerMasterKeySpec.ECC_NIST_P521,
            CustomerMasterKeySpec.ECC_SECG_P256_K1 ->
                PublicKeyAlgorithmTags.ECDSA to toECDSAPublicKey(pubRes)

            CustomerMasterKeySpec.RSA_2048,
            CustomerMasterKeySpec.RSA_3072,
            CustomerMasterKeySpec.RSA_4096 ->
                PublicKeyAlgorithmTags.RSA_SIGN to toRSAPublicKey(pubRes)

            else -> throw UnsupportedOperationException()
        }.let { (type, key) ->
            PGPPublicKey(
                PublicKeyPacket(type, Date.from(desRes.keyMetadata().creationDate()), key),
                BcKeyFingerprintCalculator()
            )
        }

    fun export(
        user: String,
        notAfter: Instant?,
        desRes: DescribeKeyResponse,
        pubRes: GetPublicKeyResponse,
        pub: PGPPublicKey = publicKey(desRes, pubRes),
        signFn: (ExtendedDigest, ByteArray) -> ByteArray,
    ) =
        signPGP(
            // https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.1
            signatureType = 0x10,
            pub = pub,
            digest = bestDigest(pubRes),
            signFn = signFn,
            subpacketsFn = { issuer ->
                setSignatureCreationTime(false, Date.from(desRes.keyMetadata().creationDate()))

                notAfter?.also {
                    Duration.between(desRes.keyMetadata().creationDate(), it).seconds.let { seconds ->
                        if (seconds >= 0) {
                            setSignatureExpirationTime(false, seconds)
                            setKeyExpirationTime(false, seconds)
                        }
                    }
                }

                setSignerUserID(false, user.toByteArray())

                setIssuerFingerprint(false, issuer)

                // https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.21
                setFeature(false, 0x01 or 0x02)

                pubRes.signingAlgorithms().map {
                    when (it) {
                        SigningAlgorithmSpec.ECDSA_SHA_256,
                        SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256 ->
                            HashAlgorithmTags.SHA256

                        SigningAlgorithmSpec.ECDSA_SHA_384,
                        SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_384 ->
                            HashAlgorithmTags.SHA384

                        SigningAlgorithmSpec.ECDSA_SHA_512,
                        SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_512 ->
                            HashAlgorithmTags.SHA512

                        else -> -1
                    }
                }
                    .filter { it > -1 }
                    .toIntArray()
                    .let {
                        if (it.isNotEmpty()) {
                            setPreferredHashAlgorithms(false, it)
                        }
                    }
            },
        ) {
            generateCertification(user, pub)
        }.let { signature ->
            Triple(pub, UserIDPacket(user), signature)
        }

    fun sign(
        now: Instant,
        digest: ExtendedDigest,
        user: String? = null,
        desRes: DescribeKeyResponse,
        pubRes: GetPublicKeyResponse,
        pub: PGPPublicKey = publicKey(desRes, pubRes),
        signFn: (ExtendedDigest, ByteArray) -> ByteArray,
    ) = signPGP(
        // https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.1
        signatureType = 0x00,
        pub = pub,
        digest = digest,
        signFn = signFn,
        subpacketsFn = {
            setSignatureCreationTime(false, Date.from(now))

            user?.apply { addSignerUserID(false, this) }
        },
        generatorFn = {
            generate()
        },
    )

    private fun signPGP(
        signatureType: Int,
        pub: PGPPublicKey,
        digest: ExtendedDigest,
        signFn: (ExtendedDigest, ByteArray) -> ByteArray,
        subpacketsFn: PGPSignatureSubpacketGenerator.(PGPPublicKey) -> Unit,
        generatorFn: PGPSignatureGenerator.(PGPPublicKey) -> (PGPSignature),
    ): PGPSignature {
        val subpackets = PGPSignatureSubpacketGenerator()
            .apply {
                subpacketsFn(this, pub)
            }
            .generate()

        val signer = PGPContentSignerBuilder { _, _ ->
            object : PGPContentSigner {
                private val digestStream: OutputStream = DigestOutputStream(digest)

                private val digestValue: ByteArray by lazy {
                    ByteArray(digest.digestSize).apply { digest.doFinal(this, 0) }
                }

                private val signatureValue: ByteArray by lazy {
                    signFn(digest, digestValue)
                }

                override fun getOutputStream(): OutputStream = digestStream

                override fun getSignature(): ByteArray = signatureValue

                override fun getDigest(): ByteArray = digestValue

                override fun getType(): Int = signatureType

                override fun getHashAlgorithm(): Int = when (digest) {
                    is SHA256Digest -> HashAlgorithmTags.SHA256
                    is SHA384Digest -> HashAlgorithmTags.SHA384
                    is SHA512Digest -> HashAlgorithmTags.SHA512
                    else -> throw UnsupportedOperationException("Unknown digest type '${digest.javaClass.name}'")
                }

                override fun getKeyAlgorithm(): Int = pub.algorithm
                override fun getKeyID(): Long = pub.keyID
            }
        }

        val signature = PGPSignatureGenerator(signer)
            .apply {
                setHashedSubpackets(subpackets)

                init(signatureType, PGPPrivateKey(0, null, null))
            }
            .run { generatorFn(this, pub) }

        return signature
    }

    fun signer(
        kmsClient: KmsClient,
        desRes: DescribeKeyResponse,
        pubRes: GetPublicKeyResponse
    ): (ExtendedDigest, ByteArray) -> ByteArray = { digest, value ->
        kmsClient.sign(
            SignRequest.builder()
                .keyId(desRes.keyMetadata().keyId())
                .message(SdkBytes.fromByteArray(value))
                .messageType(MessageType.DIGEST)
                .signingAlgorithm(
                    when (pubRes.customerMasterKeySpec()) {
                        CustomerMasterKeySpec.ECC_NIST_P256,
                        CustomerMasterKeySpec.ECC_NIST_P384,
                        CustomerMasterKeySpec.ECC_NIST_P521,
                        CustomerMasterKeySpec.ECC_SECG_P256_K1 ->
                            when (digest) {
                                is SHA256Digest -> SigningAlgorithmSpec.ECDSA_SHA_256
                                is SHA384Digest -> SigningAlgorithmSpec.ECDSA_SHA_384
                                is SHA512Digest -> SigningAlgorithmSpec.ECDSA_SHA_512
                                else -> throw UnsupportedOperationException()
                            }

                        CustomerMasterKeySpec.RSA_2048,
                        CustomerMasterKeySpec.RSA_3072,
                        CustomerMasterKeySpec.RSA_4096 ->
                            when (digest) {
                                is SHA256Digest -> SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256
                                is SHA384Digest -> SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_384
                                is SHA512Digest -> SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_512
                                else -> throw UnsupportedOperationException()
                            }


                        else -> throw UnsupportedOperationException()
                    }
                )
                .build()
        ).signature().asByteArray()
    }

    fun armor(fn: BCPGOutputStream.() -> Unit) = String(
        ByteArrayOutputStream()
            .also { bytes ->
                ArmoredOutputStream(bytes).use { armored ->
                    armored.clearHeaders()
                    armored.addHeader("Version", "github.com/hf/kmspgp ${CLI.version}")

                    BCPGOutputStream(armored).use(fn)
                }
            }
            .toByteArray()
    )
}