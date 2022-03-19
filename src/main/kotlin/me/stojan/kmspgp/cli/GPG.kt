package me.stojan.kmspgp.cli

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.arguments.multiple
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.option
import me.stojan.kmspgp.crypto.PGP
import org.bouncycastle.bcpg.BCPGOutputStream
import org.bouncycastle.crypto.io.DigestOutputStream
import org.bouncycastle.util.encoders.Hex
import software.amazon.awssdk.awscore.exception.AwsServiceException
import software.amazon.awssdk.services.kms.model.DescribeKeyRequest
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest
import java.time.Instant
import java.util.*

class GPG(val root: Root) : CliktCommand(
    help = "Runs as a GPG substitute program (usable with git commit signing).",
    treatUnknownOptionsAsArgs = true
) {
    val bsau by option("--bsauXXXXX", hidden = true)
    val bsu by option("--bsuXXXXX", hidden = true)

    val statusFd by option("--status-fd", hidden = true)

    val gpgProgram by option(
        help = "Use this program as the fallback GPG implementation",
        envvar = "KMSPGP_GPG_PROGRAM"
    )
        .default("gpg")

    val args by argument().multiple()

    override fun run() {
        if (null != bsau || null != bsu) {
            try {
                val desRes = root.kmsClient.describeKey(
                    DescribeKeyRequest.builder()
                        .keyId(bsau ?: bsu)
                        .build()
                )

                val pubRes = root.kmsClient.getPublicKey(
                    GetPublicKeyRequest.builder()
                        .keyId(bsau ?: bsu)
                        .build()
                )

                val pgpKey = PGP.publicKey(desRes, pubRes)
                val fingerprint = Hex.toHexString(pgpKey.fingerprint).uppercase(
                    Locale.US
                )

                val digest = PGP.bestDigest(pubRes)

                System.`in`.transferTo(DigestOutputStream(digest))

                val signature = PGP.sign(
                    now = Instant.now(),
                    digest = digest,
                    signFn = PGP.signer(root.kmsClient, pubRes = pubRes, desRes = desRes),
                    desRes = desRes,
                    pubRes = pubRes,
                )

                val status = when (statusFd) {
                    "1" -> System.out
                    "2" -> System.err
                    else -> null
                }

                status?.println("[GNUPG:] KEY_CONSIDERED $fingerprint")
                status?.println(
                    "[GNUPG:] BEGIN_SIGNING H${signature.hashAlgorithm}"
                )
                status?.println(
                    "[GNUPG:] SIG_CREATED D ${signature.keyAlgorithm} ${signature.hashAlgorithm} ${
                        String.format(
                            Locale.US,
                            "%02X",
                            signature.signatureType
                        )
                    } ${signature.creationTime.time / 1000} $fingerprint"
                )

                if (null != bsau) {
                    println(PGP.armor { signature.encode(this) })
                } else {
                    BCPGOutputStream(System.out).use {
                        signature.encode(it)
                        it.flush()
                    }
                }
            } catch (e: AwsServiceException) {
                invokeGPG()
            }
        } else {
            invokeGPG()
        }
    }

    private fun invokeGPG() {
        ProcessBuilder()
            .apply {
                var args = args.map {
                    if (it.length > 8 && it.startsWith("--") && it.endsWith("XXXXX")) {
                        it.substring(1, it.length - 5)
                    } else {
                        it
                    }
                }

                if (null != bsau) {
                    args += "-bsau"
                    args += bsau!!
                }

                if (null != bsu) {
                    args += "-bsu"
                    args += bsu!!
                }

                if (null != statusFd) {
                    args += "--status-fd"
                    args += statusFd!!
                }

                command(gpgProgram, *args.toTypedArray())
                inheritIO()
            }
            .start()
            .waitFor()
    }
}