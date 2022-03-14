package me.stojan.kmspgp.cli

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.required
import com.github.ajalt.clikt.parameters.types.int
import me.stojan.kmspgp.crypto.PGP
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.BCPGOutputStream
import software.amazon.awssdk.services.kms.model.DescribeKeyRequest
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest
import java.io.ByteArrayOutputStream
import java.time.Instant

class Export(val root: Root) : CliktCommand(help = "Export a key's public part as a PGP/GPG value.") {
    val userName by option(help = "(Required) User name to attach to this key.").required()
    val userEmail by option(help = "(Required) User email to attach to this key.").required()
    val userComment by option(help = "Comment to attach to the user name and email.")
    val notAfter by option(help = "Key would not be valid after this date in UNIX seconds.").int()

    val key by argument(help = "The key ID (ARN, ID, alias) of the key to export.")

    override fun run() {
        val desRes = root.kmsClient.describeKey(
            DescribeKeyRequest.builder()
                .keyId(key)
                .build()
        )

        val pubRes = root.kmsClient.getPublicKey(
            GetPublicKeyRequest.builder()
                .keyId(key)
                .build()
        )

        var user = "$userName <$userEmail>"

        if (!userComment.isNullOrBlank()) {
            user = "$user (${userComment!!.trim()})"
        } else if (desRes.keyMetadata().description().isNotBlank()) {
            user = "$user (${desRes.keyMetadata().description().trim()})"
        }

        val notAfter: Instant? = notAfter.let { specified ->
            desRes.keyMetadata().validTo().let { validTo ->
                if (null == specified) {
                    validTo
                } else {
                    if (null == validTo) {
                        Instant.ofEpochSecond(specified.toLong())
                    } else {
                        if (specified < validTo.epochSecond) {
                            Instant.ofEpochSecond(specified.toLong())
                        } else {
                            validTo
                        }
                    }
                }
            }
        }

        val (key, userID, signature) = PGP.export(
            user = user,
            notAfter = notAfter,
            desRes = desRes,
            pubRes = pubRes,
            signFn = PGP.signer(kmsClient = root.kmsClient, pubRes = pubRes, desRes = desRes)
        )

        echo(message = String(ByteArrayOutputStream()
            .also { bytes ->
                ArmoredOutputStream(bytes).use { armored ->
                    BCPGOutputStream(armored).use { bcpgout ->
                        key.encode(bcpgout)
                        userID.encode(bcpgout)
                        signature.encode(bcpgout)
                    }
                }
            }
            .toByteArray()))
    }
}