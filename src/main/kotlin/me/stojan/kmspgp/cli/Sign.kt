package me.stojan.kmspgp.cli

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.parameters.arguments.argument
import me.stojan.kmspgp.crypto.PGP
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.BCPGOutputStream
import org.bouncycastle.crypto.io.DigestOutputStream
import software.amazon.awssdk.services.kms.model.DescribeKeyRequest
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest
import java.io.ByteArrayOutputStream
import java.time.Instant

class Sign(val root: Root) : CliktCommand(help = "Sign a message with the provided key.") {
    val key by argument(help = "The key ID (ARN, ID or alias) of the key to sign with.")

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

        val digest = PGP.bestDigest(pubRes)

        System.`in`.transferTo(DigestOutputStream(digest))

        val signature = PGP.sign(
            now = Instant.now(),
            digest = digest,
            signFn = PGP.signer(root.kmsClient, pubRes = pubRes, desRes = desRes),
            desRes = desRes,
            pubRes = pubRes,
        )

        echo(
            String(ByteArrayOutputStream()
                .also { bytes ->
                    ArmoredOutputStream(bytes).use { armored ->
                        BCPGOutputStream(armored).use {
                            signature.encode(it)
                        }
                    }
                }
                .toByteArray()))
    }
}