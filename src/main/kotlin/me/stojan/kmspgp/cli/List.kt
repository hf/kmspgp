package me.stojan.kmspgp.cli

import com.github.ajalt.clikt.core.CliktCommand
import me.stojan.kmspgp.crypto.PGP
import org.bouncycastle.util.encoders.Hex
import software.amazon.awssdk.services.kms.model.DescribeKeyRequest
import software.amazon.awssdk.services.kms.model.ExpirationModelType
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest
import software.amazon.awssdk.services.kms.model.KeyUsageType
import java.time.Instant
import java.time.format.DateTimeFormatter
import java.util.*
import kotlin.streams.toList

class List(val root: Root) : CliktCommand(help = "List all keys usable in PGP/GPG mode.") {

    override fun run() {
        val now = Instant.now()

        root.kmsClient.listKeysPaginator()
            .keys()
            .stream()
            .parallel()
            .map {
                root.kmsClient.describeKey(
                    DescribeKeyRequest.builder()
                        .keyId(it.keyId())
                        .build()
                )
            }
            .filter {
                it.keyMetadata().enabled()
            }
            .filter {
                when (it.keyMetadata().keyUsage()) {
                    KeyUsageType.SIGN_VERIFY -> true
                    else -> false
                }
            }
            .filter {
                when (it.keyMetadata().expirationModel()) {
                    ExpirationModelType.KEY_MATERIAL_EXPIRES -> it.keyMetadata().validTo().isBefore(now)
                    else -> true
                }
            }
            .map { desRes ->
                val pubRes = root.kmsClient.getPublicKey(
                    GetPublicKeyRequest.builder()
                        .keyId(desRes.keyMetadata().keyId())
                        .build()
                )

                Triple(desRes, pubRes, PGP.publicKey(desRes, pubRes))
            }
            .toList()
            .sortedBy { (desRes, _, _) -> desRes.keyMetadata().creationDate() }
            .apply {
                forEachIndexed { index, (desRes, _, pgpKey) ->
                    echo(desRes.keyMetadata().keyId())
                    echo(
                        "\tFingerprint\t${
                            Hex.toHexString(pgpKey.fingerprint, pgpKey.fingerprint.size - 8, 8).uppercase(
                                Locale.US
                            )
                        }"
                    )
                    echo("\tDescription\t${desRes.keyMetadata().description().ifBlank { "<unspecified>" }}")
                    echo("\tSpecification\t${desRes.keyMetadata().customerMasterKeySpec()}")
                    echo("\tOrigin\t\t${desRes.keyMetadata().originAsString()}")
                    echo("\tNot Before\t${DateTimeFormatter.ISO_INSTANT.format(desRes.keyMetadata().creationDate())}")
                    echo(
                        "\tNot After\t${
                            desRes.keyMetadata().validTo()
                                ?.let { DateTimeFormatter.ISO_INSTANT.format(it) } ?: "<unspecified>"
                        }")
                    echo(
                        "\tSign With\t${
                            desRes.keyMetadata().signingAlgorithms()
                                ?.joinToString(separator = ", ") { it.name } ?: "<unspecified>"
                        }")

                    echo("\tARN\t\t${desRes.keyMetadata().arn()}")

                    if (index + 1 < size) {
                        echo()
                        echo()
                    }
                }
            }
    }
}