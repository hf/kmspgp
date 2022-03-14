package me.stojan.kmspgp.cli

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.subcommands
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.types.choice
import software.amazon.awssdk.http.apache.ApacheHttpClient
import software.amazon.awssdk.regions.Region
import software.amazon.awssdk.services.kms.KmsClient
import java.util.*

class Root : CliktCommand(name = "kmspgp", help = "Helps you use AWS KMS asymmetric keys as PGP/GPG keys.") {
    val region by option(help = "AWS region.", envvar = "AWS_REGION")
        .choice(*Region.regions().map { it.id() }.toTypedArray(), ignoreCase = true)
        .default(System.getenv("AWS_REGION") ?: Region.US_EAST_1.id())

    val kmsClient by lazy {
        KmsClient.builder()
            .region(Region.of(region.lowercase(Locale.US)))
            .httpClient(ApacheHttpClient.create())
            .build()
    }

    override fun run() {
        subcommands(List(this))
    }
}
