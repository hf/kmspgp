package me.stojan.kmspgp.cli

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.arguments.multiple
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.types.choice
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient
import software.amazon.awssdk.regions.Region
import software.amazon.awssdk.services.kms.KmsClient
import java.util.*

class Root : CliktCommand(
    name = "kmspgp",
    help = "Helps you use AWS KMS asymmetric keys as PGP/GPG keys.",
    invokeWithoutSubcommand = true,
    treatUnknownOptionsAsArgs = true,
) {
    val region by option(help = "AWS region.", envvar = "AWS_REGION")
        .choice(*Region.regions().map { it.id() }.toTypedArray(), ignoreCase = true)
        .default(System.getenv("AWS_REGION") ?: Region.US_EAST_1.id())

    val args by argument().multiple()

    val kmsClient by lazy {
        KmsClient.builder()
            .region(Region.of(region.lowercase(Locale.US)))
            .httpClient(UrlConnectionHttpClient.create())
            .build()
    }

    override fun run() {
        if (null == currentContext.invokedSubcommand) {
            GPG(this).main(args)
        }
    }
}
