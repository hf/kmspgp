package me.stojan.kmspgp.cli

import BuildInfo
import com.github.ajalt.clikt.core.subcommands

object CLI {
    val version = BuildInfo.version
    val commit = BuildInfo.commit

    fun run(args: Array<String>) = Root()
        .run {
            subcommands(
                List(this),
                Export(this),
                Sign(this),
                Version(this),
                GPG(this),
            )
        }.main(args)

    @JvmStatic
    fun main(args: Array<String>) {
        val invalidShortOpt = Regex("^-[a-zA-Z]{2,}$")

        run(args.map {
            if (it.matches(invalidShortOpt)) {
                // because Clikt does not support '-abcdefgh' style options at this time
                // they are transformed to a long-style option ending with 5 Xs
                "-${it}XXXXX"
            } else {
                it
            }
        }.toTypedArray())
    }
}