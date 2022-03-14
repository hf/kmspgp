package me.stojan.kmspgp.cli

import com.github.ajalt.clikt.core.subcommands

object CLI {
    fun run(args: Array<String>) = Root()
        .run {
            subcommands(
                List(this),
                Export(this),
                Sign(this),
            )
        }.main(args)

    @JvmStatic
    fun main(args: Array<String>) {
        run(args)
    }
}