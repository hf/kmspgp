package me.stojan.kmspgp.cli

import com.github.ajalt.clikt.core.CliktCommand

class Version(val root: Root) : CliktCommand(help = "Get the version.") {
    override fun run() {
        echo(message = "Version: ${CLI.version}")
    }
}