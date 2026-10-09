package com.kunzisoft.keepass.database.keeshare

import java.io.BufferedInputStream
import java.io.IOException
import java.io.InputStream
import java.util.zip.ZipInputStream

/**
 * KeePassXC writes a KeeShare container either as a plain KDBX file (unsigned)
 * or as a ZIP holding the KDBX and its signature (signed, `.kdbx.share`).
 */
object KeeShareContainer {

    private const val SIGNED_CONTAINER_ENTRY = "container.share.kdbx"

    /**
     * Retrieve the KDBX stream of a container. For a signed container,
     * the signature is not verified.
     */
    @Throws(IOException::class)
    fun databaseStream(containerStream: InputStream): InputStream {
        val stream = BufferedInputStream(containerStream)
        if (!isZip(stream)) return stream
        val zipStream = ZipInputStream(stream)
        var entry = zipStream.nextEntry
        while (entry != null) {
            if (entry.name == SIGNED_CONTAINER_ENTRY) return zipStream
            entry = zipStream.nextEntry
        }
        zipStream.close()
        throw IOException("Signed KeeShare container without $SIGNED_CONTAINER_ENTRY")
    }

    private fun isZip(stream: BufferedInputStream): Boolean {
        val header = ByteArray(4)
        stream.mark(header.size)
        var read = 0
        while (read < header.size) {
            val count = stream.read(header, read, header.size - read)
            if (count < 0) break
            read += count
        }
        stream.reset()
        // ZIP local file header signature "PK\x03\x04"
        return read == header.size
                && header[0] == 0x50.toByte() && header[1] == 0x4B.toByte()
                && header[2] == 0x03.toByte() && header[3] == 0x04.toByte()
    }
}
