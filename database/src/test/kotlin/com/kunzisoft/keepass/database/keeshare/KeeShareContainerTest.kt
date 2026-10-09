package com.kunzisoft.keepass.database.keeshare

import org.junit.Assert.assertArrayEquals
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class KeeShareContainerTest {

    // Start of a KDBX file signature
    private val kdbxBytes = byteArrayOf(0x03, 0xD9.toByte(), 0xA2.toByte(), 0x9A.toByte(), 0x67, 0xFB.toByte())

    private fun zip(vararg entries: Pair<String, ByteArray>): ByteArray {
        val output = ByteArrayOutputStream()
        ZipOutputStream(output).use { zip ->
            entries.forEach { (name, bytes) ->
                zip.putNextEntry(ZipEntry(name))
                zip.write(bytes)
                zip.closeEntry()
            }
        }
        return output.toByteArray()
    }

    @Test
    fun unsignedContainerIsReturnedAsIs() {
        val stream = KeeShareContainer.databaseStream(ByteArrayInputStream(kdbxBytes))
        assertArrayEquals(kdbxBytes, stream.readBytes())
    }

    @Test
    fun signedContainerReturnsInnerDatabase() {
        val container = zip(
            "container.share.signature" to "signature".toByteArray(),
            "container.share.kdbx" to kdbxBytes
        )
        val stream = KeeShareContainer.databaseStream(ByteArrayInputStream(container))
        assertArrayEquals(kdbxBytes, stream.readBytes())
    }

    @Test(expected = IOException::class)
    fun signedContainerWithoutDatabaseFails() {
        val container = zip("other.txt" to "nothing".toByteArray())
        KeeShareContainer.databaseStream(ByteArrayInputStream(container))
    }
}
