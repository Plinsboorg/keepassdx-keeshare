package com.kunzisoft.keepass.database.keeshare

import com.kunzisoft.keepass.database.crypto.kdf.KdfEngine
import com.kunzisoft.keepass.database.crypto.kdf.KdfFactory
import com.kunzisoft.keepass.database.crypto.kdf.KdfParameters
import com.kunzisoft.keepass.database.crypto.kdf.Limits
import com.kunzisoft.keepass.database.element.MasterCredential
import com.kunzisoft.keepass.database.element.binary.BinaryCache
import com.kunzisoft.keepass.database.element.database.DatabaseKDBX
import com.kunzisoft.keepass.database.element.entry.EntryKDBX
import com.kunzisoft.keepass.database.element.group.GroupKDBX
import com.kunzisoft.keepass.database.element.node.NodeHandler
import com.kunzisoft.keepass.database.exception.KeeShareDatabaseException
import com.kunzisoft.keepass.database.file.input.DatabaseInputKDBX
import com.kunzisoft.keepass.database.file.output.DatabaseOutputKDBX
import com.kunzisoft.keepass.database.merge.DatabaseKDBXMerger
import com.kunzisoft.keepass.hardware.HardwareKey
import java.io.File
import java.io.InputStream
import java.io.OutputStream

/**
 * Synchronize a shared group of [database] with its KeeShare container:
 * import merges the container into the group, export writes the group into the container.
 *
 * KDF engines are shared objects between databases, and reading a KDBX 3.1 file even
 * modifies the parameters already in the engine. So a copy of the parameters of [database]
 * is restored after each container operation to never change its key derivation.
 */
class KeeShareSynchronizer(
    private val database: DatabaseKDBX,
    private val limits: Limits,
    // Temporary directory for the containers binaries, deleted after the synchronization
    private val cacheDirectory: File,
    // Key derivation of a new container, Argon2id like KeePassXC
    private val newContainerKdf: KdfEngine = KdfFactory.argon2idKdf,
) {

    class Result(val importChangedGroup: Boolean, val exported: Boolean)

    private val mainKdfEngine: KdfEngine? = database.kdfEngine
    private val mainKdfParameters: KdfParameters? = mainKdfEngine?.parameters?.let {
        KdfParameters(it.uuid, it)
    }

    /**
     * @param containerInput Stream of the current container, null if it doesn't exist yet
     * @param containerOutput Stream to write the container, called only to export
     */
    fun synchronize(
        sharedGroup: GroupKDBX,
        reference: KeeShareReference,
        import: Boolean,
        export: Boolean,
        containerInput: InputStream?,
        containerOutput: () -> OutputStream?,
    ): Result {
        try {
            cacheDirectory.mkdirs()
            // Null for a new empty file
            val opened = containerInput?.let { KeeShareContainer.open(it) }
            val container = opened?.let { readContainer(it.databaseStream, reference.password) }

            var importChangedGroup = false
            if (import && container != null) {
                val signatureBefore = contentSignature(sharedGroup)
                DatabaseKDBXMerger(database).apply {
                    isRAMSufficient = { memoryWanted ->
                        limits.isMemorySufficientForBinary(memoryWanted)
                    }
                    targetGroup = sharedGroup
                }.merge(container)
                importChangedGroup = signatureBefore != contentSignature(sharedGroup)
            }

            if (export) {
                if (opened?.isSigned == true)
                    throw KeeShareDatabaseException("A signed container (.kdbx.share) can't be written")
                writeContainer(sharedGroup, reference, container, containerOutput)
            }
            return Result(importChangedGroup, export)
        } finally {
            restoreMainKdf()
            cacheDirectory.deleteRecursively()
        }
    }

    private fun readContainer(stream: InputStream, password: String): DatabaseKDBX {
        val container = DatabaseKDBX().apply {
            binaryCache = newBinaryCache()
        }
        stream.use {
            DatabaseInputKDBX(container).apply {
                setMethodToCheckMemoryForBinary { memoryWanted ->
                    limits.isMemorySufficientForBinary(memoryWanted)
                }
                openDatabase(it, null) {
                    container.deriveMasterKey(MasterCredential(password.toCharArray()), NO_CHALLENGE)
                }
            }
        }
        // Reading the header assigned the container parameters to the shared KDF engine
        container.kdfEngine?.let { engine ->
            containerKdfParameters = engine.parameters
        }
        restoreMainKdf()
        return container
    }

    private var containerKdfParameters: KdfParameters? = null

    private fun writeContainer(
        sharedGroup: GroupKDBX,
        reference: KeeShareReference,
        currentContainer: DatabaseKDBX?,
        containerOutput: () -> OutputStream?,
    ) {
        val container = KeeShareExport.buildContainer(
            database, sharedGroup, reference.keepGroups, newBinaryCache()
        )
        // Keep the encryption of the current container
        val engine = currentContainer?.kdfEngine ?: newContainerKdf
        currentContainer?.let {
            container.encryptionAlgorithm = it.encryptionAlgorithm
            container.compressionAlgorithm = it.compressionAlgorithm
        }
        container.kdfEngine = engine
        engine.parameters = containerKdfParameters?.takeIf { currentContainer != null }
            ?: engine.defaultParameters
        engine.randomize()

        val cacheFile = File(cacheDirectory, "container.kdbx")
        cacheFile.outputStream().use { outputStream ->
            DatabaseOutputKDBX(container).writeDatabase(outputStream) {
                container.deriveMasterKey(MasterCredential(reference.password.toCharArray()), NO_CHALLENGE)
            }
        }
        // Only replace the container once completely written
        val outputStream = containerOutput()
            ?: throw KeeShareDatabaseException("Unable to write the container")
        outputStream.use { output ->
            cacheFile.inputStream().use { input -> input.copyTo(output) }
        }
    }

    private fun newBinaryCache() = BinaryCache().apply {
        cacheDirectory = File(this@KeeShareSynchronizer.cacheDirectory, "binaries")
            .apply { mkdirs() }
    }

    private fun restoreMainKdf() {
        mainKdfEngine?.let { engine ->
            // Assign the engine back to the database before its parameters,
            // the setter keeps the parameters already in the engine
            database.kdfEngine = engine
            mainKdfParameters?.let { engine.parameters = KdfParameters(it.uuid, it) }
        }
    }

    companion object {
        private val NO_CHALLENGE: (HardwareKey, ByteArray?) -> ByteArray = { _, _ ->
            throw KeeShareDatabaseException("A KeeShare container can't use a hardware key")
        }

        /**
         * Changes when a node of [group] is added, removed, modified or moved
         */
        fun contentSignature(group: GroupKDBX): String {
            var count = 0
            var lastChange = 0L
            val handle = { modification: Long, location: Long ->
                count++
                lastChange = maxOf(lastChange, modification, location)
            }
            group.doForEachChild(
                object : NodeHandler<EntryKDBX>() {
                    override fun operate(node: EntryKDBX): Boolean {
                        handle(node.lastModificationTime.instant.millis, node.locationChanged.instant.millis)
                        return true
                    }
                },
                object : NodeHandler<GroupKDBX>() {
                    override fun operate(node: GroupKDBX): Boolean {
                        handle(node.lastModificationTime.instant.millis, node.locationChanged.instant.millis)
                        return true
                    }
                }
            )
            return "$count:$lastChange"
        }
    }
}
