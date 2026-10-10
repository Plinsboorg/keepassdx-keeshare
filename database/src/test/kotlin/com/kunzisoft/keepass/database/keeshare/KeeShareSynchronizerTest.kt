package com.kunzisoft.keepass.database.keeshare

import com.kunzisoft.keepass.database.crypto.kdf.KdfFactory
import com.kunzisoft.keepass.database.crypto.kdf.Limits
import com.kunzisoft.keepass.database.element.Attachment
import com.kunzisoft.keepass.database.element.CustomDataItem
import com.kunzisoft.keepass.database.element.MasterCredential
import com.kunzisoft.keepass.database.element.binary.BinaryCache
import com.kunzisoft.keepass.database.element.database.DatabaseKDBX
import com.kunzisoft.keepass.database.element.entry.EntryKDBX
import com.kunzisoft.keepass.database.element.group.GroupKDBX
import com.kunzisoft.keepass.database.exception.KeeShareDatabaseException
import com.kunzisoft.keepass.database.file.input.DatabaseInputKDBX
import com.kunzisoft.keepass.database.file.output.DatabaseOutputKDBX
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Round trips through real encrypted containers. AES-KDF is used since
 * Argon2 needs the native library, which isn't available in unit tests.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class KeeShareSynchronizerTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private val password = "share password"
    private val limits = Limits({ _, _ -> true }, 1)
    private val noChallenge: (com.kunzisoft.keepass.hardware.HardwareKey, ByteArray?) -> ByteArray =
        { _, _ -> ByteArray(0) }

    private lateinit var phone: DatabaseKDBX
    private lateinit var sharedGroup: GroupKDBX

    @Before
    fun setUp() {
        phone = newDatabase("Phone", "Root")
        sharedGroup = phone.createGroup().apply { title = "Team" }
        phone.addGroupTo(sharedGroup, phone.rootGroup)
    }

    private fun newDatabase(name: String, rootName: String) = DatabaseKDBX(name, rootName).apply {
        binaryCache = BinaryCache().apply { cacheDirectory = tempFolder.newFolder() }
        kdfEngine = KdfFactory.aesKdf
        KdfFactory.aesKdf.parameters = KdfFactory.aesKdf.defaultParameters
        KdfFactory.aesKdf.setKeyRounds(1000u)
    }

    private fun reference(type: Int = KeeShareReference.SYNCHRONIZE, keepGroups: Boolean = true) =
        KeeShareReference(type = type, path = "team.kdbx", password = password, keepGroups = keepGroups)

    private fun synchronizer(database: DatabaseKDBX) =
        KeeShareSynchronizer(database, limits, tempFolder.newFolder(), KdfFactory.aesKdf)

    private fun addEntry(database: DatabaseKDBX, group: GroupKDBX, title: String): EntryKDBX {
        val entry = database.createEntry().apply { this.title = title }
        database.addEntryTo(entry, group)
        return entry
    }

    private fun export(database: DatabaseKDBX, group: GroupKDBX, current: ByteArray? = null): ByteArray {
        val output = ByteArrayOutputStream()
        synchronizer(database).synchronize(
            group, reference(), import = current != null, export = true,
            containerInput = current?.let { ByteArrayInputStream(it) },
            containerOutput = { output }
        )
        return output.toByteArray()
    }

    private fun import(database: DatabaseKDBX, group: GroupKDBX, container: ByteArray): KeeShareSynchronizer.Result {
        return synchronizer(database).synchronize(
            group, reference(), import = true, export = false,
            containerInput = ByteArrayInputStream(container),
            containerOutput = { null }
        )
    }

    private fun readContainer(bytes: ByteArray): DatabaseKDBX {
        val container = DatabaseKDBX().apply {
            binaryCache = BinaryCache().apply { cacheDirectory = tempFolder.newFolder() }
        }
        DatabaseInputKDBX(container).openDatabase(ByteArrayInputStream(bytes), null) {
            container.deriveMasterKey(MasterCredential(password.toCharArray()), noChallenge)
        }
        return container
    }

    @Test
    fun exportThenImportOnAnotherDevice() {
        val entry = addEntry(phone, sharedGroup, "Wifi")
        val attachmentData = "router config".toByteArray()
        val binary = phone.buildNewBinaryAttachment(true, false, false)
        binary.getOutputDataStream(phone.binaryCache).use { it.write(attachmentData) }
        entry.putAttachment(Attachment("config.txt", binary), phone.attachmentPool)
        val oldVersion = EntryKDBX().apply { updateWith(entry, copyHistory = false) }
        entry.addEntryToHistory(oldVersion)
        addEntry(phone, phone.rootGroup!!, "Private")

        val container = export(phone, sharedGroup)

        val laptop = newDatabase("Laptop", "Root")
        val laptopShared = laptop.createGroup().apply { title = "Shared on laptop" }
        laptop.addGroupTo(laptopShared, laptop.rootGroup)
        val result = import(laptop, laptopShared, container)

        assertTrue(result.importChangedGroup)
        val imported = laptopShared.getChildEntries().single()
        assertEquals("Wifi", imported.title)
        assertEquals(1, imported.history.size)
        val importedAttachment = imported.getAttachments(laptop.attachmentPool).single()
        val importedData = importedAttachment.binaryData.getInputDataStream(laptop.binaryCache).use { it.readBytes() }
        assertArrayEquals(attachmentData, importedData)
        assertNull("Only the shared group is exported", laptop.rootGroup!!.getChildEntries().find { it.title == "Private" })
    }

    @Test
    fun synchronizeMergesBothWays() {
        addEntry(phone, sharedGroup, "From phone")
        val laptop = newDatabase("Laptop", "Root")
        val laptopShared = laptop.createGroup().apply { title = "Team" }
        laptop.addGroupTo(laptopShared, laptop.rootGroup)
        addEntry(laptop, laptopShared, "From laptop")
        val laptopContainer = export(laptop, laptopShared)

        val synchronized = export(phone, sharedGroup, current = laptopContainer)

        val phoneTitles = sharedGroup.getChildEntries().map { it.title }.toSet()
        assertEquals(setOf("From phone", "From laptop"), phoneTitles)
        val containerTitles = readContainer(synchronized).rootGroup!!.getChildEntries().map { it.title }.toSet()
        assertEquals(setOf("From phone", "From laptop"), containerTitles)
    }

    /**
     * Write [database] as a container, like another device with its own KDF rounds
     */
    private fun writeAsContainer(database: DatabaseKDBX, rounds: ULong): ByteArray {
        database.kdfEngine = KdfFactory.aesKdf
        KdfFactory.aesKdf.parameters = KdfFactory.aesKdf.defaultParameters
        KdfFactory.aesKdf.setKeyRounds(rounds)
        val output = ByteArrayOutputStream()
        DatabaseOutputKDBX(database).writeDatabase(output) {
            database.deriveMasterKey(MasterCredential(password.toCharArray()), noChallenge)
        }
        return output.toByteArray()
    }

    @Test
    fun keepsMainKdfAndContainerKdf() {
        val laptop = newDatabase("Laptop", "Root")
        addEntry(laptop, laptop.rootGroup!!, "From laptop")
        val laptopContainer = writeAsContainer(laptop, 2000u)

        // The phone database is open with its own parameters
        phone.kdfEngine = KdfFactory.aesKdf
        KdfFactory.aesKdf.parameters = KdfFactory.aesKdf.defaultParameters
        KdfFactory.aesKdf.setKeyRounds(1000u)
        KdfFactory.aesKdf.randomize()
        val phoneSeed = KdfFactory.aesKdf.getSeed()!!.copyOf()

        val synchronized = export(phone, sharedGroup, current = laptopContainer)

        // Reading and writing the container didn't change the phone key derivation
        assertEquals(KdfFactory.aesKdf.uuid, phone.kdfEngine!!.uuid)
        assertEquals(1000uL, phone.kdfEngine!!.getKeyRounds())
        assertArrayEquals(phoneSeed, phone.kdfEngine!!.getSeed())
        // and the container keeps its own
        val container = readContainer(synchronized)
        assertEquals(2000uL, container.kdfEngine!!.getKeyRounds())
        assertEquals("From laptop", container.rootGroup!!.getChildEntries().single().title)
    }

    @Test
    fun emptyFileIsANewContainer() {
        addEntry(phone, sharedGroup, "Wifi")
        val output = ByteArrayOutputStream()
        synchronizer(phone).synchronize(
            sharedGroup, reference(), import = true, export = true,
            containerInput = ByteArrayInputStream(ByteArray(0)),
            containerOutput = { output }
        )
        assertEquals("Wifi", readContainer(output.toByteArray()).rootGroup!!.getChildEntries().single().title)
    }

    @Test
    fun nestedSharePasswordIsNotExported() {
        sharedGroup.customData.put(CustomDataItem(KeeShareReference.CUSTOM_DATA_KEY, reference().serialize()))
        val nested = phone.createGroup().apply {
            title = "Nested"
            customData.put(CustomDataItem(KeeShareReference.CUSTOM_DATA_KEY,
                KeeShareReference(KeeShareReference.IMPORT_FROM, path = "other.kdbx", password = "secret").serialize()))
        }
        phone.addGroupTo(nested, sharedGroup)

        val container = readContainer(export(phone, sharedGroup))

        val root = container.rootGroup!!
        assertNull(root.customData.get(KeeShareReference.CUSTOM_DATA_KEY))
        val nestedGroup = root.getChildGroups().single()
        assertNull(nestedGroup.customData.get(KeeShareReference.CUSTOM_DATA_KEY))
        // The shared group keeps its own reference in the main database
        assertNotNull(sharedGroup.customData.get(KeeShareReference.CUSTOM_DATA_KEY))
    }

    @Test
    fun subgroupsOnlyWithKeepGroups() {
        val subgroup = phone.createGroup().apply { title = "Sub" }
        phone.addGroupTo(subgroup, sharedGroup)
        val output = ByteArrayOutputStream()
        synchronizer(phone).synchronize(
            sharedGroup, reference(keepGroups = false), import = false, export = true,
            containerInput = null, containerOutput = { output }
        )
        assertTrue(readContainer(output.toByteArray()).rootGroup!!.getChildGroups().isEmpty())
    }

    @Test(expected = KeeShareDatabaseException::class)
    fun signedContainerIsNotWritten() {
        val laptop = newDatabase("Laptop", "Root")
        val signed = ByteArrayOutputStream().also { bytes ->
            ZipOutputStream(bytes).use { zip ->
                zip.putNextEntry(ZipEntry("container.share.kdbx"))
                zip.write(export(laptop, laptop.rootGroup!!))
                zip.closeEntry()
            }
        }.toByteArray()
        export(phone, sharedGroup, current = signed)
    }

    @Test
    fun noChangeIsReported() {
        addEntry(phone, sharedGroup, "Wifi")
        val container = export(phone, sharedGroup)
        assertFalse(import(phone, sharedGroup, container).importChangedGroup)
    }
}
