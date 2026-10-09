package com.kunzisoft.keepass.database.merge

import com.kunzisoft.keepass.database.crypto.kdf.KdfFactory
import com.kunzisoft.keepass.database.element.CustomDataItem
import com.kunzisoft.keepass.database.element.DateInstant
import com.kunzisoft.keepass.database.element.DeletedObject
import com.kunzisoft.keepass.database.element.database.DatabaseKDBX
import com.kunzisoft.keepass.database.element.entry.EntryKDBX
import com.kunzisoft.keepass.database.element.group.GroupKDBX
import org.joda.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.UUID

/**
 * A KeeShare container is a freshly exported database, so its metadata
 * timestamps are newer than the main database's. A scoped merge must only
 * touch the target group, never the main database's settings or root group.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ScopedMergeSafetyTest {

    private lateinit var mainDb: DatabaseKDBX
    private lateinit var targetGroup: GroupKDBX
    private val recycleBinUuid = UUID.randomUUID()
    private val longAgo = DateInstant(Instant.now().minus(365L * 24 * 3600 * 1000))

    @Before
    fun setUp() {
        mainDb = DatabaseKDBX("MainDB", "Root").apply {
            description = "main description"
            kdfEngine = KdfFactory.argon2idKdf
            historyMaxItems = 42
            isRecycleBinEnabled = true
            recycleBinUUID = recycleBinUuid
            nameChanged = longAgo
            descriptionChanged = longAgo
            settingsChanged = longAgo
            recycleBinChanged = longAgo
            keyLastChanged = longAgo
        }
        val root = mainDb.rootGroup!!
        root.customData.put(CustomDataItem("SomePlugin/Setting", "keep me"))
        root.lastModificationTime = longAgo

        targetGroup = mainDb.createGroup().apply { title = "Team" }
        mainDb.addGroupTo(targetGroup, root)
    }

    private fun buildContainer(): DatabaseKDBX {
        // What KeePassXC writes on export: a new database whose root is the shared group
        return DatabaseKDBX("Team", "Team").apply {
            kdfEngine = KdfFactory.aesKdf
            isRecycleBinEnabled = false
            val entry = createEntry().apply { title = "SharedEntry" }
            addEntryTo(entry, rootGroup)
        }
    }

    private fun scopedMerge(container: DatabaseKDBX) {
        DatabaseKDBXMerger(mainDb).apply {
            targetGroup = this@ScopedMergeSafetyTest.targetGroup
        }.merge(container)
    }

    @Test
    fun scopedMergePutsEntriesInTargetGroup() {
        scopedMerge(buildContainer())
        val titles = targetGroup.getChildEntries().map(EntryKDBX::title)
        assertTrue("SharedEntry should be in the target group", titles.contains("SharedEntry"))
    }

    @Test
    fun scopedMergeKeepsMainDatabaseSettings() {
        scopedMerge(buildContainer())
        assertEquals("MainDB", mainDb.name)
        assertEquals("main description", mainDb.description)
        assertEquals(KdfFactory.argon2idKdf.uuid, mainDb.kdfEngine?.uuid)
        assertEquals(42, mainDb.historyMaxItems)
        assertTrue(mainDb.isRecycleBinEnabled)
        assertEquals(recycleBinUuid, mainDb.recycleBinUUID)
    }

    @Test
    fun scopedMergeKeepsMainRootGroup() {
        scopedMerge(buildContainer())
        val root = mainDb.rootGroup!!
        assertEquals("Root", root.title)
        assertNotNull(root.customData.get("SomePlugin/Setting"))
    }

    @Test
    fun scopedMergeOnlyDeletesInsideTargetGroup() {
        val root = mainDb.rootGroup!!
        val outside = mainDb.createEntry().apply {
            title = "Outside"
            lastModificationTime = longAgo
        }
        mainDb.addEntryTo(outside, root)
        val inside = mainDb.createEntry().apply {
            title = "Inside"
            lastModificationTime = longAgo
        }
        mainDb.addEntryTo(inside, targetGroup)

        val container = buildContainer().apply {
            addDeletedObject(DeletedObject(outside.nodeId.id))
            addDeletedObject(DeletedObject(inside.nodeId.id))
            addDeletedObject(DeletedObject(targetGroup.nodeId.id))
        }
        scopedMerge(container)

        assertNotNull("Entry outside the share must survive", mainDb.getEntryById(outside.nodeId))
        assertNull("Entry inside the share is deleted", mainDb.getEntryById(inside.nodeId))
        assertNotNull("The shared group itself must survive", mainDb.getGroupById(targetGroup.nodeId))
    }

    @Test
    fun unscopedMergeStillMergesSettings() {
        // Regular "Merge database" keeps its existing behaviour
        DatabaseKDBXMerger(mainDb).merge(buildContainer())
        assertEquals("Team", mainDb.name)
    }
}
