package com.kunzisoft.keepass.database.keeshare

import com.kunzisoft.keepass.database.element.DeletedObject
import com.kunzisoft.keepass.database.element.binary.BinaryCache
import com.kunzisoft.keepass.database.element.binary.BinaryData
import com.kunzisoft.keepass.database.element.database.DatabaseKDBX
import com.kunzisoft.keepass.database.element.entry.EntryKDBX
import com.kunzisoft.keepass.database.element.group.GroupKDBX
import com.kunzisoft.keepass.database.element.icon.IconImage
import com.kunzisoft.keepass.utils.readAllBytes

/**
 * Build the content of a KeeShare container from a shared group,
 * the same way as KeePassXC (ShareExport::extractIntoDatabase):
 * the shared group becomes the root, entries keep their history,
 * subgroups are kept with [KeeShareReference.keepGroups],
 * and the deleted objects of the source database are pushed to the container.
 */
object KeeShareExport {

    fun buildContainer(
        sourceDatabase: DatabaseKDBX,
        sharedGroup: GroupKDBX,
        keepGroups: Boolean,
        binaryCache: BinaryCache,
    ): DatabaseKDBX {
        val container = DatabaseKDBX(sharedGroup.title, sharedGroup.title).apply {
            this.binaryCache = binaryCache
            isRecycleBinEnabled = false
        }
        val containerRoot = container.rootGroup!!
        container.removeGroupIndex(containerRoot)
        containerRoot.updateWith(sharedGroup, updateParents = false)
        containerRoot.nodeId = sharedGroup.nodeId
        containerRoot.customData.remove(KeeShareReference.CUSTOM_DATA_KEY)
        container.addGroupIndex(containerRoot)

        val exporter = Exporter(sourceDatabase, container)
        exporter.copyIcon(containerRoot.icon)
        exporter.copyEntries(sharedGroup, containerRoot)
        if (keepGroups) {
            exporter.copyGroups(sharedGroup, containerRoot)
        }

        sourceDatabase.deletedObjects.forEach { deletedObject ->
            container.addDeletedObject(DeletedObject(deletedObject.uuid, deletedObject.deletionTime))
        }
        return container
    }

    // Bigger binaries are kept in the cache directory instead of memory
    private const val SMALL_BINARY_SIZE = 1024L * 1024L

    private class Exporter(
        private val source: DatabaseKDBX,
        private val container: DatabaseKDBX,
    ) {
        // Source attachment pool id to the binary already copied in the container
        private val copiedBinaries = mutableMapOf<Int, BinaryData>()

        fun copyGroups(sourceParent: GroupKDBX, containerParent: GroupKDBX) {
            sourceParent.getChildGroups().forEach { sourceGroup ->
                val group = GroupKDBX().apply {
                    updateWith(sourceGroup, updateParents = false)
                    // Never share the password of a nested share
                    customData.remove(KeeShareReference.CUSTOM_DATA_KEY)
                }
                container.addGroupTo(group, containerParent)
                copyIcon(group.icon)
                copyEntries(sourceGroup, group)
                copyGroups(sourceGroup, group)
            }
        }

        fun copyEntries(sourceGroup: GroupKDBX, containerGroup: GroupKDBX) {
            sourceGroup.getChildEntries().forEach { sourceEntry ->
                val entry = EntryKDBX().apply {
                    updateWith(sourceEntry, copyHistory = true, updateParents = false)
                }
                copyAttachments(entry)
                entry.history.forEach { historyEntry ->
                    copyAttachments(historyEntry)
                    copyIcon(historyEntry.icon)
                }
                copyIcon(entry.icon)
                container.addEntryTo(entry, containerGroup)
            }
        }

        /**
         * Attachments are referenced by pool id, which differs between databases
         */
        private fun copyAttachments(entry: EntryKDBX) {
            val binaries = LinkedHashMap(entry.binaries)
            entry.binaries.clear()
            binaries.forEach { (label, sourcePoolId) ->
                val sourceBinary = source.attachmentPool[sourcePoolId] ?: return@forEach
                val binary = copiedBinaries.getOrPut(sourcePoolId) {
                    container.buildNewBinaryAttachment(
                        sourceBinary.getSize() <= SMALL_BINARY_SIZE,
                        sourceBinary.isCompressed,
                        sourceBinary.isProtected
                    ).also { binaryData ->
                        sourceBinary.getInputDataStream(source.binaryCache).use { inputStream ->
                            binaryData.getOutputDataStream(container.binaryCache).use { outputStream ->
                                inputStream.readAllBytes { buffer ->
                                    outputStream.write(buffer)
                                }
                            }
                        }
                    }
                }
                entry.binaries[label] = container.attachmentPool.put(binary)
            }
        }

        fun copyIcon(icon: IconImage) {
            val customIcon = icon.custom
            if (customIcon.isUnknown || container.getCustomIcon(customIcon.uuid) != null)
                return
            source.iconsManager.doForEachCustomIcon { sourceIcon, sourceBinary ->
                if (sourceIcon.uuid == customIcon.uuid) {
                    container.addCustomIcon(
                        sourceIcon.uuid,
                        sourceIcon.name,
                        sourceIcon.lastModificationTime,
                        false
                    ) { _, binaryData ->
                        sourceBinary.getInputDataStream(source.binaryCache).use { inputStream ->
                            binaryData?.getOutputDataStream(container.binaryCache).use { outputStream ->
                                inputStream.readAllBytes { buffer ->
                                    outputStream?.write(buffer)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
