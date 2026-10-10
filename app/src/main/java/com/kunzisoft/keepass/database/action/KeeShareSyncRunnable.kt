package com.kunzisoft.keepass.database.action

import android.content.Context
import android.net.Uri
import android.os.Bundle
import androidx.documentfile.provider.DocumentFile
import com.kunzisoft.keepass.database.ContextualDatabase
import com.kunzisoft.keepass.database.element.GroupId
import com.kunzisoft.keepass.database.exception.KeeShareDatabaseException
import com.kunzisoft.keepass.hardware.HardwareKey
import com.kunzisoft.keepass.settings.PreferencesUtil
import com.kunzisoft.keepass.tasks.ActionRunnable
import com.kunzisoft.keepass.utils.AppUtil.getLimits
import com.kunzisoft.keepass.utils.getUriInputStream
import com.kunzisoft.keepass.utils.getUriOutputStream
import java.io.File
import java.io.FileNotFoundException

/**
 * Synchronize a KeeShare group with its linked container file,
 * the database is saved only if the import changed the group.
 */
class KeeShareSyncRunnable(
    private val context: Context,
    private val database: ContextualDatabase,
    private val groupId: GroupId,
    private val export: Boolean,
    private val challengeResponseRetriever: (HardwareKey, ByteArray?) -> ByteArray,
) : ActionRunnable() {

    override fun onActionRun() {
        val contentResolver = context.contentResolver
        val groupKey = groupId.toString()
        val containerUri = PreferencesUtil.getKeeShareContainerUri(context, groupKey)
            ?.let { Uri.parse(it) }
            ?: throw KeeShareDatabaseException("No file linked to the shared group")

        val containerInput = try {
            contentResolver.getUriInputStream(containerUri)
        } catch (e: FileNotFoundException) {
            // Can be created by the export
            if (!export) throw e
            null
        }
        val syncResult = database.synchronizeKeeShare(
            groupId = groupId,
            export = export,
            containerInput = containerInput,
            containerOutput = { contentResolver.getUriOutputStream(containerUri) },
            cacheDirectory = File(context.cacheDir, KEESHARE_CACHE_DIRECTORY),
            limits = context.getLimits()
        )

        // Not imported again until another device changes the container
        database.keeShareImportedVersions[groupKey] = lastModified(containerUri)
        // Not exported again until the group changes
        if (syncResult.exported) {
            database.keeShareContentSignature(groupId)?.let {
                database.keeShareExportedSignatures[groupKey] = it
            }
        }

        if (syncResult.importChangedGroup) {
            result.data = Bundle().apply { putBoolean(GROUP_CHANGED_KEY, true) }
            if (!database.isReadOnly) {
                val saveRunnable = SaveDatabaseRunnable(
                    context, database, true, null, challengeResponseRetriever
                )
                saveRunnable.run()
                if (!saveRunnable.result.isSuccess) {
                    result = saveRunnable.result
                }
            }
        }
    }

    private fun lastModified(uri: Uri): Long {
        return try {
            DocumentFile.fromSingleUri(context, uri)?.lastModified() ?: 0L
        } catch (e: Exception) {
            0L
        }
    }

    companion object {
        const val GROUP_CHANGED_KEY = "KEESHARE_GROUP_CHANGED_KEY"
        private const val KEESHARE_CACHE_DIRECTORY = "keeshare"
    }
}
