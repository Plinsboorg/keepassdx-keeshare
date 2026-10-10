package com.kunzisoft.keepass.activities.dialogs

import android.app.Dialog
import android.content.DialogInterface
import android.net.Uri
import android.os.Bundle
import android.widget.CheckBox
import android.widget.EditText
import android.widget.RadioGroup
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.core.os.bundleOf
import androidx.documentfile.provider.DocumentFile
import com.kunzisoft.keepass.R
import com.kunzisoft.keepass.activities.helpers.ExternalFileHelper
import com.kunzisoft.keepass.database.element.GroupId
import com.kunzisoft.keepass.database.keeshare.KeeShareReference
import com.kunzisoft.keepass.utils.UriUtil.takeUriPermission
import com.kunzisoft.keepass.utils.getParcelableCompat

/**
 * Link a group to a KeeShare container: the share type, the container file and its password.
 * The choice is sent back with a fragment result to [REQUEST_KEY].
 */
class KeeShareDialogFragment : DatabaseDialogFragment() {

    private var mExternalFileHelper: ExternalFileHelper? = null
    private var mContainerUri: Uri? = null
    private var mFileView: TextView? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        mExternalFileHelper = ExternalFileHelper(this).apply {
            // Opened documents get a persistent read and write permission
            buildOpenDocument { uri ->
                uri?.let { selectContainer(it) }
            }
            buildCreateDocument { uri ->
                uri?.let {
                    activity?.contentResolver?.takeUriPermission(it)
                    selectContainer(it)
                }
            }
        }
    }

    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        val activity = requireActivity()
        val arguments = requireArguments()
        val groupTitle = arguments.getString(ARG_GROUP_TITLE) ?: ""
        // Read from the database to not keep the password in the arguments
        val reference = arguments.getParcelableCompat<GroupId>(ARG_GROUP_ID)?.let { groupId ->
            mDatabaseViewModel.database?.getGroupById(groupId)?.let { group ->
                KeeShareReference.fromCustomData(group.customData)
            }
        }
        mContainerUri = savedInstanceState?.getParcelableCompat(KEY_CONTAINER_URI)
            ?: arguments.getParcelableCompat(ARG_CONTAINER_URI)

        val root = activity.layoutInflater.inflate(R.layout.fragment_keeshare, null)
        root.findViewById<TextView>(R.id.keeshare_title).text =
            getString(R.string.keeshare_group, groupTitle)
        val typeView = root.findViewById<RadioGroup>(R.id.keeshare_type)
        val passwordView = root.findViewById<EditText>(R.id.keeshare_password)
        val keepGroupsView = root.findViewById<CheckBox>(R.id.keeshare_keep_groups)
        mFileView = root.findViewById(R.id.keeshare_file)
        root.findViewById<TextView>(R.id.keeshare_choose_file).setOnClickListener {
            mExternalFileHelper?.openDocument()
        }
        root.findViewById<TextView>(R.id.keeshare_new_file).setOnClickListener {
            mExternalFileHelper?.createDocument("$groupTitle.kdbx")
        }

        if (savedInstanceState == null) {
            typeView.check(
                when (reference?.type) {
                    KeeShareReference.IMPORT_FROM -> R.id.keeshare_type_import
                    KeeShareReference.EXPORT_TO -> R.id.keeshare_type_export
                    else -> R.id.keeshare_type_synchronize
                }
            )
            passwordView.setText(reference?.password ?: "")
            keepGroupsView.isChecked = reference?.keepGroups ?: true
        }
        showContainerName()

        val builder = AlertDialog.Builder(activity)
            .setView(root)
            // Listener set after showing, to keep the dialog open without file
            .setPositiveButton(android.R.string.ok, null)
            .setNegativeButton(android.R.string.cancel, null)
        if (reference != null) {
            builder.setNeutralButton(R.string.keeshare_remove) { _, _ ->
                sendResult(bundleOf(RESULT_REMOVE to true))
            }
        }
        return builder.create().apply {
            setOnShowListener {
                getButton(DialogInterface.BUTTON_POSITIVE).setOnClickListener {
                    val containerUri = mContainerUri
                    if (containerUri == null) {
                        mFileView?.error = getString(R.string.keeshare_no_file)
                        return@setOnClickListener
                    }
                    sendResult(bundleOf(
                        RESULT_TYPE to when (typeView.checkedRadioButtonId) {
                            R.id.keeshare_type_import -> KeeShareReference.IMPORT_FROM
                            R.id.keeshare_type_export -> KeeShareReference.EXPORT_TO
                            else -> KeeShareReference.SYNCHRONIZE
                        },
                        RESULT_CONTAINER_URI to containerUri,
                        RESULT_CONTAINER_NAME to containerName(containerUri),
                        RESULT_PASSWORD to passwordView.text.toString(),
                        RESULT_KEEP_GROUPS to keepGroupsView.isChecked
                    ))
                    dismiss()
                }
            }
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putParcelable(KEY_CONTAINER_URI, mContainerUri)
    }

    private fun selectContainer(uri: Uri) {
        mContainerUri = uri
        mFileView?.error = null
        showContainerName()
    }

    private fun showContainerName() {
        mFileView?.text = mContainerUri?.let { containerName(it) }
            ?: getString(R.string.keeshare_no_file)
    }

    private fun containerName(uri: Uri): String {
        return try {
            DocumentFile.fromSingleUri(requireContext(), uri)?.name
        } catch (e: Exception) {
            null
        } ?: uri.lastPathSegment ?: uri.toString()
    }

    private fun sendResult(result: Bundle) {
        result.putParcelable(RESULT_GROUP_ID, requireArguments().getParcelableCompat<GroupId>(ARG_GROUP_ID))
        parentFragmentManager.setFragmentResult(REQUEST_KEY, result)
    }

    companion object {
        const val TAG = "KeeShareDialogFragment"
        const val REQUEST_KEY = "KEESHARE_REQUEST_KEY"

        const val RESULT_GROUP_ID = "RESULT_GROUP_ID"
        const val RESULT_REMOVE = "RESULT_REMOVE"
        const val RESULT_TYPE = "RESULT_TYPE"
        const val RESULT_CONTAINER_URI = "RESULT_CONTAINER_URI"
        const val RESULT_CONTAINER_NAME = "RESULT_CONTAINER_NAME"
        const val RESULT_PASSWORD = "RESULT_PASSWORD"
        const val RESULT_KEEP_GROUPS = "RESULT_KEEP_GROUPS"

        private const val ARG_GROUP_ID = "ARG_GROUP_ID"
        private const val ARG_GROUP_TITLE = "ARG_GROUP_TITLE"
        private const val ARG_CONTAINER_URI = "ARG_CONTAINER_URI"
        private const val KEY_CONTAINER_URI = "KEY_CONTAINER_URI"

        fun getInstance(
            groupId: GroupId,
            groupTitle: String,
            containerUri: Uri?,
        ): KeeShareDialogFragment {
            return KeeShareDialogFragment().apply {
                arguments = bundleOf(
                    ARG_GROUP_ID to groupId,
                    ARG_GROUP_TITLE to groupTitle,
                    ARG_CONTAINER_URI to containerUri
                )
            }
        }
    }
}
