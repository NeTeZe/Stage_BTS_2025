"""
file_processing.py

This module contains the main functions for handling and processing files.
It is designed to support operations such as reading, analyzing, filtering,
and moving files as part of a larger data pipeline or analysis workflow.

"""



# === TABLE === #

# === SMB2 ERROR DECODING TABLE === #
SMB2_ERRORS = {
    '0xc0000034': 'STATUS_OBJECT_NAME_NOT_FOUND',
    '0xc0000022': 'STATUS_ACCESS_DENIED',
    '0xc000000f': 'STATUS_NO_SUCH_FILE',
    '0xc000003a': 'STATUS_OBJECT_PATH_NOT_FOUND',
    '0xc0000061': 'STATUS_PRIVILEGE_NOT_HELD',
    '0x00000103': 'STATUS_PENDING',
    '0xc0000003': 'STATUS_INVALID_INFO_CLASS',
    '0x80000006': 'STATUS_NO_MORE_FILES',
    '0xc000019c': 'STATUS_FS_DRIVER_REQUIRED',
    '0xc0000023': 'STATUS_BUFFER_TOO_SMALL',
    '0xc0000120': 'STATUS_CANCELLED',
    '0xc00002b8': 'STATUS_JOURNAL_NOT_ACTIVE',
    '0xc0000225': 'STATUS_NOT_FOUND',
    '0x80000005': 'STATUS_BUFFER_OVERFLOW',
    '0x00000000': 'SUCCESS'
    # Add more if needed
}
# === SMB2 COMMAND MAPPING TABLE === #
SMB2_COMMANDS = {
    '0': 'NEGOTIATE',
    '1': 'SESSION_SETUP',
    '2': 'LOGOFF',
    '3': 'TREE_CONNECT',
    '4': 'TREE_DISCONNECT',
    '5': 'CREATE',
    '6': 'CLOSE',
    '7': 'FLUSH',
    '8': 'READ',
    '9': 'WRITE',
    '10': 'LOCK',
    '11': 'IOCTL',
    '12': 'CANCEL',
    '13': 'ECHO', 
    '14': 'FIND',          # ou QUERY_DIRECTORY
    '15': 'NOTIFY',
    '16': 'GETINFO',
    '17': 'SETINFO',
    '18': 'BREAK'
    # Add more if needed
}