```cpp
/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 2005-2025 Hex-Rays SA <support@hex-rays.com>
 *      ALL RIGHTS RESERVED.
 *
 *      Undo functionality.
 *
 *      Glossary:
 *
 *         undo point:  a point in the undo history to which it is possible
 *                      to return.
 *         undo record: record in the undo history about one chunk of a change.
 *                      each record has an undo code, which determines the nature
 *                      of the change and the undo handler.
 *
 */

#ifndef _UNDO_HPP
#define _UNDO_HPP

/// Create a new restore point.
/// The user can undo to this point in the future.
/// \param bytes     body of the record for UNDO_ACTION_START
/// \param size      size of the record for UNDO_ACTION_START
/// \return success; fails if undo is disabled
idaman bool ida_export create_undo_point(const uchar *bytes, size_t size);

/// Get the label of the action that will be undone.
/// This function returns the text that can be displayed in the undo menu
/// \return success
idaman bool ida_export get_undo_action_label(qstring *action_to_be_undone);

/// Get the label of the action that will be redone.
/// This function returns the text that can be displayed in the redo menu
/// \return success
idaman bool ida_export get_redo_action_label(qstring *action_to_be_redone);

/// Perform undo.
/// \return success
idaman bool ida_export perform_undo();

/// Perform redo.
/// \return success
idaman bool ida_export perform_redo();

#endif // _UNDO_HPP

```
