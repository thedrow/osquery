/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <augeas.h>

#include <boost/algorithm/string/join.hpp>

#include <osquery/logger.h>
#include <osquery/tables.h>

namespace osquery {

/**
 * @brief Augeas lenses path.
 *
 * Directory that contains augeus lenses.
 */
#ifdef __APPLE__
FLAG(string,
     augeas_lenses,
     "/private/var/osquery/lenses",
     "Directory that contains augeas lenses files");
#else
FLAG(string,
     augeas_lenses,
     "/usr/share/osquery/lenses",
     "Directory that contains augeas lenses files");
#endif

namespace tables {

void reportAugeasError(augeas* aug) {
  const char* error_message = aug_error_message(aug);
  VLOG(1) << "An error has occurred while trying to query augeas: "
          << error_message;
}

inline std::string getSpanInfo(augeas* aug,
                               const std::string& node,
                               size_t &idx) {
  char* filename = nullptr;
  int result = aug_ns_source(aug, "matches", idx, &filename);

  if (result == 0 && filename != nullptr) {
    std::string source = filename;
    // aug_ns_source() allocates the source and expects the caller to free it.
    free(filename);
    return source.substr(6);
  } else {
    return "";
  }
}

inline std::string getLabelInfo(augeas* aug,
                                const std::string& node,
                                const size_t &idx) {
  const char* label = nullptr;
  int result = aug_ns_label(aug, "matches", idx, &label);

  if (result == 1 && label != nullptr) {
    return label;
  } else {
    return "";
  }
}

void matchAugeasPattern(augeas* aug,
                        const std::string& pattern,
                        QueryData& results,
                        bool use_path = false) {
  // The caller may supply an Augeas PATH/NODE expression or filesystem path.
  // Below we formulate a Augeas pattern from a path if needed.
  aug_defvar(aug,
             "matches",
             (use_path ? ("/files/" + pattern + "|/files" + pattern + "//*").c_str() : pattern.c_str()));
  char** matches = nullptr;
  int len = aug_match(
      aug,
      "$matches",
      &matches);

  // Handle matching errors.
  if (matches == nullptr) {
    return;
  } else if (len < 0) {
    reportAugeasError(aug);
    return;
  }

  results.reserve(len);

  // Emit a row for each match.
  for (size_t i = 0; i < static_cast<size_t>(len); i++) {
    if (matches[i] == nullptr) {
      continue;
    }

    // The caller is responsible for the matching memory.
    std::string node(matches[i]);
    free(matches[i]);

    Row r;
    const char* value = nullptr;
    int result = aug_ns_get(aug, "matches", i, &value);
    if (result == 1) {
      r["node"] = node;

      if (value != nullptr) {
        r["value"] = value;
      }

      if (!use_path) {
        r["path"] = getSpanInfo(aug, node, i);
      } else {
        r["path"] = pattern;
      }

      r["label"] = getLabelInfo(aug, node, i);

      results.push_back(r);
    } else {
      reportAugeasError(aug);
    }
  }

  // aug_match() allocates the matches array and expects the caller to free it.
  free(matches);
}

QueryData genAugeas(QueryContext& context) {
  augeas* aug = aug_init(
      nullptr, FLAGS_augeas_lenses.c_str(), AUG_NO_ERR_CLOSE);

  // Handle initialization errors.
  if (aug == nullptr) {
    VLOG(1) << "An error has occurred while trying to initialize augeas";
    return {};
  } else if (aug_error(aug) != AUG_NOERROR) {
    // Do not use aug_error_details() here since augeas is not fully
    // initialized.
    VLOG(1) << "An error has occurred while trying to initialize augeas: "
            << aug_error_message(aug);
    aug_close(aug);
    return {};
  }

  QueryData results;
  if (context.hasConstraint("path", EQUALS)) {
    // Allow requests via filesystem path.
    // We will request the pattern match by path using an optional argument.
    auto paths = context.constraints["path"].getAll(EQUALS);
    for (const auto& path : paths) {
      matchAugeasPattern(aug, path, results, true);
    }
  } else if (context.hasConstraint("node", EQUALS)) {
    auto nodes = context.constraints["node"].getAll(EQUALS);
    auto pattern = boost::algorithm::join(nodes, "|");
    matchAugeasPattern(aug, pattern, results);
  } else {
    matchAugeasPattern(aug, "/files//*", results);
  }

  aug_close(aug);
  return results;
}
}
}
