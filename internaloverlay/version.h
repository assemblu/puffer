#pragma once

// ------------------------------------------------------------------
//  Version macros â€“ the build number (fourth field) will be bumped
//  automatically by a preâ€‘build script.
// ------------------------------------------------------------------
#define VERSION_MAJOR   1
#define VERSION_MINOR   0
#define VERSION_BUILD   3

// Helper to turn the numeric macros into a string (optional)
#define STRINGIFY_IMPL(x) #x
#define STRINGIFY(x) STRINGIFY_IMPL(x)
#define VERSION_STRING  STRINGIFY(VERSION_MAJOR) "." STRINGIFY(VERSION_MINOR) "." STRINGIFY(VERSION_BUILD)



