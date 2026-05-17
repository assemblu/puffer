#pragma once
#include <windows.h>
#include <string>

struct EspConfig {
    // Globals (RVAs relative to client.dll base)
    uintptr_t dwLocalPlayerController = 0;
    uintptr_t dwViewMatrix = 0;
    uintptr_t dwEntityList = 0;

    // Controller offsets
    uintptr_t m_hPlayerPawn = 0;
    uintptr_t m_iPawnHealth = 0;
    uintptr_t m_bPawnIsAlive = 0;
    uintptr_t m_iPawnArmor = 0;

    // Entity offsets
    uintptr_t m_pGameSceneNode = 0;

    // Scene node offsets
    uintptr_t m_vecAbsOrigin = 0;
    uintptr_t m_vecOrigin = 0;

    // Entity list structure
    uint32_t chunkCount = 64;
    uint32_t entitiesPerChunk = 512;
    uintptr_t entryStride = 0x70;
    uintptr_t entityPtrOffset = 0x08;
    uintptr_t entityHandleOffset = 0x10;

    // Load config from JSON file. Returns true on success.
    bool Load(const wchar_t* path);

    // Validate that all critical offsets are non-zero.
    bool IsValid() const;
};
