//
// ExtGameAPI.h — Layer 3: External CODM data reader.
//
// Unlike the internal menu (which calls CODM functions directly),
// this reads IL2CPP data structures from CODM's memory via mach_vm_read.
//
// We can READ data (positions, health, team, bones) but can NOT call
// CODM functions (transforms, raycasts). Transform positions are read
// from the cached field in the transform component instead.
//

#pragma once

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    float x, y, z;
} ExtVec3;

typedef struct {
    float m[4][4];
} ExtMatrix4;

typedef struct {
    float x, y, z, w;
} ExtQuat;

typedef struct {
    ExtVec3   position;
    float     health;
    float     maxHealth;
    uint32_t  teamId;
    bool      isAlive;
    bool      isBot;
    bool      valid;
    uint16_t  nameUTF16[65];
    int       nameLen;
    ExtVec3   bones[16];
    bool      bonesValid;
} ExtEnemyData;

// Initialize — must be called after ext_attach().
void extgame_init(void);

// Per-frame update: reads the camera matrix + enemy list from CODM memory.
// Returns number of enemies found (0 if game not in match).
int extgame_update(void);

// Get the current view-projection matrix for WorldToScreen.
ExtMatrix4 extgame_get_vp_matrix(void);

// Get enemy data (index 0..extgame_update()-1).
const ExtEnemyData* extgame_get_enemy(int index);

// Get local player position.
ExtVec3 extgame_get_local_pos(void);

// Get local player team ID.
uint32_t extgame_get_local_team(void);

// WorldToScreen using the cached VP matrix.
// Returns false if behind camera.
bool extgame_w2s(ExtVec3 world, float *outX, float *outY);

#ifdef __cplusplus
}
#endif
