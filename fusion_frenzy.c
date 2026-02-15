#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include "cJSON.h"

#define DEBUG

#ifdef DEBUG
#include <time.h>
#define SPAM
#endif

#ifdef _WIN32
// Set Windows Vista or later for condition variable support
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600  // Windows Vista
#endif
#ifndef WINVER
#define WINVER 0x0600
#endif

#include <windows.h>
#include <process.h>
#define A_THREAD HANDLE
#define THREAD_RETURN_TYPE DWORD WINAPI
#define THREAD_CREATE(thread, func, arg) (thread = CreateThread(NULL, 0, func, arg, 0, NULL))
#define THREAD_JOIN(thread) WaitForSingleObject(thread, INFINITE)
#define THREAD_EXIT(value) ExitThread((DWORD)value)
#define MUTEX CRITICAL_SECTION
#define MUTEX_INIT(mutex) InitializeCriticalSection(mutex)
#define MUTEX_LOCK(mutex) EnterCriticalSection(mutex)
#define MUTEX_TRYLOCK(mutex) TryEnterCriticalSection(mutex)
#define MUTEX_UNLOCK(mutex) LeaveCriticalSection(mutex)
#define MUTEX_DESTROY(mutex) DeleteCriticalSection(mutex)

#ifndef CONDITION_VARIABLE // Fallback for older Windows versions without condition variable support
typedef HANDLE CONDITION_VARIABLE; // treat as a HANDLE for the fallback
#define CONDITION_VAR HANDLE
#define COND_INIT(cond) do { *(cond) = CreateEvent(NULL, FALSE, FALSE, NULL); } while(0)
#define COND_WAIT(cond, mutex) do { LeaveCriticalSection(mutex); WaitForSingleObject(*(cond), INFINITE); EnterCriticalSection(mutex); } while(0)
#define COND_SIGNAL(cond) SetEvent(*(cond))
#define COND_BROADCAST(cond) SetEvent(*(cond))
#define COND_DESTROY(cond) do { if (*(cond)) CloseHandle(*(cond)); } while(0)
#else // Use native condition variables
#define CONDITION_VAR CONDITION_VARIABLE
#define COND_INIT(cond) InitializeConditionVariable(cond)
#define COND_WAIT(cond, mutex) SleepConditionVariableCS(cond, mutex, INFINITE)
#define COND_SIGNAL(cond) WakeConditionVariable(cond)
#define COND_BROADCAST(cond) WakeAllConditionVariable(cond)
#define COND_DESTROY(cond) /* No destroy needed */
#endif

#ifndef SRWLOCK_MISSING // Fallback for older Windows versions without SRWLOCK support
typedef struct { CRITICAL_SECTION cs; int readers; CONDITION_VARIABLE cond; } RWLOCK; // simple reader-writer lock using critical section and condition variable
#define RW_INIT(lock) do { InitializeCriticalSection(&((lock)->cs)); (lock)->readers = 0; COND_INIT(&((lock)->cond)); } while(0)
#define RW_RDLOCK(lock) do { EnterCriticalSection(&((lock)->cs)); while ((lock)->readers < 0) COND_WAIT(&((lock)->cond), &((lock)->cs)); (lock)->readers++; LeaveCriticalSection(&((lock)->cs)); } while(0)
#define RW_WRLOCK(lock) do { EnterCriticalSection(&((lock)->cs)); while ((lock)->readers != 0) COND_WAIT(&((lock)->cond), &((lock)->cs)); (lock)->readers = -1; LeaveCriticalSection(&((lock)->cs)); } while(0)
#define RW_UNLOCK(lock) do { EnterCriticalSection(&((lock)->cs)); if ((lock)->readers == -1) (lock)->readers = 0; else (lock)->readers--; COND_BROADCAST(&((lock)->cond)); LeaveCriticalSection(&((lock)->cs)); } while(0)
#define RW_DESTROY(lock) do { DeleteCriticalSection(&((lock)->cs)); COND_DESTROY(&((lock)->cond)); } while(0)
#else // Use native SRW locks
#define RWLOCK SRWLOCK
#define RW_INIT(lock) InitializeSRWLock(lock)
#define RW_RDLOCK(lock) AcquireSRWLockShared(lock)
#define RW_WRLOCK(lock) AcquireSRWLockExclusive(lock)
#define RW_UNLOCK(lock) ReleaseSRWLockShared(lock)  // Works for both; SRW automatically knows
#define RW_DESTROY(lock) /* no-op */
#endif

#else // POSIX
#include <pthread.h>
#include <unistd.h>
#include <sys/sysinfo.h>
#include <stdint.h>
#define A_THREAD pthread_t
#define THREAD_RETURN_TYPE void*
#define THREAD_CREATE(thread, func, arg) pthread_create(&thread, NULL, func, arg)
#define THREAD_JOIN(thread) pthread_join(thread, NULL)
#define THREAD_EXIT(value) pthread_exit((void*)(size_t)value)
#define MUTEX pthread_mutex_t
#define MUTEX_INIT(mutex) pthread_mutex_init(&(mutex), NULL)
#define MUTEX_LOCK(mutex) pthread_mutex_lock(&(mutex))
#define MUTEX_TRYLOCK(mutex) pthread_mutex_trylock(&(mutex))
#define MUTEX_UNLOCK(mutex) pthread_mutex_unlock(&(mutex))
#define MUTEX_DESTROY(mutex) pthread_mutex_destroy(&(mutex))
#define CONDITION_VAR pthread_cond_t
#define COND_INIT(cond) pthread_cond_init(&(cond), NULL)
#define COND_WAIT(cond, mutex) pthread_cond_wait(&(cond), &(mutex))
#define COND_SIGNAL(cond) pthread_cond_signal(&(cond))
#define COND_BROADCAST(cond) pthread_cond_broadcast(&(cond))
#define COND_DESTROY(cond) pthread_cond_destroy(&(cond))
#define RWLOCK pthread_rwlock_t
#define RW_INIT(lock) pthread_rwlock_init(&(lock), NULL)
#define RW_RDLOCK(lock) pthread_rwlock_rdlock(&(lock))
#define RW_WRLOCK(lock) pthread_rwlock_wrlock(&(lock))
#define RW_UNLOCK(lock) pthread_rwlock_unlock(&(lock))
#define RW_DESTROY(lock) pthread_rwlock_destroy(&(lock))
#endif

#ifdef __GNUC__   // MinGW or Cygwin GCC
#define SYNC_ADD(ptr, val) __sync_fetch_and_add((volatile UINT32*)(ptr), (UINT32)(val))
#define SYNC_AND(ptr, val) __sync_fetch_and_and((volatile UINT32*)(ptr), (UINT32)(val))
#define SYNC_OR(ptr, val)  __sync_fetch_and_or((volatile UINT32*)(ptr), (UINT32)(val))
#else              // MSVC
#define SYNC_ADD(ptr, val) InterlockedExchangeAdd((volatile LONG*)(ptr), (LONG)(val))
#define SYNC_AND(ptr, val) InterlockedAnd((volatile LONG*)(ptr), (LONG)(val))
#define SYNC_OR(ptr, val)  InterlockedOr((volatile LONG*)(ptr), (LONG)(val))
#endif

#define MAX_DEMONS 687
#define MAX_RACES 41
#define MAX_COMPONENTS 3
#define MAX_FUSIONS 6
#define ELEMENTALS 4
#define BITSET_WORDS ((MAX_DEMONS + sizeof(void*) - 1) / sizeof(void*)) // number of words needed to represent MAX_DEMONS bits

#define COMPONENT_COUNT(demon_id, fusion_index) (all_demons[demon_id].fusions[fusion_index].demon_components ? all_demons[demon_id].fusions[fusion_index].component_count : 2)
#define ERR_LOG(...) do { fprintf(stderr, __VA_ARGS__); fflush(stderr); } while(0)
#define ERR_EXIT(...) do { ERR_LOG(__VA_ARGS__); exit(EXIT_FAILURE); } while(0)
#define BITMASK_TEST(bm, id) ((bm)->bits[(id) / (sizeof(void*) * 8)] & (1L << ((id) % (sizeof(void*) * 8))))
#define BITMASK_SET_ALL(bm) do { for (int i = 0; i < BITSET_WORDS; i++) (bm)->bits[i] = ~0L; } while(0)
#define BITMASK_CLEAR(bm, id) do { (bm)->bits[(id) / (sizeof(void*) * 8)] &= ~(1L << ((id) % (sizeof(void*) * 8))); } while(0)
#define BITMASK_AND(dest, src) do { for (int i = 0; i < BITSET_WORDS; i++) (dest)->bits[i] &= (src)->bits[i]; } while(0)
#define BITMASK_OR(dest, src) do { for (int i = 0; i < BITSET_WORDS; i++) (dest)->bits[i] |= (src)->bits[i]; } while(0)
#ifdef DEBUG
#define DEBUG_LOG(...) do { fprintf(debug_file, __VA_ARGS__); fflush(debug_file); } while(0)
#ifdef SPAM
#define SPAM_LOG(...) do { fprintf(debug_file, __VA_ARGS__); fflush(debug_file); } while(0)
#define THREAD_LOG(thread_file, ...) do { fprintf(thread_file, __VA_ARGS__); fflush(thread_file); SPAM_LOG(__VA_ARGS__); } while(0)
#else
#define SPAM_LOG(...) do {} while(0)
#define THREAD_LOG(thread_file, ...) do {} while(0)
#endif
#else
#define DEBUG_LOG(...) do {} while(0)
#define SPAM_LOG(...) do {} while(0)
#define THREAD_LOG(thread_file, ...) do {} while(0)
#endif

// Forward declarations
typedef struct Demon Demon;
typedef struct WorkItem WorkItem;

// Data structures

// A possible fusion for a demon
typedef struct {
	unsigned char min_level; // level range for regular fusions
	unsigned char max_level; // level range for regular fusions
	Demon** demon_components;  // component demons of this fusion set to null when not a special fusion
	char component_count; // number of components, Overloaded with race when racial fusing to make elementals
} Fusion;

// Fusion tree node
typedef struct FusionNode {
	int demon_id; // created demon id
	struct FusionNode** components;  // different components for this fusion (null for leaf nodes)
	char component_count; // number of demon components (0 for leaf nodes)
	int demon_count; // total demons in this fusion subtree (including self)
	int fusion_count; // total fusions in this fusion subtree (0 for leaf nodes)
} FusionNode;

// Group of demons used as anchors for elemental fusions
typedef struct {
	Demon** demons; // demons in this racial group
	char demon_count; // number of demons in this group
	bool is_anchor; // whether this group is an anchor group
} AnchorGroup;

// Collection of anchor groups for a race
typedef struct {
	AnchorGroup* groups; // collection of anchor groups
	char group_count; // number of anchor groups
} RaceAnchors;

typedef struct ParentWRef {
	WorkItem* parent; // parent work item
	int ref_count; // reference count for this parent
} ParentWRef;

typedef struct {
	volatile UINT32 bits[BITSET_WORDS]; // bitmask for available demons
} Bitmask;

// Work item for the queue
typedef struct WorkItem {
	int demon_id; // demon to process
	Bitmask available_demons; // bitmask for which demons are still available for processing this work item
	int depth; // current depth
	FusionNode* result; // pointer to where to store the result
	RWLOCK result_rwlock; // rwlock to protect result access
	char processed; // where in the processing we are (0 for not started, 1 for processing, 2 for done)
	ParentWRef parent[MAX_DEMONS]; // parents work items (for pruning)
	MUTEX parent_mutex; // mutex to protect parent data
	struct WorkItem*** children; // child work items [fusion][component]
	int fusion_count; // number of fusions (component count is calculated from demon data)
	RWLOCK child_rwlock; // rwlock to protect child data
	int best_fusion_count; // best fusion count found so far
	RWLOCK best_fusion_count_rwlock; // rwlock to protect best_fusion_count updates
} WorkItem;

typedef struct Demon {
	char race; // race of the demon
	unsigned char level; // level of the demon
	Fusion* fusions;  // Possible fusions for this demon
	char fusion_count; // number of fusions available
	WorkItem* work_item; // work item for this demon
	RWLOCK work_rwlock; // mutex to protect work item
	AnchorGroup* anchor_group; // anchor group this demon belongs to
} Demon;

// Collection of demons in a race
typedef struct {
	Demon** demons; // demons of this race
	int count; // number of demons in this race
} RaceArray;

// Work queue for thread pool
typedef struct {
	WorkItem* items[MAX_DEMONS]; // we will at most ever process MAX_DEMONS
	int front;
	int rear;
	int count;
	MUTEX queue_mutex;
	CONDITION_VAR queue_not_empty;
	bool shutdown;
} WorkQueue;

// Worker thread context
typedef struct {
	A_THREAD thread;
	int id;
	WorkQueue* queue;
} Worker;

// Global variables
static RaceArray demons_by_race[MAX_RACES];
static Demon all_demons[MAX_DEMONS];
static char race_fusions[MAX_RACES][MAX_RACES];
static char elemental_chart[ELEMENTALS][MAX_RACES];
static bool base_demons[MAX_DEMONS];
static const Demon* elemental_ids[ELEMENTALS];
static RaceAnchors race_anchors[MAX_RACES];
static int target_demon_id;

// Thread pool and work queue
static Worker* workers;
static int num_workers;
static WorkQueue* work_queue;

// Work depth limit for BFS levels
static volatile int work_depth_limit = 0; // current maximum depth being processed
static volatile int active_work_items[MAX_DEMONS / 2];
static MUTEX active_work_mutex;
static CONDITION_VAR work_depth_cond;
static MUTEX solution_mutex;
static CONDITION_VAR solution_cond;

#ifdef DEBUG
static volatile int total_work_items = 0;
static volatile int processed_work_items = 0;
static volatile int pruned_branches = 0;
static FILE* debug_file;
static time_t start_time;
#ifdef SPAM
#endif
#endif

// forward declarations of functions
static void update_this_work(WorkItem* work);

// File operations
static FILE* my_fopen(const char* filename, const char* mode) {
	FILE* file = fopen(filename, mode);
	if (!file) {
		perror("Failed to open file");
		return NULL;
	}
	return file;
}

static cJSON* load_json(const char* filename) {
	FILE* file = my_fopen(filename, "r");
	if (!file) return NULL;
	fseek(file, 0, SEEK_END);
	const long length = ftell(file);
	fseek(file, 0, SEEK_SET);
	char* data = (char*)malloc(length + 1);
	if (data == NULL) {
        fclose(file);
        return NULL;
    }
	fread(data, 1, length, file);
	fclose(file);
	data[length] = '\0';
	cJSON* json = cJSON_Parse(data);
	free(data);
	if (!json) {
		const char* error_ptr = cJSON_GetErrorPtr();
		ERR_EXIT("JSON parsing failed. Error before: %s\n", error_ptr ? error_ptr : "unknown error");
	}
	return json;
}

static void quick_sort_demons_by_level(Demon** arr, const int left, const int right) {
	if (left < right) {
		Demon* pivot = arr[right];
		int i = left - 1;
		for (int j = left; j < right; j++) {
			if (arr[j]->level <= pivot->level) {
				i++;
				Demon* temp = arr[i];
				arr[i] = arr[j];
				arr[j] = temp;
			}
		}
		Demon* temp = arr[i + 1];
		arr[i + 1] = arr[right];
		arr[right] = temp;
		int pivot_index = i + 1;
		quick_sort_demons_by_level(arr, left, pivot_index - 1);
		quick_sort_demons_by_level(arr, pivot_index + 1, right);
	}
}

static void add_demon_fusion(Demon* demon, const Fusion fusion) {
	if (demon->fusion_count >= MAX_FUSIONS) {
		ERR_LOG("Warning: Attempted to add fusion to demon ID %d, but it already has maximum fusions\n", (int)(demon - all_demons));
		return;
	}
	demon->fusions = (Fusion*)realloc(demon->fusions, (demon->fusion_count + 1) * sizeof(Fusion));
	if (!demon->fusions) {
		ERR_EXIT("Error: Failed to allocate memory for demon fusions\n");
	}
	SPAM_LOG("Adding fusion to demon ID: %d, fusion count now: %d\n", (int)(demon - all_demons), demon->fusion_count + 1);
	demon->fusions[demon->fusion_count++] = fusion;
}

static void free_fusion_node(FusionNode* node) {
	if (!node) return;
	if (node->components) {
		for (int i = 0; i < node->component_count; i++) {
			free_fusion_node(node->components[i]);
		}
		free(node->components);
		node->components = NULL;
	}
	free(node);
}

static void free_demon_resources(Demon* demon) {
	if (!demon) return;
	if (demon->fusions) {
		for (int i = 0; i < demon->fusion_count; i++) {
			if (demon->fusions[i].demon_components) {
				free(demon->fusions[i].demon_components);
			}
		}
		free(demon->fusions);
		demon->fusions = NULL;
	}
}

static void load_demons(const char* filename) {
	cJSON* json = load_json(filename);
	if (!json) return;
	cJSON* demon_entry;
#ifdef SPAM
	int demon_count = 0;
#endif
	cJSON_ArrayForEach(demon_entry, json) {
		const int demon_id = atoi(demon_entry->string);
		SPAM_LOG("Loading demon ID: %d\n", demon_id);
		if (demon_id < 0 || demon_id >= MAX_DEMONS) {
			printf("Warning: Demon ID %d out of bounds\n", demon_id);
			continue;
		}
		cJSON* race = cJSON_GetObjectItem(demon_entry, "race");
		cJSON* level = cJSON_GetObjectItem(demon_entry, "level");
		cJSON* fuse_able = cJSON_GetObjectItem(demon_entry, "fuse_able");
		Demon* this_demon = &all_demons[demon_id];
		RW_INIT(&this_demon->work_rwlock);
		this_demon->race = (char)(race ? race->valueint : 0);
		this_demon->level = (unsigned char)(level ? level->valueint : 0);
		this_demon->fusions = NULL;
		this_demon->fusion_count = 0;
		this_demon->work_item = NULL;
		this_demon->anchor_group = NULL;
#ifdef SPAM
		demon_count++;
#endif
		if (this_demon->race >= 0 && this_demon->race < MAX_RACES) {
			demons_by_race[this_demon->race].demons = (Demon**)realloc(demons_by_race[this_demon->race].demons, (demons_by_race[this_demon->race].count + 1) * sizeof(Demon*));
			if (!demons_by_race[this_demon->race].demons) {
				ERR_EXIT("Error: Failed to allocate memory for demons by race\n");
			}
			demons_by_race[this_demon->race].demons[demons_by_race[this_demon->race].count++] = this_demon;
		}
		if (!(fuse_able && fuse_able->valueint)) continue;
		cJSON* special_fusion = cJSON_GetObjectItem(demon_entry, "special_fusion");
		if (special_fusion && cJSON_IsArray(special_fusion)) {
			SPAM_LOG("Demon %d has special fusions\n", demon_id);
			cJSON* recipe;
			cJSON_ArrayForEach(recipe, special_fusion) {
				if (this_demon->fusion_count >= MAX_FUSIONS) {
					printf("Warning: Too many fusions for demon %d\n", demon_id);
					break;
				}
				Fusion this_fusion;
				this_fusion.component_count = cJSON_GetArraySize(recipe);
				if (this_fusion.component_count > MAX_COMPONENTS) {
					printf("Warning: Too many components in special fusion for demon %d\n", demon_id);
					continue;
				}
				this_fusion.demon_components = (Demon**)malloc(this_fusion.component_count * sizeof(Demon*));
				if (!this_fusion.demon_components) {
					ERR_EXIT("Error: Failed to allocate memory for fusion components\n");
				}
				cJSON* component;
				char index = 0;
				cJSON_ArrayForEach(component, recipe) {
					const int comp_id = component->valueint;
					if (comp_id < 0 || comp_id >= MAX_DEMONS) {
						ERR_LOG("Warning: demon_id for component is out of bounds: %d\n", comp_id);
						free(this_fusion.demon_components);
						continue;
					}
					this_fusion.demon_components[index] = &all_demons[comp_id];
					index++;
				}
				SPAM_LOG("Adding special fusion for demon %d with %d components\n", demon_id, this_fusion.component_count);
				add_demon_fusion(this_demon, this_fusion);
			}
		} else {
			cJSON* racial_fusion = cJSON_GetObjectItem(demon_entry, "racial_fusion");
			if (racial_fusion && cJSON_IsArray(racial_fusion)) {
				cJSON* recipe;
				cJSON_ArrayForEach(recipe, racial_fusion) {
					if (this_demon->fusion_count >= MAX_FUSIONS) {
						printf("Warning: Too many fusions for demon %d\n", demon_id);
						break;
					}
					Fusion this_fusion;
					this_fusion.demon_components = NULL;
					cJSON* race_item = cJSON_GetArrayItem(recipe, 0);
					if (!(race_item && race_item->type == cJSON_Number)) {
						printf("Warning: Invalid race item in racial fusion for demon %d\n", demon_id);
						continue;
					}
					this_fusion.component_count = (char)race_item->valueint;
					SPAM_LOG("Adding racial fusion for demon %d with race %d\n", demon_id, this_fusion.component_count);
					add_demon_fusion(this_demon, this_fusion);
				}
			} else {
				cJSON* min_level = cJSON_GetObjectItem(demon_entry, "min_level");
				cJSON* max_level = cJSON_GetObjectItem(demon_entry, "max_level");
				if (!(min_level && max_level)) {
					printf("Warning: Demon %d supposedly fuse able, however no fusions found\n", demon_id);
					continue;
				}
				Fusion this_fusion;
				this_fusion.min_level = (unsigned char)min_level->valueint;
				this_fusion.max_level = (unsigned char)max_level->valueint;
				this_fusion.demon_components = NULL;
				this_fusion.component_count = -1;
				SPAM_LOG("Adding regular fusion for demon %d with level range %d-%d\n", demon_id, this_fusion.min_level, this_fusion.max_level);
				add_demon_fusion(this_demon, this_fusion);
			}
		}
	}
	for (int i = 0; i < MAX_RACES; i++) {
		if (demons_by_race[i].count > 1) {
			quick_sort_demons_by_level(demons_by_race[i].demons, 0, demons_by_race[i].count - 1);
		}
	}
	cJSON_Delete(json);
	printf("Successfully loaded demons\n");
	DEBUG_LOG("Total demons loaded: %d\n", demon_count);
}

static void load_race_fusions(const char* filename) {
	for (int i = 0; i < MAX_RACES; i++) {
		for (int j = 0; j < MAX_RACES; j++) {
			race_fusions[i][j] = -1;
		}
	}
	cJSON* root = load_json(filename);
	if (!root) return;
	cJSON* race_item;
#ifdef SPAM
	int race_fusion_count = 0;
#endif
	cJSON_ArrayForEach(race_item, root) {
		const char* key = race_item->string;
		const char result_race = (char)atoi(key);
		if (!(result_race >= 0 && result_race < MAX_RACES)) {
			printf("Warning: resultant race %d is outside of range %d\n", result_race, MAX_RACES);
			continue;
		}
		cJSON* pair_item;
		cJSON_ArrayForEach(pair_item, race_item) {
			cJSON* first = cJSON_GetArrayItem(pair_item, 0);
			cJSON* second = cJSON_GetArrayItem(pair_item, 1);
			if (!(first && second && cJSON_IsNumber(first) && cJSON_IsNumber(second))) {
				printf("Warning: unhandled error while trying to load races\n");
				continue;
			}
			const char race1 = (char)first->valueint;
			const char race2 = (char)second->valueint;
			if (!(race1 >= 0 && race1 < MAX_RACES && race2 >= 0 && race2 < MAX_RACES)) {
				printf("Warning: races %d, %d are outside of range %d\n", race1, race2, MAX_RACES);
				continue;
			}
#ifdef SPAM
			race_fusion_count++;
			SPAM_LOG("Loading race fusion: %d + %d -> %d\n", race1, race2, result_race);
#endif
			if (race1 < race2) {
				race_fusions[result_race][race1] = race2;
			} else {
				race_fusions[result_race][race2] = race1;
			}
		}
	}
	cJSON_Delete(root);
	DEBUG_LOG("Total race fusions loaded: %d\n", race_fusion_count);
}

static void load_elemental_chart(const char* filename) {
	for (int i = 0; i < ELEMENTALS; i++) {
		for (int j = 0; j < MAX_RACES; j++) {
			elemental_chart[i][j] = 0;
		}
	}
	cJSON* root = load_json(filename);
	if (!root) return;
	char elemental_count = 0;
	cJSON* elemental_data = NULL;
#ifdef SPAM
	int elemental_load_count = 0;
#endif
	cJSON_ArrayForEach(elemental_data, root) {
		if (elemental_count >= ELEMENTALS) {
			printf("Warning: attempted to load too many elementals\n");
			break;
		}
		elemental_ids[elemental_count] = &all_demons[atoi(elemental_data->string)];
		cJSON* race_item = NULL;
		cJSON_ArrayForEach(race_item, elemental_data) {
			const int race_id = atoi(race_item->string);
			if (race_id < 0 || race_id >= MAX_RACES) {
				printf("Warning: attempted to load race value %d that is out of bounds of %d\n", race_id, MAX_RACES);
				continue;
			}
			if (!(cJSON_IsBool(race_item))) {
				printf("Warning: attempted to load non-bool value as bool value from elemental chart\n");
				continue;
			}
			elemental_chart[elemental_count][race_id] = cJSON_IsTrue(race_item) ? -1 : 1;
#ifdef SPAM
			elemental_load_count++;
			SPAM_LOG("Loaded elemental chart data: Elemental %d, Race %d, Value %d\n", elemental_count, race_id, elemental_chart[elemental_count][race_id]);
#endif
		}
		elemental_count++;
	}
	cJSON_Delete(root);
	DEBUG_LOG("Loaded elemental chart with %d elementals and %d total entries\n", elemental_count, elemental_load_count);
}

static void load_race_anchors(const char* filename) {
	cJSON* root = load_json(filename);
	if (!root) return;
	cJSON* race_item = NULL;
#ifdef SPAM
	int race_anchor_count = 0;
#endif
	cJSON_ArrayForEach(race_item, root) {
		const char* race_key = race_item->string;
		const char race_id = atoi(race_key);
		if (race_id < 0 || race_id >= MAX_RACES) {
			printf("Warning: Race ID %d out of bounds in anchor file\n", race_id);
			continue;
		}
		const char group_count = cJSON_GetArraySize(race_item);
		AnchorGroup* groups = (AnchorGroup*)malloc(group_count * sizeof(AnchorGroup));
		if (!groups) {
			ERR_EXIT("Error: Failed to allocate memory for anchor groups\n");
		}
		RaceAnchors* this_anchor = (RaceAnchors*)&race_anchors[race_id];
		this_anchor->groups = groups;
		this_anchor->group_count = group_count;
		for (int i = 0; i < group_count; i++) {
			cJSON* group_item = cJSON_GetArrayItem(race_item, i);
			cJSON* demons_array = cJSON_GetObjectItem(group_item, "demons");
			cJSON* anchor_item = cJSON_GetObjectItem(group_item, "anchor");
			const char demon_count = cJSON_GetArraySize(demons_array);
			groups[i].demon_count = demon_count;
			groups[i].demons = (Demon**)malloc(demon_count * sizeof(Demon*));
			groups[i].is_anchor = (anchor_item && cJSON_IsTrue(anchor_item)) ? true : false;
#ifdef SPAM
			race_anchor_count++;
#endif
			for (int j = 0; j < demon_count; j++) {
				const int demon_id = cJSON_GetArrayItem(demons_array, j)->valueint;
				if (demon_id < 0 || demon_id >= MAX_DEMONS) {
					printf("Warning: Demon ID %d out of bounds in anchor group for race %d\n", demon_id, race_id);
					groups[i].demons[j] = NULL;
					continue;
				}
				Demon* demon = &all_demons[demon_id];
				groups[i].demons[j] = demon;
				demon->anchor_group = &groups[i];
				SPAM_LOG("Loaded race anchor: Race %d, Group %d, Demon %d\n", race_id, i, demon_id);
				if (demon->race != race_id) {
					printf("Warning: Demon %d (race %d) placed in wrong race anchor group %d\n", demon_id, demon->race, race_id);
				}
			}
		}
	}
	cJSON_Delete(root);
	DEBUG_LOG("Total race anchor groups loaded: %d\n", race_anchor_count);
}

static FusionNode* create_fusion_node(const int demon_id, const char component_count, FusionNode** components) {
	FusionNode* node = (FusionNode*)malloc(sizeof(FusionNode));
	if (!node) {
		ERR_EXIT("Error: Failed to allocate memory for fusion node\n");
	}
	node->demon_id = demon_id;
	node->component_count = component_count;
	node->demon_count = 1;
	node->fusion_count = 0;
	if (component_count > 0 && components) {
		node->components = (FusionNode**)malloc(component_count * sizeof(FusionNode*));
		if (!node->components) {
			ERR_EXIT("Error: Failed to allocate memory for fusion node components\n");
		}
		for (char i = 0; i < component_count; i++) {
			node->components[i] = components[i];
			node->demon_count += components[i]->demon_count;
			node->fusion_count += components[i]->fusion_count;
		}
		node->fusion_count++; // count this fusion
	} else {
		node->components = NULL;
	}
	return node;
}

static WorkItem* create_work_item(int demon_id, const Bitmask* available_demons, int depth) {
	WorkItem* work = (WorkItem*)malloc(sizeof(WorkItem));
	if (!work) {
		ERR_EXIT("Error: Failed to allocate memory for work item\n");
	}
	work->demon_id = demon_id;
	work->available_demons = *available_demons;
	work->depth = depth;
	work->result = NULL;
	RW_INIT(&work->result_rwlock);
	work->processed = 0;
	MUTEX_INIT(&work->parent_mutex);
	memset(work->parent, 0, sizeof(ParentWRef) * MAX_DEMONS);
	work->children = NULL;
	work->fusion_count = 0;
	RW_INIT(&work->child_rwlock);
	RW_INIT(&work->best_fusion_count_rwlock);
	work->best_fusion_count = MAX_DEMONS;
	/* publish work_item after fully initializing the WorkItem to avoid races */
	RW_WRLOCK(&all_demons[demon_id].work_rwlock);
	if (all_demons[demon_id].work_item) {
		/* another thread created a work item for this demon concurrently */
		SPAM_LOG("Concurrent work item creation detected for demon ID %d, merging available demons\n", demon_id);
		BITMASK_AND(&work->available_demons, &all_demons[demon_id].work_item->available_demons); // merge available demons
		RW_UNLOCK(&all_demons[demon_id].work_rwlock);
		RW_DESTROY(&work->result_rwlock);
		MUTEX_DESTROY(&work->parent_mutex);
		RW_DESTROY(&work->child_rwlock);
		free(work);
		return all_demons[demon_id].work_item;
	}
	all_demons[demon_id].work_item = work;
	RW_UNLOCK(&all_demons[demon_id].work_rwlock);
	SPAM_LOG("Enqueuing work for demon ID: %d at depth %d\n", work->demon_id, work->depth);
	MUTEX_LOCK(&work_queue->queue_mutex); // lock queue to safely enqueue work
	if (work_queue->shutdown) {
		MUTEX_UNLOCK(&work_queue->queue_mutex);
		THREAD_LOG(debug_file, "Work queue is shutting down, cannot enqueue work for demon ID %d\n", demon_id);
		return NULL;
	}
	work_queue->items[work_queue->rear] = work;
	work_queue->rear = (work_queue->rear + 1); // no wrap around needed, max size is MAX_DEMONS ensured by logic
	SYNC_ADD(&work_queue->count, 1);
	SYNC_ADD(&active_work_items[work->depth], 1);
#ifdef DEBUG
	SYNC_ADD(&total_work_items, 1);
#endif
	COND_SIGNAL(&work_queue->queue_not_empty);
	MUTEX_UNLOCK(&work_queue->queue_mutex); // unlock after enqueuing work
	SPAM_LOG("created and enqueued work=%p demon=%d depth=%d\n", (void*)work, demon_id, depth);
	return work;
}

static int get_num_cpus() {
#ifdef _WIN32
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	return sysinfo.dwNumberOfProcessors;
#else
	return sysconf(_SC_NPROCESSORS_ONLN);
#endif
}

// count cyrrent shortest possible fusion count for an incomplete fusion
static int count_incomplete_children(WorkItem** child_work, char component_count) {
    int incomplete_count = 1; // Start with 1 for the current fusion
    for (int comp = 0; comp < component_count; comp++) {
        if (!child_work[comp]) {
            ERR_LOG("Warning: null child work item encountered during count_incomplete_children\n");
            incomplete_count += MAX_DEMONS; // Penalize heavily for null child
            break;
        }
        WorkItem* child = child_work[comp];
        RW_RDLOCK(&child->result_rwlock);
        if (child->result) { // Child already has a complete result
            incomplete_count += child->result->fusion_count;
            RW_UNLOCK(&child->result_rwlock);
            continue;
        }
		RW_UNLOCK(&child->result_rwlock);
        int this_count = MAX_DEMONS; // Start with worst-case
		RW_RDLOCK(&child->child_rwlock);
        if (child->fusion_count == 0) { // No fusions explored yet for this child - optimistic estimate
            this_count = 0; // Just the child itself
        } else { // Recursively explore child's fusions to find best incomplete path
            for (int c = 0; c < child->fusion_count; c++) {
				char child_component_count = COMPONENT_COUNT(child->demon_id, c);
                if (!child->children || !child->children[c]) {
                    continue;
                }
                int candidate = count_incomplete_children(child->children[c], child_component_count);
                if (candidate < this_count) {
                    this_count = candidate;
                }
            }
        }
        RW_UNLOCK(&child->child_rwlock);
        incomplete_count += this_count;
    }
    return incomplete_count;
}

static void update_parents(WorkItem* child_work) {
	if (!child_work || !child_work->parent || !child_work->result) {
		ERR_LOG("Warning: Invalid parameters to update_parents for demon ID %d\n", child_work ? child_work->demon_id : -1);
		return;
	}
	MUTEX_LOCK(&child_work->parent_mutex);
	for (int p = 0; p < MAX_DEMONS; p++) {
		if (child_work->parent[p].ref_count > 0) {
			update_this_work(child_work->parent[p].parent);
		}
	}
	MUTEX_UNLOCK(&child_work->parent_mutex);
}

static void update_this_work(WorkItem* work) {
	if (!work) {
		ERR_LOG("Error: Null work item passed to update_this_work\n");
		return;
	}
	RW_WRLOCK(&work->best_fusion_count_rwlock);
	RW_RDLOCK(&work->child_rwlock);
	for (int c = 0; c < work->fusion_count; c++) {
		char component_count = COMPONENT_COUNT(work->demon_id, c);
		bool all_done = true;
		int this_fusion_count = 1;
		for (int comp = 0; comp < component_count; comp++) {
			RW_RDLOCK(&work->result_rwlock);
			if (!work->children[c][comp]->result) {
				all_done = false;
				RW_UNLOCK(&work->result_rwlock);
				break;
			}
			this_fusion_count += work->children[c][comp]->result->fusion_count;
			RW_UNLOCK(&work->result_rwlock);
		}
		if (all_done && this_fusion_count < work->best_fusion_count) {
			work->best_fusion_count = this_fusion_count;
		}
	}
	RW_UNLOCK(&work->child_rwlock);
	RW_UNLOCK(&work->best_fusion_count_rwlock);
	RW_RDLOCK(&work->best_fusion_count_rwlock);
	if (work->best_fusion_count == MAX_DEMONS) {
		RW_UNLOCK(&work->best_fusion_count_rwlock);
	} else { // check for pruning opportunities
		RW_UNLOCK(&work->best_fusion_count_rwlock);
		RW_WRLOCK(&work->child_rwlock);
		for (int c = 0; c < work->fusion_count; c++) {
			char component_count = COMPONENT_COUNT(work->demon_id, c);
			int this_fusion_count = 1;
			bool safe_prune = true;
			for (int comp = 0; comp < component_count; comp++) {
				RW_RDLOCK(&work->children[c][comp]->result_rwlock);
				if (!work->children[c][comp] || !work->children[c][comp]->result) {
					RW_UNLOCK(&work->children[c][comp]->result_rwlock);
					safe_prune = false;
					break;
				}
				this_fusion_count += work->children[c][comp]->result->fusion_count;
				RW_UNLOCK(&work->children[c][comp]->result_rwlock);
			}
			RW_RDLOCK(&work->best_fusion_count_rwlock);
			if ((safe_prune && this_fusion_count > work->best_fusion_count) || (!safe_prune && count_incomplete_children(work->children[c], component_count) >= work->best_fusion_count)) {
				for (int comp = 0; comp < component_count; comp++) {
					WorkItem* child = work->children[c][comp];
					if (!child) {
						ERR_LOG("Warning: Null child work item encountered during prune_fusion for demon ID %d\n", work->demon_id);
						continue;
					}
					MUTEX_LOCK(&child->parent_mutex);
					child->parent[work->demon_id].ref_count--;
					MUTEX_UNLOCK(&child->parent_mutex);
				}
				for (int i = c; i < work->fusion_count - 1; i++) {
					work->children[i] = work->children[i + 1];
				}
				work->fusion_count--;
				c--; // stay at same index to check the next fusion that was just shifted into this position
				SPAM_LOG("Pruned fusion %d for demon ID %d due to best fusion count %d\n", c, work->demon_id, work->best_fusion_count);
			}
			RW_UNLOCK(&work->best_fusion_count_rwlock);
		}
		RW_UNLOCK(&work->child_rwlock);
		RW_RDLOCK(&work->child_rwlock);
		if (work->fusion_count != 1) { // only one fusion left, can finalize
			RW_UNLOCK(&work->child_rwlock);
		} else {
			char component_count = COMPONENT_COUNT(work->demon_id, 0);
			FusionNode** component_nodes = (FusionNode**)malloc(component_count * sizeof(FusionNode*));
			if (!component_nodes) {
				ERR_EXIT("Error: Failed to allocate memory for component nodes\n");
			}
			for (int i = 0; i < component_count; i++) {
				RW_RDLOCK(&work->children[0][i]->result_rwlock);
				if (work->children[0][i] && work->children[0][i]->result) {
					component_nodes[i] = work->children[0][i]->result;
				} else {
					ERR_EXIT("Warning: Missing child result for component %d\n", i);
				}
				RW_UNLOCK(&work->children[0][i]->result_rwlock);
			}
			RW_UNLOCK(&work->child_rwlock);
			FusionNode* result_node = create_fusion_node(work->demon_id, component_count, component_nodes);
			free(component_nodes);
			RW_WRLOCK(&work->result_rwlock);
			work->result = result_node;
			RW_UNLOCK(&work->result_rwlock);
			if (work->demon_id == target_demon_id) { // root node
				// signal main thread that we're done
				COND_SIGNAL(&solution_cond);
				MUTEX_LOCK(&active_work_mutex);
				work_depth_limit = MAX_DEMONS; // unblock all threads
				COND_BROADCAST(&work_depth_cond);
				MUTEX_UNLOCK(&active_work_mutex);
			} else {
				update_parents(work);
			}
		}
	}
}

static bool recursive_check_cycle(WorkItem* current_work, WorkItem* target_work) {
	if (!current_work || !target_work) {
		ERR_LOG("Warning: Invalid parameters to recursive_check_cycle\n");
		return false;
	}
	if (current_work == target_work) {
		return true; // cycle detected
	}
	RW_RDLOCK(&current_work->child_rwlock);
	for (int i = 0; i < current_work->fusion_count; i++) {
		char component_count = COMPONENT_COUNT(current_work->demon_id, i);
		if (!current_work->children || !current_work->children[i]) {
			continue;
		}
		for (char c = 0; c < component_count; c++) {
			if (recursive_check_cycle(current_work->children[i][c], target_work)) {
				RW_UNLOCK(&current_work->child_rwlock);
				SPAM_LOG("Cycle detected during recursive check: Demon ID %d is a component of its own parent demon ID %d\n", current_work->children[i][c]->demon_id, current_work->demon_id);
				return true;
			}
		}
	}
	RW_UNLOCK(&current_work->child_rwlock);
	return false;
}

static bool add_demons_to_work_queue(WorkItem* parent_work, Demon** demons, int demon_count) {
	if (!parent_work || !demons) {
		ERR_LOG("Warning: Invalid parameters to add_demons_to_work_queue\n");
		return false;
	}
	SPAM_LOG("Adding %d demons to work queue for parent demon ID: %d\n", demon_count, parent_work->demon_id);
	for (char i = 0; i < demon_count; i++) { // first check for cycles
		if (!demons[i]) {
			ERR_LOG("Warning: NULL demon pointer at index %d in add_demons_to_work_queue\n", i);
			return false;
		}
		// Read demon->work_item under the demon's work_rwlock to avoid races
		WorkItem* child_work = NULL;
		RW_RDLOCK(&demons[i]->work_rwlock);
		child_work = demons[i]->work_item;
		RW_UNLOCK(&demons[i]->work_rwlock);
		if (child_work) {
			SPAM_LOG("add_demons: parent=%d demon_idx=%d demon_id=%d child_work=%p child_work->fusion_count=%d\n", parent_work->demon_id, i, (int)(demons[i]-all_demons), (void*)child_work, child_work?child_work->fusion_count:0);
			if (recursive_check_cycle(child_work, parent_work)) { // cycle detected, do not add this fusion
				SPAM_LOG("Cycle detected: Demon ID %d is a component of its own parent demon ID %d\n", child_work->demon_id, parent_work->demon_id);
				BITMASK_CLEAR(&parent_work->available_demons, demons[i] - all_demons); // mark this demon as unavailable for future fusions in this branch
				return false;
			}
		}
	} // if we reach here, no cycles detected, we can safely add the fusion
	RW_WRLOCK(&parent_work->child_rwlock);
	parent_work->children = (WorkItem***)realloc(parent_work->children, (parent_work->fusion_count + 1) * sizeof(WorkItem**));
	if (!parent_work->children) {
		ERR_EXIT("Error: Failed to expand parent children array for demon ID %d\n", parent_work->demon_id);
		RW_UNLOCK(&parent_work->child_rwlock);
		return false;
	}
	parent_work->children[parent_work->fusion_count] = (WorkItem**)malloc(demon_count * sizeof(WorkItem*));
	if (!parent_work->children[parent_work->fusion_count]) {
		ERR_EXIT("Error: Failed to allocate child pointers for parent demon ID %d\n", parent_work->demon_id);
		RW_UNLOCK(&parent_work->child_rwlock);
		return false;
	}
	char processed_children = 0;
	for (char i = 0; i < demon_count; i++) {
		Demon* demon = demons[i];
		WorkItem* child_work;
		RW_RDLOCK(&demon->work_rwlock);
		if (!demon->work_item) {
			RW_UNLOCK(&demon->work_rwlock);
			child_work = create_work_item(demon - all_demons, &parent_work->available_demons, parent_work->depth + 1);
			if (!child_work) {
				ERR_EXIT("Error: Failed to create work item for demon ID: %d\n", (int)(demon - all_demons));
			}
		} else {
			SPAM_LOG("Reusing existing work item for demon ID: %d, attaching to parent demon ID: %d\n", (int)(demon - all_demons), parent_work->demon_id);
			child_work = demon->work_item;
			RW_UNLOCK(&demon->work_rwlock);
			RW_RDLOCK(&child_work->result_rwlock);
			if (child_work->result) processed_children++;
			else BITMASK_AND(&child_work->available_demons, &parent_work->available_demons);
			RW_UNLOCK(&child_work->result_rwlock);
		}
		MUTEX_LOCK(&child_work->parent_mutex);
		child_work->parent[parent_work->demon_id].parent = parent_work;
		child_work->parent[parent_work->demon_id].ref_count += 1;
		MUTEX_UNLOCK(&child_work->parent_mutex);
		parent_work->children[parent_work->fusion_count][i] = child_work;
	}
	parent_work->fusion_count++;
	RW_UNLOCK(&parent_work->child_rwlock);
	if (processed_children == demon_count) {
		SPAM_LOG("All child work items already processed for parent demon ID: %d\n", parent_work->demon_id);
		return true;
	}
	return false;
}

static bool check_demon_availability(WorkItem* work, const Demon* demon) {
	if (!work || !demon) {
		ERR_LOG("Warning: Invalid parameters to check_demon_availability\n");
		return false;
	}
	int demon_id = demon - all_demons;
	if (demon_id < 0 || demon_id >= MAX_DEMONS) {
		ERR_LOG("Warning: Demon ID %d out of bounds in check_demon_availability\n", demon_id);
		return false;
	}
	bool available = BITMASK_TEST(&work->available_demons, demon_id) && (all_demons[demon_id].fusions != NULL || base_demons[demon_id]);
	return available;
}

static THREAD_RETURN_TYPE worker_thread(void* arg) {
	Worker* worker = (Worker*)arg;
	WorkQueue* queue = worker->queue;
	DEBUG_LOG("Worker %d started\n", worker->id);
#ifdef SPAM
	char filename[64];
	snprintf(filename, sizeof(filename), "fusion_worker%d_debug.log", worker->id);
	FILE* worker_file = fopen(filename, "w");
	if (!worker_file) {
		ERR_EXIT("Error: Failed to open worker log file\n");
	}
#endif
	while (true) {
		THREAD_LOG(worker_file, "Waiting for work\n");
		MUTEX_LOCK(&queue->queue_mutex); // start of critical section for dequeuing work
		while (queue->count == 0 && !queue->shutdown) {
			COND_WAIT(&queue->queue_not_empty, &queue->queue_mutex);
		}
		if (queue->shutdown) {
			MUTEX_UNLOCK(&queue->queue_mutex);
			THREAD_LOG(worker_file, "Shutdown signal received while waiting for work, exiting\n");
			THREAD_EXIT(0);
		}
		WorkItem* work = queue->items[queue->front];
		queue->front = (queue->front + 1);
		SYNC_ADD(&queue->count, -1);
		MUTEX_UNLOCK(&queue->queue_mutex); // end of critical section for dequeuing work
		THREAD_LOG(worker_file, "Beginning work for demon %d at depth %d\n", work->demon_id, work->depth);
		// process demon data
		if (base_demons[work->demon_id]) {
			THREAD_LOG(worker_file, "Demon ID: %d is a base demon, creating leaf fusion node\n", work->demon_id);
			RW_WRLOCK(&work->result_rwlock);
			work->result = create_fusion_node(work->demon_id, 0, NULL); // leaf node
			RW_UNLOCK(&work->result_rwlock);
			update_parents(work);
		} else {
			BITMASK_CLEAR(&work->available_demons, work->demon_id); // mark self as unavailable to prevent self-fusion
			THREAD_LOG(worker_file, "Awaiting depth permission for demon ID: %d at depth %d\n", work->demon_id, work->depth);
			MUTEX_LOCK(&active_work_mutex);
			while (work->depth > work_depth_limit && !work_queue->shutdown) { // wait to be allowed to process this level of fusion
				COND_WAIT(&work_depth_cond, &active_work_mutex);
			}
			if (work_queue->shutdown) {
				MUTEX_UNLOCK(&active_work_mutex);
				THREAD_LOG(worker_file, "Shutdown signal received while waiting for depth permission, exiting\n");
				THREAD_EXIT(0);
			}
			MUTEX_UNLOCK(&active_work_mutex);
			THREAD_LOG(worker_file, "Proceeding with demon ID: %d at depth %d\n", work->demon_id, work->depth);
			Demon* demon = &all_demons[work->demon_id];
			bool any_completed = false;
			for (char f = 0; f < demon->fusion_count; f++) {
				if (demon->fusions[f].demon_components != NULL) { // special fusion
					THREAD_LOG(worker_file, "Processing special fusion for demon ID: %d\n", work->demon_id);
					bool all_available = true;
					for (int i = 0; i < demon->fusions[f].component_count; i++) {
						if (!check_demon_availability(work, demon->fusions[f].demon_components[i])) {
							all_available = false;
							break; // if any component is unavailable, skip this fusion
						}
					}
					if (all_available && add_demons_to_work_queue(work, demon->fusions[f].demon_components, demon->fusions[f].component_count)) any_completed = true;
				} else if (demon->fusions[f].component_count >= 0) { // racial fusion to make elementals
					for (int demon1 = 0; demon1 < demons_by_race[demon->fusions[f].component_count].count; demon1++) {
						const Demon* comp1 = demons_by_race[demon->fusions[f].component_count].demons[demon1];
						if (!check_demon_availability(work, comp1)) continue;
						for (int demon2 = demon1 + 1; demon2 < demons_by_race[demon->fusions[f].component_count].count; demon2++) {
							const Demon* comp2 = demons_by_race[demon->fusions[f].component_count].demons[demon2];
							if (!check_demon_availability(work, comp2)) continue;
							THREAD_LOG(worker_file, "Adding racial fusion for demon ID: %d using components %d and %d\n", work->demon_id, comp1 - all_demons, comp2 - all_demons);
							if (add_demons_to_work_queue(work, (Demon*[]){(Demon*)comp1, (Demon*)comp2}, 2)) any_completed = true;
						}
					}
				} else { // regular fusion (level or elemental)
					THREAD_LOG(worker_file, "Processing regular fusion for demon ID: %d\n", work->demon_id);
					for (char race1 = 0; race1 < MAX_RACES; race1++) { // first level fusion
						for (char race2 = race1; race2 < MAX_RACES; race2++) {
							if (race_fusions[all_demons[work->demon_id].race][race1] != race2) continue;
							RaceArray* race1_array = &demons_by_race[race1];
							RaceArray* race2_array = &demons_by_race[race2];
							for (int demon1 = 0; demon1 < race1_array->count && race1_array->demons[demon1]->level < all_demons[work->demon_id].fusions->max_level; demon1++) {
								const Demon* comp1 = race1_array->demons[demon1];
								if (comp1->level < all_demons[work->demon_id].fusions->min_level - 99 || !check_demon_availability(work, comp1)) continue;
								for (int demon2 = 0; demon2 < race2_array->count && race2_array->demons[demon2]->level + comp1->level <= all_demons[work->demon_id].fusions->max_level; demon2++) {
									const Demon* comp2 = race2_array->demons[demon2];
									if (comp1->level + comp2->level < all_demons[work->demon_id].fusions->min_level || !check_demon_availability(work, comp2)) continue;
									THREAD_LOG(worker_file, "Adding level fusion for demon ID: %d using components %d (Level %d) and %d (Level %d)\n", work->demon_id, comp1 - all_demons, comp1->level, comp2 - all_demons, comp2->level);
									if (add_demons_to_work_queue(work, (Demon*[]){(Demon*)comp1, (Demon*)comp2}, 2)) any_completed = true;
								}
							}
						}
					}
					if (!all_demons[work->demon_id].anchor_group) {
						ERR_LOG("Warning: Demon %d has no anchor group for elemental fusion\n", work->demon_id);
						break;
					}
					if (!all_demons[work->demon_id].anchor_group->is_anchor) {
						ERR_LOG("Warning: Demon %d is not in an anchor group for elemental fusion\n", work->demon_id);
						break;
					}
					THREAD_LOG(worker_file, "Processing elemental fusions for demon ID: %d\n", work->demon_id);
					for (int e = 0; e < ELEMENTALS; e++) { // then elemental fusion
						if (elemental_chart[e][all_demons[work->demon_id].race] == 0 || !check_demon_availability(work, elemental_ids[e])) continue;
						const char direction = elemental_chart[e][all_demons[work->demon_id].race];
						char i = all_demons[work->demon_id].anchor_group - race_anchors[all_demons[work->demon_id].race].groups + direction; // start just past the starting anchor
						for (; i >= 0 && i < race_anchors[all_demons[work->demon_id].race].group_count; i += direction) {
							for (int j = 0; j < race_anchors[all_demons[work->demon_id].race].groups[i].demon_count; j++) {
								const Demon* demon_ptr = race_anchors[all_demons[work->demon_id].race].groups[i].demons[j];
								if (!demon_ptr) continue;
								if (!check_demon_availability(work, demon_ptr)) continue;
								THREAD_LOG(worker_file, "Adding elemental fusion for demon ID: %d using components %d and %d\n", work->demon_id, elemental_ids[e] - all_demons, demon_ptr - all_demons);
								if (add_demons_to_work_queue(work, (Demon*[]){(Demon*)elemental_ids[e], (Demon*)demon_ptr}, 2)) any_completed = true;
							}
							if (race_anchors[all_demons[work->demon_id].race].groups[i].is_anchor) break; // stop after processing next anchor
						}
					}
				}
			}
			if (any_completed) {
				THREAD_LOG(worker_file, "Some fusions completed immediately for demon ID: %d at depth %d, updating work\n", work->demon_id, work->depth);
				update_this_work(work);
			}
		}
		// finish processing demon, update active work count and possibly allow next depth level to proceed
		MUTEX_LOCK(&active_work_mutex);
		SYNC_ADD(&active_work_items[work->depth], -1);
		for (int d = 0; d <= work->depth + 1; d++) {
			if (active_work_items[d] > 0) {
				THREAD_LOG(worker_file, "Active work being set to %d by demon %d\n", d, work->demon_id);
				work_depth_limit = d; // allow next depth level to process only if all work at current level is done
				COND_BROADCAST(&work_depth_cond);
				break;
			}
		}
		MUTEX_UNLOCK(&active_work_mutex);
#ifdef DEBUG
		SYNC_ADD(&processed_work_items, 1);
		THREAD_LOG(worker_file, "Finished processing demon ID: %d at depth %d\n", work->demon_id, work->depth);
#endif
	}
	return 0;
}

static bool init_thread_pool() {
	num_workers = get_num_cpus();
	DEBUG_LOG("Detected %d CPU cores, initializing thread pool\n", num_workers, num_workers);
	workers = (Worker*)malloc(num_workers * sizeof(Worker));
	if (!workers) {
		ERR_EXIT("Error: Failed to allocate memory for worker threads\n");
		return false;
	}
	WorkQueue* work_queue = (WorkQueue*)malloc(sizeof(WorkQueue));
	if (!work_queue) {
		ERR_EXIT("Error: Failed to allocate memory for work queue\n");
	}
	work_queue->front = 0;
	work_queue->rear = 0;
	work_queue->count = 0;
	work_queue->shutdown = false;
	MUTEX_INIT(&work_queue->queue_mutex);
	COND_INIT(&work_queue->queue_not_empty); // work_queue finished initializing, now create worker threads
	for (int i = 0; i < num_workers; i++) {
		workers[i].id = i;
		workers[i].queue = work_queue;
		if (!THREAD_CREATE(workers[i].thread, worker_thread, &workers[i])) {
			ERR_EXIT("Error: Failed to create worker thread %d\n", i);
		}
	}
	return true;
}

static void print_fusion_tree(FusionNode* node, int depth) {
	if (!node) return;
	for (int i = 0; i < depth; i++) printf("  ");
	printf("Demon %d (Race: %d, Level: %d)", node->demon_id, 
		   all_demons[node->demon_id].race, all_demons[node->demon_id].level);
	if (node->component_count == 0) {
		printf(" [BASE]\n");
	} else {
		printf(" [%d fusions, %d demons total]\n", node->fusion_count, node->demon_count);
		for (int i = 0; i < node->component_count; i++) {
			print_fusion_tree(node->components[i], depth + 1);
		}
	}
}

static FusionNode* find_fusion_chain(int target_demon) {
	Bitmask available_demons;
	BITMASK_SET_ALL(&available_demons);
	WorkItem* root_work = create_work_item(target_demon, &available_demons, 0);
	if (!root_work) {
		ERR_EXIT("Error: Failed to create root work item\n");
		return NULL;
	}
	MUTEX_LOCK(&solution_mutex);
	while (!root_work->result) {
		COND_WAIT(&solution_cond, &solution_mutex);
	}
	MUTEX_UNLOCK(&solution_mutex);
	MUTEX_LOCK(&work_queue->queue_mutex);
	work_queue->shutdown = true;
	COND_BROADCAST(&work_queue->queue_not_empty);
	MUTEX_UNLOCK(&work_queue->queue_mutex);
	for (int i = 0; i < num_workers; i++) {
		THREAD_JOIN(workers[i].thread);
	}
	DEBUG_LOG("Fusion chain found for demon %d\n", target_demon);
	FusionNode* final_result = root_work->result;
	return final_result;
}

int main(int argc, char* argv[]) {
#ifdef DEBUG
	start_time = time(NULL);
	debug_file = my_fopen("fusion_debug.log", "w");
	SPAM_LOG("Debug verbose logging enabled\n");
#endif
	// Parse command line arguments
	if (argc < 4) {
		ERR_EXIT("Error: Usage: %s <target_demon> [base_demon1] [base_demon2] ...\n", argv[0]);
	}
	target_demon_id = atoi(argv[1]);
	DEBUG_LOG("Target demon ID: %d\n", target_demon_id);
	if (target_demon_id < 0 || target_demon_id >= MAX_DEMONS) {
		ERR_EXIT("Error: Invalid target demon ID: %s\n", argv[1]);
	}
	for (int i = 0; i < MAX_DEMONS; i++) {
		base_demons[i] = false;
	}
	for (int i = 2; i < argc; i++) {
		int demon_id = atoi(argv[i]);
		if (demon_id >= 0 && demon_id < MAX_DEMONS) {
			DEBUG_LOG("Adding base demon ID: %d\n", demon_id);
			base_demons[demon_id] = true;
		} else {
			ERR_LOG("Warning: Skipping invalid demon ID: %s\n", argv[i]);
		}
	}
	MUTEX_INIT(&solution_mutex);
	COND_INIT(&solution_cond);
	MUTEX_INIT(&active_work_mutex);
	COND_INIT(&work_depth_cond);
	for (int i = 0; i < MAX_DEMONS / 2; i++) {
		active_work_items[i] = 0;
	}
	DEBUG_LOG("Loading demon data...\n");
	load_demons("data/c/c_demons.json");
	DEBUG_LOG("Loading race fusions...\n");
	load_race_fusions("data/c/c_race_fusions.json");
	DEBUG_LOG("Loading elemental chart...\n");
	load_elemental_chart("data/c/c_elemental_chart.json");
	DEBUG_LOG("Loading race anchors...\n");
	load_race_anchors("data/c/c_race_anchors.json");
	if (!init_thread_pool()) {
		ERR_EXIT("Error: Failed to initialize thread pool\n");
	}
	printf("Finding fusion chain for demon %d...\n", target_demon_id);
	DEBUG_LOG("Starting fusion chain search for demon ID: %d\n", target_demon_id);
	FusionNode* result = find_fusion_chain(target_demon_id);
	if (result) {
		printf("\nFound optimal fusion chain for demon %d:\n", target_demon_id);
		printf("Total fusions: %d\n", result->fusion_count);
		printf("Total demons used: %d\n", result->demon_count);
		print_fusion_tree(result, 0);
	} else {
		printf("\nNo fusion chain found for demon %d\n", target_demon_id);
	}
#ifdef DEBUG
	time_t end_time = time(NULL);
	fprintf(debug_file, "\nPerformance Statistics:\n");
	fprintf(debug_file, "Total work items created: %d\n", total_work_items);
	fprintf(debug_file, "Processed work items: %d\n", processed_work_items);
	fprintf(debug_file, "Pruned branches: %d\n", pruned_branches);
	fprintf(debug_file, "Execution time: %lld seconds\n", (long long)(end_time - start_time));
	fclose(debug_file);
#endif
	printf("Program completed successfully\n");
	return 0;
}
