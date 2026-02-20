#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include "cJSON.h"
#include <stdint.h>

typedef uintptr_t WORD_TYPE;   // unsigned integer type with the same size as a pointer, to be size-agnostic for bitmask operations

// do all my defines make compile times unnecessarily long? yes. Would I light myself on fire to save a single millisecond of runtime? Indubitably.

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
typedef struct { MUTEX waiters_lock; HANDLE sema; int waiters_count; } Custom_Condition;
#define COND_VAR Custom_Condition
#define COND_INIT(cond) do { MUTEX_INIT(&(cond)->waiters_lock); (cond)->sema = CreateSemaphore(NULL, 0, ((~(0UL)) >> 1), NULL); (cond)->waiters_count = 0; } while(0)
#define COND_WAIT(cond, mutex) do { MUTEX_LOCK(&(cond)->waiters_lock); (cond)->waiters_count++; MUTEX_UNLOCK(&(cond)->waiters_lock); MUTEX_UNLOCK(mutex); WaitForSingleObject((cond)->sema, INFINITE); MUTEX_LOCK(mutex); MUTEX_LOCK(&(cond)->waiters_lock); (cond)->waiters_count--; MUTEX_UNLOCK(&(cond)->waiters_lock); } while(0)
#define COND_SIGNAL(cond) do { MUTEX_LOCK(&(cond)->waiters_lock); if ((cond)->waiters_count > 0) { ReleaseSemaphore((cond)->sema, 1, NULL); } MUTEX_UNLOCK(&(cond)->waiters_lock); } while(0)
#define COND_BROADCAST(cond) do { MUTEX_LOCK(&(cond)->waiters_lock); if ((cond)->waiters_count > 0) { ReleaseSemaphore((cond)->sema, (cond)->waiters_count, NULL); } MUTEX_UNLOCK(&(cond)->waiters_lock); } while(0)
#define COND_DESTROY(cond) do { CloseHandle((cond)->sema); MUTEX_DESTROY(&(cond)->waiters_lock); } while(0)
#else // Use native condition variables
#define COND_VAR CONDITION_VARIABLE
#define COND_INIT(cond) InitializeConditionVariable(cond)
#define COND_WAIT(cond, mutex) SleepConditionVariableCS(cond, mutex, INFINITE)
#define COND_SIGNAL(cond) WakeConditionVariable(cond)
#define COND_BROADCAST(cond) WakeAllConditionVariable(cond)
#define COND_DESTROY(cond) /* No destroy needed */
#endif

#ifndef SRWLOCK_MISSING // Fallback for older Windows versions without SRWLOCK support
typedef struct { MUTEX cs; int readers; COND_VAR cond; } RWLOCK; // simple reader-writer lock using critical section and condition variable
#define RW_INIT(lock) do { MUTEX_INIT(&((lock)->cs)); (lock)->readers = 0; COND_INIT(&((lock)->cond)); } while(0)
#define RW_RDLOCK(lock) do { MUTEX_LOCK(&((lock)->cs)); while ((lock)->readers < 0) COND_WAIT(&((lock)->cond), &((lock)->cs)); (lock)->readers++; MUTEX_UNLOCK(&((lock)->cs)); } while(0)
#define RW_WRLOCK(lock) do { MUTEX_LOCK(&((lock)->cs)); while ((lock)->readers != 0) COND_WAIT(&((lock)->cond), &((lock)->cs)); (lock)->readers = -1; MUTEX_UNLOCK(&((lock)->cs)); } while(0)
#define RW_UNLOCK_RD(lock) do { MUTEX_LOCK(&((lock)->cs)); (lock)->readers--; if ((lock)->readers == 0) COND_SIGNAL(&((lock)->cond)); MUTEX_UNLOCK(&((lock)->cs)); } while(0)
#define RW_UNLOCK_WR(lock) do { MUTEX_LOCK(&((lock)->cs)); (lock)->readers = 0; COND_BROADCAST(&((lock)->cond)); MUTEX_UNLOCK(&((lock)->cs)); } while(0)
#define RW_DESTROY(lock) do { MUTEX_DESTROY(&((lock)->cs)); COND_DESTROY(&((lock)->cond)); } while(0)
#else // Use native SRW locks
#define RWLOCK SRWLOCK
#define RW_INIT(lock) InitializeSRWLock(lock)
#define RW_RDLOCK(lock) AcquireSRWLockShared(lock)
#define RW_WRLOCK(lock) AcquireSRWLockExclusive(lock)
#define RW_UNLOCK_RD(lock) ReleaseSRWLockShared(lock)
#define RW_UNLOCK_WR(lock) ReleaseSRWLockExclusive(lock)
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
#define MUTEX_INIT(mutex) pthread_mutex_init(mutex, NULL)
#define MUTEX_LOCK(mutex) pthread_mutex_lock(mutex)
#define MUTEX_TRYLOCK(mutex) pthread_mutex_trylock(mutex)
#define MUTEX_UNLOCK(mutex) pthread_mutex_unlock(mutex)
#define MUTEX_DESTROY(mutex) pthread_mutex_destroy(mutex)
#define COND_VAR pthread_cond_t
#define COND_INIT(cond) pthread_cond_init(cond, NULL)
#define COND_WAIT(cond, mutex) pthread_cond_wait(cond, mutex)
#define COND_SIGNAL(cond) pthread_cond_signal(cond)
#define COND_BROADCAST(cond) pthread_cond_broadcast(cond)
#define COND_DESTROY(cond) pthread_cond_destroy(cond)
#define RWLOCK pthread_rwlock_t
#define RW_INIT(lock) pthread_rwlock_init(lock, NULL)
#define RW_RDLOCK(lock) pthread_rwlock_rdlock(lock)
#define RW_WRLOCK(lock) pthread_rwlock_wrlock(lock)
#define RW_UNLOCK_RD(lock) pthread_rwlock_unlock(lock)
#define RW_UNLOCK_WR(lock) pthread_rwlock_unlock(lock)
#define RW_DESTROY(lock) pthread_rwlock_destroy(lock)
#endif

#ifdef __GNUC__   // MinGW or Cygwin GCC
#define SYNC_ADD(ptr, val) __sync_fetch_and_add((volatile WORD_TYPE*)(ptr), (WORD_TYPE)(val))
#define SYNC_AND(ptr, val) __sync_fetch_and_and((volatile WORD_TYPE*)(ptr), (WORD_TYPE)(val))
#define SYNC_OR(ptr, val)  __sync_fetch_and_or((volatile WORD_TYPE*)(ptr), (WORD_TYPE)(val))
#define ATOMIC_LOAD(ptr) __atomic_load_n((volatile WORD_TYPE*)(ptr), __ATOMIC_RELAXED)
#else              // MSVC
#define ATOMIC_LOAD(ptr) (*(volatile WORD_TYPE*)(ptr))
#ifdef _WIN64
#define SYNC_ADD(ptr, val) InterlockedExchangeAdd64((volatile LONG64*)(ptr), (LONG64)(val))
#define SYNC_AND(ptr, val) InterlockedAnd64((volatile LONG64*)(ptr), (LONG64)(val))
#define SYNC_OR(ptr, val)  InterlockedOr64((volatile LONG64*)(ptr), (LONG64)(val))
#else
#define SYNC_ADD(ptr, val) InterlockedExchangeAdd((volatile LONG*)(ptr), (LONG)(val))
#define SYNC_AND(ptr, val) InterlockedAnd((volatile LONG*)(ptr), (LONG)(val))
#define SYNC_OR(ptr, val)  InterlockedOr((volatile LONG*)(ptr), (LONG)(val))
#endif
#endif

#define MAX_DEMONS 687
#define MAX_RACES 41
#define MAX_COMPONENTS 3
#define MAX_FUSIONS 6
#define ELEMENTALS 4
#define BITS_PER_WORD sizeof(WORD_TYPE) * 8
#define BITSET_WORDS (MAX_DEMONS + BITS_PER_WORD - 1) / BITS_PER_WORD // number of words needed to represent MAX_DEMONS bits
#define DEPTH_LIMIT BITS_PER_WORD // max depth limit for our BFS search, chosen to be the number of bits in our bitmask type, which should be more than enough since in practice max depth is much less than MAX_DEMONS / 2 which is the theoretical maximum depth due to each fusion requiring at least 2 components

#define COMPONENT_COUNT(demon_id, fusion_index) (all_demons[demon_id].fusions[fusion_index].demon_components ? all_demons[demon_id].fusions[fusion_index].component_count : 2)
#define ERR_LOG(...) do { fprintf(stderr, __VA_ARGS__); fflush(stderr); } while(0)
#define ERR_EXIT(...) do { ERR_LOG(__VA_ARGS__); exit(EXIT_FAILURE); } while(0)
#define BITMASK_TEST(bm, id) ((ATOMIC_LOAD(&(bm)->bits[(id) / BITS_PER_WORD]) >> ((id) % BITS_PER_WORD)) & 1)
#define BITMASK_SET_ALL(bm) do { for (int bitmask_i = 0; bitmask_i < BITSET_WORDS; bitmask_i++) (bm)->bits[bitmask_i] = ~0; } while(0)
#define BITMASK_CLEAR(bm, id) SYNC_AND(&(bm)->bits[(id) / BITS_PER_WORD], ~((WORD_TYPE)1 << ((id) % BITS_PER_WORD)) )
#define BITMASK_AND(dest, src) do { for (int bitmask_j = 0; bitmask_j < BITSET_WORDS; bitmask_j++) { SYNC_AND(&(dest)->bits[bitmask_j], (src)->bits[bitmask_j]); } } while(0)
#define BITMASK_OR(dest, src) do { for (int bitmask_k = 0; bitmask_k < BITSET_WORDS; bitmask_k++) { SYNC_OR(&(dest)->bits[bitmask_k], (src)->bits[bitmask_k]); } } while(0)
#define CHECK_DEMON_AVAILABILITY(work, demon) (BITMASK_TEST(&(work)->available_demons, demon - all_demons) && (all_demons[demon - all_demons].fusions != NULL || base_demons[demon - all_demons]))
#define FILE_WRITE(file, ...) do { fprintf(file, __VA_ARGS__); fflush(file); } while(0)
#ifdef DEBUG
#define DEBUG_LOG(...) do { FILE_WRITE(debug_file, __VA_ARGS__); } while(0)
#ifdef SPAM
#define SPAM_LOG(...) do { DEBUG_LOG(__VA_ARGS__); } while(0)
#define WORKER_LOG(...) do { FILE_WRITE(worker_file, __VA_ARGS__); SPAM_LOG(__VA_ARGS__); } while(0)
#else
#define SPAM_LOG(...) do {} while(0)
#define WORKER_LOG(...) do {} while(0)
#endif
#else
#define DEBUG_LOG(...) do {} while(0)
#define SPAM_LOG(...) do {} while(0)
#define WORKER_LOG(...) do {} while(0)
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
	int lifetime; // lifetime of this reference, used for pruning. If this reaches 0, we can be sure that this current path is invalid and should attempt an update to prune it
} ParentWRef;

typedef struct {
	volatile WORD_TYPE bits[BITSET_WORDS]; // bitmask for available demons
} Bitmask;

typedef struct {
	WorkItem** components;  // component work items of this fusion
	char component_count; // number of components in this fusion
} ChildFusion;

// Work item for the queue
typedef struct WorkItem {
	int demon_id; // demon to process
	Bitmask available_demons; // bitmask for which demons are still available for processing this work item
	int depth; // current depth
	FusionNode* result; // pointer to where to store the result
	RWLOCK result_rwlock; // rwlock to protect result access
	ParentWRef parent[MAX_DEMONS]; // parents work items (for pruning)
	MUTEX parent_mutex; // mutex to protect parent data
	ChildFusion* children; // child work items for each fusion of this demon
	int fusion_count; // number of fusions (component count is located in the ChildFusion struct since it can vary for each fusion)
	RWLOCK child_rwlock; // rwlock to protect child data
	int best_fusion_count; // best fusion count found so far
	MUTEX best_fusion_count_mutex; // mutex to protect best_fusion_count updates
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
	COND_VAR queue_not_empty;
	volatile bool shutdown; // simple bool but using WORD_TYPE for atomic operations
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
static bool base_demons[MAX_DEMONS] = {false};
static const Demon* elemental_ids[ELEMENTALS];
static RaceAnchors race_anchors[MAX_RACES];
static int target_demon_id;

// Thread pool and work queue
static Worker* workers;
static WorkQueue* work_queue;

// Work depth limit for BFS levels
static volatile WORD_TYPE work_depth_limit = 0; // current maximum depth being processed
static volatile WORD_TYPE active_work_items[DEPTH_LIMIT] = {0}; // count of active work items at each depth level
static MUTEX active_work_mutex;
static COND_VAR work_depth_cond;
static MUTEX solution_mutex;
static COND_VAR solution_cond;

#ifdef DEBUG
static volatile WORD_TYPE total_work_items = 0;
static volatile WORD_TYPE processed_work_items = 0;
static volatile int pruned_branches = 0;
static FILE* debug_file;
static time_t start_time;
#endif

// forward declarations of functions
static inline void update_this_work(WorkItem* work);

// File operations
static inline FILE* my_fopen(const char* filename, const char* mode) {
	FILE* file = fopen(filename, mode);
	if (!file) {
		perror("Failed to open file");
		return NULL;
	}
	return file;
}

static inline cJSON* load_json(const char* filename) {
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

static inline void quick_sort_demons_by_level(Demon** arr, const int left, const int right) {
	if (left < right) {
		Demon* pivot = arr[right];
		int i = left - 1;
		for (int j = left; j < right; j++) if (arr[j]->level <= pivot->level) {
			i++;
			Demon* temp = arr[i];
			arr[i] = arr[j];
			arr[j] = temp;
		}
		Demon* temp = arr[i + 1];
		arr[i + 1] = arr[right];
		arr[right] = temp;
		int pivot_index = i + 1;
		quick_sort_demons_by_level(arr, left, pivot_index - 1);
		quick_sort_demons_by_level(arr, pivot_index + 1, right);
	}
}

static inline void add_demon_fusion(Demon* demon, const Fusion fusion) {
	if (demon->fusion_count >= MAX_FUSIONS) {
		ERR_LOG("Warning: Attempted to add fusion to demon ID %d, but it already has maximum fusions\n", (int)(demon - all_demons));
		return;
	}
	demon->fusions = (Fusion*)realloc(demon->fusions, (demon->fusion_count + 1) * sizeof(Fusion));
	if (!demon->fusions) ERR_EXIT("Error: Failed to allocate memory for demon fusions\n");
	demon->fusions[demon->fusion_count++] = fusion;
}

static inline void free_fusion_node(FusionNode* node) {
	if (!node) return;
	if (node->components) {
		for (int i = 0; i < node->component_count; i++) free_fusion_node(node->components[i]);
		free(node->components);
		node->components = NULL;
	}
	free(node);
}

static inline void free_demon_resources(Demon* demon) {
	if (!demon) return;
	if (demon->fusions) {
		for (int i = 0; i < demon->fusion_count; i++) if (demon->fusions[i].demon_components) free(demon->fusions[i].demon_components);
		free(demon->fusions);
		demon->fusions = NULL;
	}
}

static inline void load_demons(const char* filename) {
	cJSON* json = load_json(filename);
	if (!json) return;
	cJSON* demon_entry;
#ifdef SPAM
	int demon_count = 0;
#endif
	cJSON_ArrayForEach(demon_entry, json) {
		const int demon_id = atoi(demon_entry->string);
		if (demon_id < 0 || demon_id >= MAX_DEMONS) {
			ERR_LOG("Warning: Demon ID %d out of bounds\n", demon_id);
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
			if (!demons_by_race[this_demon->race].demons) ERR_EXIT("Error: Failed to allocate memory for demons by race\n");
			demons_by_race[this_demon->race].demons[demons_by_race[this_demon->race].count++] = this_demon;
		}
		if (!(fuse_able && fuse_able->valueint)) continue;
		cJSON* special_fusion = cJSON_GetObjectItem(demon_entry, "special_fusion");
		if (special_fusion && cJSON_IsArray(special_fusion)) {
			cJSON* recipe;
			cJSON_ArrayForEach(recipe, special_fusion) {
				if (this_demon->fusion_count >= MAX_FUSIONS) {
					ERR_LOG("Warning: Too many fusions for demon %d\n", demon_id);
					break;
				}
				Fusion this_fusion;
				this_fusion.component_count = cJSON_GetArraySize(recipe);
				if (this_fusion.component_count > MAX_COMPONENTS) {
					ERR_LOG("Warning: Too many components in special fusion for demon %d\n", demon_id);
					continue;
				}
				this_fusion.demon_components = (Demon**)malloc(this_fusion.component_count * sizeof(Demon*));
				if (!this_fusion.demon_components) ERR_EXIT("Error: Failed to allocate memory for fusion components\n");
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
				add_demon_fusion(this_demon, this_fusion);
			}
		} else {
			cJSON* racial_fusion = cJSON_GetObjectItem(demon_entry, "racial_fusion");
			if (racial_fusion && cJSON_IsArray(racial_fusion)) {
				cJSON* recipe;
				cJSON_ArrayForEach(recipe, racial_fusion) {
					if (this_demon->fusion_count >= MAX_FUSIONS) {
						ERR_LOG("Warning: Too many fusions for demon %d\n", demon_id);
						break;
					}
					Fusion this_fusion;
					this_fusion.demon_components = NULL;
					cJSON* race_item = cJSON_GetArrayItem(recipe, 0);
					if (!(race_item && race_item->type == cJSON_Number)) {
						ERR_LOG("Warning: Invalid race item in racial fusion for demon %d\n", demon_id);
						continue;
					}
					this_fusion.component_count = (char)race_item->valueint;
					add_demon_fusion(this_demon, this_fusion);
				}
			} else {
				cJSON* min_level = cJSON_GetObjectItem(demon_entry, "min_level");
				cJSON* max_level = cJSON_GetObjectItem(demon_entry, "max_level");
				if (!(min_level && max_level)) {
					ERR_LOG("Warning: Demon %d supposedly fuse able, however no fusions found\n", demon_id);
					continue;
				}
				Fusion this_fusion;
				this_fusion.min_level = (unsigned char)min_level->valueint;
				this_fusion.max_level = (unsigned char)max_level->valueint;
				this_fusion.demon_components = NULL;
				this_fusion.component_count = -1;
				add_demon_fusion(this_demon, this_fusion);
			}
		}
	}
	for (int i = 0; i < MAX_RACES; i++) if (demons_by_race[i].count > 1) quick_sort_demons_by_level(demons_by_race[i].demons, 0, demons_by_race[i].count - 1);
	cJSON_Delete(json);
	printf("Successfully loaded demons\n");
	DEBUG_LOG("Total demons loaded: %d\n", demon_count);
}

static inline void load_race_fusions(const char* filename) {
	for (int i = 0; i < MAX_RACES; i++) for (int j = 0; j < MAX_RACES; j++) race_fusions[i][j] = -1;
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
			ERR_LOG("Warning: resultant race %d is outside of range %d\n", result_race, MAX_RACES);
			continue;
		}
		cJSON* pair_item;
		cJSON_ArrayForEach(pair_item, race_item) {
			cJSON* first = cJSON_GetArrayItem(pair_item, 0);
			cJSON* second = cJSON_GetArrayItem(pair_item, 1);
			if (!(first && second && cJSON_IsNumber(first) && cJSON_IsNumber(second))) {
				ERR_LOG("Warning: unhandled error while trying to load races\n");
				continue;
			}
			const char race1 = (char)first->valueint;
			const char race2 = (char)second->valueint;
			if (!(race1 >= 0 && race1 < MAX_RACES && race2 >= 0 && race2 < MAX_RACES)) {
				ERR_LOG("Warning: races %d, %d are outside of range %d\n", race1, race2, MAX_RACES);
				continue;
			}
#ifdef SPAM
			race_fusion_count++;
#endif
			if (race1 < race2) race_fusions[race1][race2] = result_race;
			else race_fusions[race2][race1] = result_race;
		}
	}
	cJSON_Delete(root);
	DEBUG_LOG("Total race fusions loaded: %d\n", race_fusion_count);
}

static inline void load_elemental_chart(const char* filename) {
	for (int i = 0; i < ELEMENTALS; i++) for (int j = 0; j < MAX_RACES; j++) elemental_chart[i][j] = 0;
	cJSON* root = load_json(filename);
	if (!root) return;
	char elemental_count = 0;
	cJSON* elemental_data = NULL;
#ifdef SPAM
	int elemental_load_count = 0;
#endif
	cJSON_ArrayForEach(elemental_data, root) {
		if (elemental_count >= ELEMENTALS) {
			ERR_LOG("Warning: attempted to load too many elementals\n");
			break;
		}
		elemental_ids[elemental_count] = &all_demons[atoi(elemental_data->string)];
		cJSON* race_item = NULL;
		cJSON_ArrayForEach(race_item, elemental_data) {
			const int race_id = atoi(race_item->string);
			if (race_id < 0 || race_id >= MAX_RACES) {
				ERR_LOG("Warning: attempted to load race value %d that is out of bounds of %d\n", race_id, MAX_RACES);
				continue;
			}
			if (!(cJSON_IsBool(race_item))) {
				ERR_LOG("Warning: attempted to load non-bool value as bool value from elemental chart\n");
				continue;
			}
			elemental_chart[elemental_count][race_id] = cJSON_IsTrue(race_item) ? -1 : 1;
#ifdef SPAM
			elemental_load_count++;
#endif
		}
		elemental_count++;
	}
	cJSON_Delete(root);
	DEBUG_LOG("Loaded elemental chart with %d elementals and %d total entries\n", elemental_count, elemental_load_count);
}

static inline void load_race_anchors(const char* filename) {
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
			ERR_LOG("Warning: Race ID %d out of bounds in anchor file\n", race_id);
			continue;
		}
		const char group_count = cJSON_GetArraySize(race_item);
		AnchorGroup* groups = (AnchorGroup*)malloc(group_count * sizeof(AnchorGroup));
		if (!groups) ERR_EXIT("Error: Failed to allocate memory for anchor groups\n");
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
					ERR_LOG("Warning: Demon ID %d out of bounds in anchor group for race %d\n", demon_id, race_id);
					groups[i].demons[j] = NULL;
					continue;
				}
				Demon* demon = &all_demons[demon_id];
				groups[i].demons[j] = demon;
				demon->anchor_group = &groups[i];
				if (demon->race != race_id) ERR_LOG("Warning: Demon %d (race %d) placed in wrong race anchor group %d\n", demon_id, demon->race, race_id);
			}
		}
	}
	cJSON_Delete(root);
	DEBUG_LOG("Total race anchor groups loaded: %d\n", race_anchor_count);
}

static inline FusionNode* create_fusion_node(const int demon_id, const char component_count, FusionNode** components) {
	FusionNode* node = (FusionNode*)malloc(sizeof(FusionNode));
	if (!node) {
		ERR_EXIT("Error: Failed to allocate memory for fusion node\n");
	}
	node->demon_id = demon_id;
	node->component_count = component_count;
	node->demon_count = 1;
	node->fusion_count = 0;
	if (component_count == 0) node->components = NULL;
	else {
		if (!components) ERR_EXIT("Error: Non-leaf fusion node must have components\n");
		node->components = (FusionNode**)malloc(component_count * sizeof(FusionNode*));
		if (!node->components) ERR_EXIT("Error: Failed to allocate memory for fusion node components\n");
		for (char i = 0; i < component_count; i++) {
			node->components[i] = components[i];
			node->demon_count += components[i]->demon_count;
			node->fusion_count += components[i]->fusion_count;
		}
		node->fusion_count++; // count this fusion
	}
	return node;
}

static inline WorkItem* create_work_item(int demon_id, const Bitmask* available_demons, int depth) {
	RW_WRLOCK(&all_demons[demon_id].work_rwlock); // publish under lock
	if (all_demons[demon_id].work_item) {
		SPAM_LOG("Work item already exists for demon ID %d, merging available demons\n", demon_id);
		BITMASK_AND(&all_demons[demon_id].work_item->available_demons, available_demons); // merge available demons
		RW_UNLOCK_WR(&all_demons[demon_id].work_rwlock);
		return all_demons[demon_id].work_item;
	}
	WorkItem* work = (WorkItem*)malloc(sizeof(WorkItem));
	if (!work) ERR_EXIT("Error: Failed to allocate memory for work item\n");
	work->demon_id = demon_id;
	work->available_demons = *available_demons;
	work->depth = depth;
	work->result = NULL;
	RW_INIT(&work->result_rwlock);
	MUTEX_INIT(&work->parent_mutex);
	memset(work->parent, 0, sizeof(ParentWRef) * MAX_DEMONS);
	for (int i = 0; i < MAX_DEMONS; i++) work->parent[i].lifetime = -1; // initialize lifetimes to -1 to indicate no valid path yet, we cant do this in the memset as we need to keep the parent pointers as null but we want to be able to distinguish between no parents and parents that are just not valid for any depth yet
	work->children = NULL;
	work->fusion_count = 0;
	RW_INIT(&work->child_rwlock);
	MUTEX_INIT(&work->best_fusion_count_mutex);
	work->best_fusion_count = MAX_DEMONS;
	all_demons[demon_id].work_item = work;
	RW_UNLOCK_WR(&all_demons[demon_id].work_rwlock);
	MUTEX_LOCK(&work_queue->queue_mutex); // lock queue to safely enqueue work
	if (work_queue->shutdown) {
		MUTEX_UNLOCK(&work_queue->queue_mutex);
		SPAM_LOG("Work queue is shutting down, cannot enqueue work for demon ID %d\n", demon_id);
		THREAD_EXIT(0);
	}
	work_queue->items[work_queue->rear] = work;
	work_queue->rear = (work_queue->rear + 1); // no wrap around needed, max size is MAX_DEMONS ensured by logic
	work_queue->count++; // no need for atomic operation since we are under mutex lock
	MUTEX_LOCK(&active_work_mutex);
	active_work_items[depth]++; // increment active work count for this depth
	MUTEX_UNLOCK(&active_work_mutex);
#ifdef DEBUG
	total_work_items++;
#endif
	COND_SIGNAL(&work_queue->queue_not_empty);
	MUTEX_UNLOCK(&work_queue->queue_mutex); // unlock after enqueuing work
	return work;
}

static inline int get_num_cpus() {
#ifdef _WIN32
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	return sysinfo.dwNumberOfProcessors;
#else
	return sysconf(_SC_NPROCESSORS_ONLN);
#endif
}

// count current shortest possible fusion count for an incomplete fusion, caller MUST hold best_fusion_count_mutex for the work item corresponding to target_demon_id before calling this function to ensure that the depth parameter is still valid and that the result is not already complete, this function will also update the lifetimes of the parent references for the current path being evaluated
static int count_incomplete_children(ChildFusion* fusion, int depth, int target_demon_id) {
    int incomplete_count = 1; // Start with 1 for the current fusion
	for (int comp = 0; comp < fusion->component_count && depth > incomplete_count; comp++) { // if depth is already exceeded by incomplete count, no need to keep counting since this path is already worse than current best
		if (!fusion->components[comp]) {
			ERR_LOG("Warning: null child work item encountered during count_incomplete_children\n");
			incomplete_count += MAX_DEMONS; // Penalize heavily for null child
			break;
		}
		WorkItem* child = fusion->components[comp];
		if (child->parent[target_demon_id].lifetime < depth) { // Double Checked Lock to update lifetime
			MUTEX_LOCK(&child->parent_mutex);
			if (child->parent[target_demon_id].lifetime < depth) child->parent[target_demon_id].lifetime = depth; // update lifetime if this path is still valid for longer
			MUTEX_UNLOCK(&child->parent_mutex);
		}
		RW_RDLOCK(&child->result_rwlock);
		if (child->result) { // Child already has a complete result
			incomplete_count += child->result->fusion_count;
			RW_UNLOCK_RD(&child->result_rwlock);
			continue;
		}
		RW_UNLOCK_RD(&child->result_rwlock);
		int demon_cost = MAX_DEMONS; // Start with worst-case
		RW_RDLOCK(&child->child_rwlock);
		if (child->fusion_count == 0) demon_cost = 0; // Just the child itself
		else { // Recursively explore child's fusions to find best incomplete path
			for (int c = 0; c < child->fusion_count; c++) {
				if (!child->children || !child->children[c].components) {
					ERR_LOG("Warning: null child fusion encountered during count_incomplete_children for demon ID %d\n", child->demon_id);
					continue;
				}
				int candidate = count_incomplete_children(&child->children[c], depth - incomplete_count, target_demon_id); // recursion is safe as cycles are guaranteed to be impossible due to work item creation logic, we use incomplete_count to take into account how expensive the sibling nodes for this fusion are
				if (candidate < demon_cost) {
					demon_cost = candidate;
					if (demon_cost + incomplete_count >= depth || demon_cost == 1) break; // no need to keep checking if this path is already worse than current best
				}
			}
		}
		RW_UNLOCK_RD(&child->child_rwlock);
		incomplete_count += demon_cost;
	}
    return incomplete_count;
}

static void signal_up(WorkItem* work) {
	if (work->demon_id != target_demon_id) {
		SPAM_LOG("Signaling up from demon ID %d to parents\n", work->demon_id);
		MUTEX_LOCK(&work->parent_mutex);
		int parent_count = 0;
		for (int i = 0; i < MAX_DEMONS; i++) if (work->parent[i].ref_count > 0) parent_count++;
		if (parent_count == 0) {
			MUTEX_UNLOCK(&work->parent_mutex);
			return;
		}
		WorkItem** parents_to_update = (WorkItem**)malloc(parent_count * sizeof(WorkItem*));
		int parent_index = 0;
		for (int i = 0; i < MAX_DEMONS; i++) if (work->parent[i].ref_count > 0) parents_to_update[parent_index++] = work->parent[i].parent;
		MUTEX_UNLOCK(&work->parent_mutex);
		for (int i = 0; i < parent_count; i++) update_this_work(parents_to_update[i]);
		free(parents_to_update);
	} else {
		MUTEX_LOCK(&solution_mutex);
		COND_SIGNAL(&solution_cond);
		MUTEX_UNLOCK(&solution_mutex);
		MUTEX_LOCK(&work_queue->queue_mutex);
		work_queue->shutdown = true; // signal worker threads to shutdown
		COND_BROADCAST(&work_queue->queue_not_empty);
		MUTEX_UNLOCK(&work_queue->queue_mutex);
		MUTEX_LOCK(&active_work_mutex);
		work_depth_limit = MAX_DEMONS; // unblock all threads
		COND_BROADCAST(&work_depth_cond);
		MUTEX_UNLOCK(&active_work_mutex);
	}
}

static void update_this_work(WorkItem* work) {
	if (!work) {
		ERR_LOG("Error: Null work item passed to update_this_work\n");
		return;
	}
	RW_RDLOCK(&work->result_rwlock);
	if (work->result) {
		RW_UNLOCK_RD(&work->result_rwlock);
		return; // already has a result, no need to update
	}
	RW_UNLOCK_RD(&work->result_rwlock);
	SPAM_LOG("Updating work for demon ID %d\n", work->demon_id);
	MUTEX_LOCK(&work->best_fusion_count_mutex);
	bool retry = true;
	bool found_best_count;
	RW_WRLOCK(&work->child_rwlock);
	while (retry) {
		retry = false;
		found_best_count = false;
		for (int fusion_index = 0; fusion_index < work->fusion_count; fusion_index++) {
			char component_count = work->children[fusion_index].component_count;
			int this_fusion_count = 1;
			bool all_done = true;
			if (!work->children || !work->children[fusion_index].components) {
				ERR_LOG("Warning: Null child fusion encountered during update_this_work for demon ID %d\n", work->demon_id);
				continue;
			}
			for (char comp = 0; comp < component_count; comp++) {
				if (!work->children[fusion_index].components[comp]) {
					ERR_LOG("Warning: Null child work item encountered during update_this_work for demon ID %d\n", work->demon_id);
					all_done = false;
					break;
				}
				RW_RDLOCK(&work->children[fusion_index].components[comp]->result_rwlock);
				if (!work->children[fusion_index].components[comp]->result) {
					all_done = false;
					RW_UNLOCK_RD(&work->children[fusion_index].components[comp]->result_rwlock);
					break;
				}
				this_fusion_count += work->children[fusion_index].components[comp]->result->fusion_count;
				RW_UNLOCK_RD(&work->children[fusion_index].components[comp]->result_rwlock);
			}
			if (all_done && this_fusion_count < work->best_fusion_count) {
				work->best_fusion_count = this_fusion_count;
				found_best_count = true;
				if (fusion_index != 0) retry = true; // found a better complete fusion count, need to re-check for pruning opportunities
			} else if (all_done && this_fusion_count == work->best_fusion_count && !found_best_count) found_best_count = true;
			else if (all_done || (work->best_fusion_count < MAX_DEMONS && count_incomplete_children(&work->children[fusion_index], work->best_fusion_count, work->demon_id) >= work->best_fusion_count)) {
				for (int comp = 0; comp < work->children[fusion_index].component_count; comp++) {
					WorkItem* child = work->children[fusion_index].components[comp];
					if (!child) {
						ERR_LOG("Warning: Null child work item encountered during prune_fusion for demon ID %d\n", work->demon_id);
						continue;
					}
					MUTEX_LOCK(&child->parent_mutex);
					child->parent[work->demon_id].ref_count--;
					MUTEX_UNLOCK(&child->parent_mutex);
				}
				free(work->children[fusion_index].components);
				work->children[fusion_index].components = NULL;
				for (int i = fusion_index; i < work->fusion_count - 1; i++) work->children[i] = work->children[i + 1];
				work->fusion_count--;
#ifdef DEBUG
				SYNC_ADD(&pruned_branches, 1);
				SPAM_LOG("Pruned fusion %d for demon ID %d due to best fusion count %d\n", fusion_index, work->demon_id, work->best_fusion_count);
#endif
				fusion_index--; // re-check this index since we just shifted a new fusion into it
			}
		}
	}
	RW_UNLOCK_WR(&work->child_rwlock);
	MUTEX_UNLOCK(&work->best_fusion_count_mutex);
	SPAM_LOG("Finished evaluating fusions for demon ID %d, best fusion count is %d, remaining fusion count is %d\n", work->demon_id, work->best_fusion_count, work->fusion_count);
	RW_RDLOCK(&work->child_rwlock); // re-lock downgraded child_rwlock to check if we can finalize this work item
	if (work->fusion_count == 0) {
		SPAM_LOG("No valid fusions remain for demon ID %d, marking as impossible\n", work->demon_id);
		RW_UNLOCK_RD(&work->child_rwlock);
		RW_WRLOCK(&work->result_rwlock);
		if (work->result) {
			RW_UNLOCK_WR(&work->result_rwlock);
			SPAM_LOG("Concurrent attempt at updating impossible result for demon ID %d\n", work->demon_id);
			return;
		}
		FusionNode* result_node = create_fusion_node(work->demon_id, 0, NULL);
		work->result = result_node;
		work->result->fusion_count = MAX_DEMONS; // mark as impossible result to prevent any parent fusions from trying to use this result
		RW_UNLOCK_WR(&work->result_rwlock);
		signal_up(work);
	} else if (work->fusion_count != 1) RW_UNLOCK_RD(&work->child_rwlock);
	else { // only one fusion left, check if it is complete and finalize if so
		bool all_done = true;
		for (int c = 0; c < work->children[0].component_count; c++) {
			if (!work->children[0].components[c]) {
				ERR_LOG("Warning: Null child fusion encountered during finalization check for demon ID %d\n", work->demon_id);
				RW_UNLOCK_RD(&work->child_rwlock);
				return;
			}
			RW_RDLOCK(&work->children[0].components[c]->result_rwlock);
			if (!work->children[0].components[c]->result) {
				all_done = false;
				RW_UNLOCK_RD(&work->children[0].components[c]->result_rwlock);
				break;
			}
			RW_UNLOCK_RD(&work->children[0].components[c]->result_rwlock);
		}
		if (!all_done) {
			RW_UNLOCK_RD(&work->child_rwlock);
			return;
		} // else finalize this work item with the single remaining fusion
		char component_count = work->children[0].component_count;
		FusionNode** component_nodes = (FusionNode**)malloc(component_count * sizeof(FusionNode*));
		if (!component_nodes) ERR_EXIT("Error: Failed to allocate memory for component nodes\n");
		for (int i = 0; i < component_count; i++) {
			WorkItem* child = work->children[0].components[i];
			if (!child) ERR_EXIT("Error: Null child work item encountered during finalization for demon ID %d\n", work->demon_id);
			RW_RDLOCK(&child->result_rwlock);
			if (!child->result) ERR_EXIT("Error: Missing child result for component %d\n", i);
			component_nodes[i] = child->result;
			RW_UNLOCK_RD(&child->result_rwlock);
		}
		RW_UNLOCK_RD(&work->child_rwlock);
		RW_WRLOCK(&work->result_rwlock);
		if (work->result) {
			RW_UNLOCK_WR(&work->result_rwlock);
			SPAM_LOG("Concurrent attempt at updating result for demon ID %d\n", work->demon_id);
			free(component_nodes);
			return;
		}
		FusionNode* result_node = create_fusion_node(work->demon_id, component_count, component_nodes);
		free(component_nodes);
		work->result = result_node;
		RW_UNLOCK_WR(&work->result_rwlock);
		signal_up(work);
	}
}

static bool recursive_cycle_check(WorkItem* current_work, WorkItem* target_work) {
	if (!current_work || !target_work) {
		ERR_LOG("Warning: Invalid parameters to recursive_cycle_check\n");
		return false;
	}
	if (current_work == target_work) return true; // cycle detected
	SPAM_LOG("recursive_cycle_check: work=%p demon=%d, fusion_count=%d, children=%p\n", current_work, current_work->demon_id, current_work->fusion_count, current_work->children);
	SPAM_LOG("BITMASK_AND: child=%p, child->available_demons at %p, target_work->available_demons at %p\n", current_work, &current_work->available_demons, &target_work->available_demons);
	for (int i = 0; i < current_work->fusion_count; i++) {
		SPAM_LOG("  fusion[%d]: components=%p, component_count=%d\n", i, current_work->children[i].components, current_work->children[i].component_count);
		if (!current_work->children || !current_work->children[i].components) {
			ERR_LOG("Warning: Null child fusion encountered during recursive_cycle_check for demon ID %d\n", current_work->demon_id);
			continue;
		}
		for (char c = 0; c < current_work->children[i].component_count; c++) {
			SPAM_LOG("    component[%d]: child_work=%p (demon %d)\n", c, current_work->children[i].components[c], current_work->children[i].components[c] ? current_work->children[i].components[c]->demon_id : -1);
			if (!current_work->children[i].components[c]) ERR_EXIT("Error: Null child work item encountered during recursive_cycle_check for demon ID %d\n", current_work->demon_id);
			SPAM_LOG("Before recursion: child_work[%d][%d] = %p (demon %d)\n", i, c, current_work->children[i].components[c], current_work->children[i].components[c] ? current_work->children[i].components[c]->demon_id : -1);
			RW_RDLOCK(&current_work->children[i].components[c]->child_rwlock); // lock child work item to safely check its children for cycles
			if (recursive_cycle_check(current_work->children[i].components[c], target_work)) {
				RW_UNLOCK_RD(&current_work->children[i].components[c]->child_rwlock);
				SPAM_LOG("Cycle detected during recursive check: Demon ID %d is a component of its own parent demon ID %d\n", current_work->children[i].components[c]->demon_id, current_work->demon_id);
				return true;
			}
			SPAM_LOG("After recursion, before BITMASK_AND: child_work[%d][%d] = %p (demon %d)\n", i, c, current_work->children[i].components[c], current_work->children[i].components[c] ? current_work->children[i].components[c]->demon_id : -1);
			RW_UNLOCK_RD(&current_work->children[i].components[c]->child_rwlock);
		}
	}
	return false;
}

static inline bool add_demons_to_work_queue(WorkItem* parent_work, Demon** demons, int demon_count) {
	if (!parent_work || !demons) {
		ERR_LOG("Warning: Invalid parameters to add_demons_to_work_queue\n");
		return false;
	}
	SPAM_LOG("Adding %d demons to work queue for parent demon ID: %d\n", demon_count, parent_work->demon_id);
	RW_RDLOCK(&parent_work->child_rwlock); // lock parent work item to safely check its children for cycles before adding new fusions
	for (char demon_index = 0; demon_index < demon_count; demon_index++) { // first check for cycles
		if (!demons[demon_index]) {
			ERR_LOG("Warning: NULL demon pointer at index %d in add_demons_to_work_queue\n", demon_index);
			return false;
		}
		// Read demon->work_item under the demon's work_rwlock to avoid races
		WorkItem* child_work = NULL;
		RW_RDLOCK(&demons[demon_index]->work_rwlock);
		child_work = demons[demon_index]->work_item;
		RW_UNLOCK_RD(&demons[demon_index]->work_rwlock);
		if (!child_work) continue;
		if (!BITMASK_TEST(&child_work->available_demons, parent_work->demon_id)) continue; // this work has previously been checked for cycles

		// RW_RDLOCK(&child_work->child_rwlock); // lock child work item to safely check its children for cycles
		// if (recursive_cycle_check(child_work, parent_work)) { // cycle detected, do not add this fusion
		// 	RW_UNLOCK_RD(&child_work->child_rwlock);
		// 	SPAM_LOG("Cycle detected: Demon ID %d is a component of its own parent demon ID %d\n", child_work->demon_id, parent_work->demon_id);
		// 	BITMASK_CLEAR(&parent_work->available_demons, demons[demon_index] - all_demons); // mark this demon as unavailable for future fusions in this branch
		// 	return false;
		// }
		// BITMASK_AND(&child_work->available_demons, &parent_work->available_demons); // merge available demons to prevent future cycles through other paths
		// RW_UNLOCK_RD(&child_work->child_rwlock);

		WorkItem* stack[MAX_DEMONS]; // Local stack for DFS
		int stack_top = 0; // index for next push, also represents current stack size
		int visited_count = 0; // count of visited nodes, also serves as index for visited array
		bool seen[MAX_DEMONS] = {false}; // track seen demon IDs to avoid processing duplicates in the stack
		seen[child_work->demon_id] = true; // mark the child work's demon ID as seen
		stack[stack_top++] = child_work; // start DFS from the child work item
		while (visited_count != stack_top) {
			WorkItem* node = stack[visited_count++];
			int demon_id = node->demon_id;
			if (!BITMASK_TEST(&parent_work->available_demons, demon_id)) {
				for (int i = 0; i < visited_count - 1; i++) RW_UNLOCK_RD(&stack[i]->child_rwlock);
				SPAM_LOG("Cycle detected: Component %d is an ancestor of parent %d\n", demon_id, parent_work->demon_id);
				BITMASK_CLEAR(&parent_work->available_demons, demons[demon_index] - all_demons); // mark this demon as unavailable for future fusions in this branch
				RW_UNLOCK_RD(&parent_work->child_rwlock); // unlock the current node before returning since we won't be processing it further
				return false;
			}
			RW_RDLOCK(&node->child_rwlock); // lock node to safely check its children for cycles and to merge available demons
			if (!BITMASK_TEST(&node->available_demons, parent_work->demon_id)) continue; // this node has previously been checked for cycles with this parent work item, skip further processing but keep it locked to preserve stack structure for unlocking at the end
			for (int f = 0; f < node->fusion_count; f++) if (!node->children[f].components) {
				ERR_LOG("Warning: Null child fusion encountered during cycle check for demon ID %d\n", node->demon_id);
				continue;
			} else for (int c = 0; c < node->children[f].component_count; c++) if (!node->children[f].components[c]) {
				ERR_LOG("Warning: Null child work item encountered during cycle check for demon ID %d\n", node->demon_id);
				continue;
			} else if (node->children[f].components[c]->demon_id < 0 || node->children[f].components[c]->demon_id >= MAX_DEMONS) {
				ERR_LOG("Warning: Demon ID %d out of bounds during cycle check\n", node->children[f].components[c]->demon_id);
				continue;
			} else if (!seen[node->children[f].components[c]->demon_id]) {
				stack[stack_top++] = node->children[f].components[c];
				seen[node->children[f].components[c]->demon_id] = true; // mark as seen when pushing to avoid duplicates in stack
				if (stack_top >= MAX_DEMONS) ERR_EXIT("Error: Stack overflow during cycle check, too many nodes in the subtree for demon ID %d\n", node->demon_id);
			}
		} // No cycle found: propagate the parent's availability mask to every node in the subtree
		for (int stack_index = 0; stack_index < visited_count; stack_index++) {
			if (!stack[stack_index]) ERR_EXIT("Error: Null work item in stack[%d] during cycle check for parent demon ID %d\n", stack_index, parent_work->demon_id);
			BITMASK_AND(&stack[stack_index]->available_demons, &parent_work->available_demons);
			RW_UNLOCK_RD(&stack[stack_index]->child_rwlock); // unlock each node after merging available demons
		}

	} // if we reach here, no cycles detected, we can safely add the fusion
	RW_UNLOCK_RD(&parent_work->child_rwlock); // release read lock before acquiring write lock to add new fusion
	SPAM_LOG("No cycles detected for any components, proceeding to add fusion for parent demon ID %d\n", parent_work->demon_id);
	RW_WRLOCK(&parent_work->child_rwlock);
	for (char i = 0; i < demon_count; i++) if (!CHECK_DEMON_AVAILABILITY(parent_work, demons[i])) {
		SPAM_LOG("Demon ID %d was concurrently set to not available to parent demon ID %d, skipping this fusion\n", (int)(demons[i] - all_demons), parent_work->demon_id);
		RW_UNLOCK_WR(&parent_work->child_rwlock);
		return false;
	}
	parent_work->children = (ChildFusion*)realloc(parent_work->children, (parent_work->fusion_count + 1) * sizeof(ChildFusion));
	if (!parent_work->children) {
		ERR_EXIT("Error: Failed to expand parent children array for demon ID %d\n", parent_work->demon_id);
		RW_UNLOCK_WR(&parent_work->child_rwlock);
		return false;
	}
	parent_work->children[parent_work->fusion_count].components = (WorkItem**)malloc(demon_count * sizeof(WorkItem*));
	if (!parent_work->children[parent_work->fusion_count].components) {
		ERR_EXIT("Error: Failed to allocate child pointers for parent demon ID %d\n", parent_work->demon_id);
		RW_UNLOCK_WR(&parent_work->child_rwlock);
		return false;
	}
	parent_work->children[parent_work->fusion_count].component_count = demon_count;
	char processed_children = 0;
	for (char i = 0; i < demon_count; i++) {
		Demon* demon = demons[i];
		WorkItem* child_work;
		RW_RDLOCK(&demon->work_rwlock);
		if (!demon->work_item) {
			RW_UNLOCK_RD(&demon->work_rwlock);
			child_work = create_work_item(demon - all_demons, &parent_work->available_demons, parent_work->depth + 1);
			if (!child_work) ERR_EXIT("Error: Failed to create work item for demon ID: %d\n", (int)(demon - all_demons));
		} else {
			child_work = demon->work_item;
			RW_UNLOCK_RD(&demon->work_rwlock);
			RW_RDLOCK(&child_work->result_rwlock);
			if (child_work->result) processed_children++;
			RW_UNLOCK_RD(&child_work->result_rwlock);
		}
		MUTEX_LOCK(&parent_work->parent_mutex);
		MUTEX_LOCK(&child_work->parent_mutex);
		if (!child_work->parent[parent_work->demon_id].parent) child_work->parent[parent_work->demon_id].parent = parent_work;
		child_work->parent[parent_work->demon_id].ref_count += 1;
		for (int p = 0; p < MAX_DEMONS; p++) if (parent_work->parent[p].lifetime > 0 && parent_work->parent[p].lifetime > child_work->parent[p].lifetime + 1) {
			child_work->parent[p].lifetime = parent_work->parent[p].lifetime - 1; // propagate any existing lifetime constraints from parent to child
			if (!child_work->parent[p].parent && parent_work->parent[p].parent) child_work->parent[p].parent = parent_work->parent[p].parent; // propagate parent pointer for any existing lifetime constraints to maintain correct structure for future pruning
		}
		MUTEX_UNLOCK(&child_work->parent_mutex);
		MUTEX_UNLOCK(&parent_work->parent_mutex);
		parent_work->children[parent_work->fusion_count].components[i] = child_work;
	}
	parent_work->fusion_count++;
	RW_UNLOCK_WR(&parent_work->child_rwlock);
	if (processed_children == demon_count) return true;
	return false;
}

static THREAD_RETURN_TYPE worker_thread(void* arg) {
	Worker* worker = (Worker*)arg;
	WorkQueue* queue = worker->queue;
	DEBUG_LOG("Worker %d started\n", worker->id);
#ifdef SPAM
	char filename[64];
	snprintf(filename, sizeof(filename), "fusion_worker%d_debug.log", worker->id);
	FILE* worker_file = fopen(filename, "w");
	if (!worker_file) ERR_EXIT("Error: Failed to open worker log file\n");
#endif
	while (true) {
		WORKER_LOG("Waiting for work\n");
		MUTEX_LOCK(&queue->queue_mutex); // start of critical section for dequeuing work
		while (queue->count == 0 && !queue->shutdown) COND_WAIT(&queue->queue_not_empty, &queue->queue_mutex); // wait for work or shutdown signal
		if (queue->shutdown) {
			MUTEX_UNLOCK(&queue->queue_mutex);
			WORKER_LOG("Shutdown signal received while waiting for work, exiting\n");
			THREAD_EXIT(0);
		}
		WorkItem* work = queue->items[queue->front];
		queue->front = (queue->front + 1);
		queue->count--;
		MUTEX_UNLOCK(&queue->queue_mutex); // end of critical section for dequeuing work
		WORKER_LOG("Beginning work for demon %d at depth %d. Work=%p\n", work->demon_id, work->depth, (void*)work);
		if (work->demon_id < 0 || work->demon_id >= MAX_DEMONS) ERR_EXIT("Error: Demon ID %d out of bounds in worker_thread %d\n", work->demon_id, worker->id);
		if (base_demons[work->demon_id]) {
			WORKER_LOG("Demon ID: %d is a base demon, creating leaf fusion node\n", work->demon_id);
			RW_WRLOCK(&work->result_rwlock);
			if (work->result) { // if this happens something went very wrong with concurrent work item creation, log and skip
				RW_UNLOCK_WR(&work->result_rwlock);
				ERR_LOG("Warning: Concurrent attempt at creating leaf node for demon ID %d\n", work->demon_id);
			} else {
				work->result = create_fusion_node(work->demon_id, 0, NULL); // leaf node
				RW_UNLOCK_WR(&work->result_rwlock);
				signal_up(work);
			}
		} else { // explore fusions
			BITMASK_CLEAR(&work->available_demons, work->demon_id); // mark self as unavailable to prevent self-fusion
			WORKER_LOG("Awaiting depth permission for demon ID: %d at depth %d\n", work->demon_id, work->depth);
			if (work->depth > work_depth_limit) {
				MUTEX_LOCK(&active_work_mutex); // Double Checked Lock for depth limit
				while (work->depth > work_depth_limit && !work_queue->shutdown) COND_WAIT(&work_depth_cond, &active_work_mutex);
				MUTEX_UNLOCK(&active_work_mutex); // unlock after granted permission to proceed
			}
			if (work_queue->shutdown) {
					MUTEX_UNLOCK(&active_work_mutex);
					WORKER_LOG("Shutdown signal received while waiting for depth permission, exiting\n");
					THREAD_EXIT(0);
			}
			WORKER_LOG("Proceeding with demon ID: %d at depth %d\n", work->demon_id, work->depth);
			Demon* demon = &all_demons[work->demon_id];
			bool any_completed = false;
			for (char f = 0; f < demon->fusion_count; f++) {
				if (demon->fusions[f].demon_components != NULL) { // special fusion
					WORKER_LOG("Processing special fusion for demon ID: %d\n", work->demon_id);
					bool all_available = true;
					for (int i = 0; i < demon->fusions[f].component_count; i++) if (!CHECK_DEMON_AVAILABILITY(work, demon->fusions[f].demon_components[i])) {
						all_available = false;
						break; // if any component is unavailable, skip this fusion
					}
					if (all_available && add_demons_to_work_queue(work, demon->fusions[f].demon_components, demon->fusions[f].component_count)) any_completed = true;
				} else if (demon->fusions[f].component_count >= 0) { // racial fusion to make elementals
					for (int demon1 = 0; demon1 < demons_by_race[demon->fusions[f].component_count].count; demon1++) {
						const Demon* comp1 = demons_by_race[demon->fusions[f].component_count].demons[demon1];
						if (!CHECK_DEMON_AVAILABILITY(work, comp1)) continue;
						for (int demon2 = demon1 + 1; demon2 < demons_by_race[demon->fusions[f].component_count].count; demon2++) {
							const Demon* comp2 = demons_by_race[demon->fusions[f].component_count].demons[demon2];
							if (!CHECK_DEMON_AVAILABILITY(work, comp2)) continue;
							WORKER_LOG("Adding racial fusion for demon ID: %d using components %d and %d\n", work->demon_id, comp1 - all_demons, comp2 - all_demons);
							if (add_demons_to_work_queue(work, (Demon*[]){(Demon*)comp1, (Demon*)comp2}, 2)) any_completed = true;
						}
					}
				} else { // regular fusion (level or elemental)
					WORKER_LOG("Processing regular fusion for demon ID: %d\n", work->demon_id);
					for (char race1 = 0; race1 < MAX_RACES; race1++) for (char race2 = race1 + 1; race2 < MAX_RACES; race2++) if (race_fusions[race1][race2] == all_demons[work->demon_id].race) {
						RaceArray* race1_array = &demons_by_race[race1];
						RaceArray* race2_array = &demons_by_race[race2];
						for (int demon1 = 0; demon1 < race1_array->count && race1_array->demons[demon1]->level < all_demons[work->demon_id].fusions[f].max_level; demon1++) {
							const Demon* comp1 = race1_array->demons[demon1];
							if (comp1->level < all_demons[work->demon_id].fusions[f].min_level - 99 || !CHECK_DEMON_AVAILABILITY(work, comp1)) continue;
							for (int demon2 = 0; demon2 < race2_array->count && race2_array->demons[demon2]->level + comp1->level <= all_demons[work->demon_id].fusions[f].max_level; demon2++) {
								const Demon* comp2 = race2_array->demons[demon2];
								if (comp1->level + comp2->level < all_demons[work->demon_id].fusions[f].min_level || !CHECK_DEMON_AVAILABILITY(work, comp2)) continue;
								WORKER_LOG("Adding level fusion for demon ID: %d using components %d (Level %d) and %d (Level %d)\n", work->demon_id, comp1 - all_demons, comp1->level, comp2 - all_demons, comp2->level);
								if (add_demons_to_work_queue(work, (Demon*[]){(Demon*)comp1, (Demon*)comp2}, 2)) any_completed = true;
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
					WORKER_LOG("Processing elemental fusions for demon ID: %d\n", work->demon_id);
					for (int e = 0; e < ELEMENTALS; e++) if (elemental_chart[e][all_demons[work->demon_id].race] != 0 && CHECK_DEMON_AVAILABILITY(work, elemental_ids[e])) {
						const char direction = elemental_chart[e][all_demons[work->demon_id].race];
						char i = all_demons[work->demon_id].anchor_group - race_anchors[all_demons[work->demon_id].race].groups + direction; // start just past the starting anchor
						for (; i >= 0 && i < race_anchors[all_demons[work->demon_id].race].group_count; i += direction) {
							for (int j = 0; j < race_anchors[all_demons[work->demon_id].race].groups[i].demon_count; j++) {
								const Demon* demon_ptr = race_anchors[all_demons[work->demon_id].race].groups[i].demons[j];
								if (!demon_ptr) continue;
								if (!CHECK_DEMON_AVAILABILITY(work, demon_ptr)) continue;
								WORKER_LOG("Adding elemental fusion for demon ID: %d using components %d and %d\n", work->demon_id, elemental_ids[e] - all_demons, demon_ptr - all_demons);
								if (add_demons_to_work_queue(work, (Demon*[]){(Demon*)elemental_ids[e], (Demon*)demon_ptr}, 2)) any_completed = true;
							}
							if (race_anchors[all_demons[work->demon_id].race].groups[i].is_anchor) break; // stop after processing next anchor
						}
					}
				}
			}
			for (int i = 0; i < MAX_DEMONS; i++) {
				WorkItem* parent_to_update = NULL;
				if (work->parent[i].parent && work->parent[i].lifetime == 0) {
					MUTEX_LOCK(&work->parent_mutex);
					if (work->parent[i].parent && work->parent[i].lifetime == 0) {
						WORKER_LOG("Demon %d has parent demon ID %d with expired lifetime, updating parent work\n", work->demon_id, i);
						parent_to_update = work->parent[i].parent;
						work->parent[i].lifetime = -1; // Prevent continuous duplicate updates
					}
					MUTEX_UNLOCK(&work->parent_mutex);
				}
				if (parent_to_update) update_this_work(parent_to_update);
			}
			if (any_completed) {
				WORKER_LOG("Some fusions completed immediately for demon ID: %d at depth %d, updating work\n", work->demon_id, work->depth);
				update_this_work(work);
			} else {
				RW_RDLOCK(&work->child_rwlock); // lock to safely check if we can prune any parent fusions due to dead branch
				if (work->fusion_count != 0) RW_UNLOCK_RD(&work->child_rwlock);
				else { // this branch is a dead end, prune any parent fusions that rely on this work item
					RW_UNLOCK_RD(&work->child_rwlock); // unlock before acquiring write lock to avoid deadlock with any concurrent finalization attempts
					RW_WRLOCK(&work->result_rwlock); // lock result to prevent concurrent finalization while pruning
					if (work->result) {
						RW_UNLOCK_WR(&work->result_rwlock);
						ERR_LOG("Warning: Concurrent attempt at pruning finalized work for demon ID %d\n", work->demon_id);
					} else { // create a special marker node to indicate this work item is a dead end, so that any concurrent attempts at finalization will fail and trigger pruning instead of creating an invalid result
						work->result = create_fusion_node(work->demon_id, 0, NULL);
						work->result->fusion_count = MAX_DEMONS; // set fusion count to max to prompt all links to this node to prune themselves immediately without needing to check children
						RW_UNLOCK_WR(&work->result_rwlock);
						WORKER_LOG("Pruning parent fusions for demon ID %d due to dead end branch\n", work->demon_id);
						signal_up(work);
					}
				}
			}
		} // finish processing demon, update active work count and possibly allow next depth level to proceed
		MUTEX_LOCK(&active_work_mutex);
		active_work_items[work->depth]--; // decrement active work count for this depth
		for (int d = 0; d < DEPTH_LIMIT; d++) if (active_work_items[d] != 0) {
			WORKER_LOG("Active work being set to %d by demon %d\n", d, work->demon_id);
			work_depth_limit = d; // allow next depth level to process only if all work at current level is done
			COND_BROADCAST(&work_depth_cond);
			break;
		}
#ifdef DEBUG
		processed_work_items++; // protected by global mutex, syn unneeded
		WORKER_LOG("Finished processing demon ID: %d at depth %d\n", work->demon_id, work->depth);
		printf("Progress: %d work items processed, current depth limit is %d\n", processed_work_items, work_depth_limit);
#endif
		MUTEX_UNLOCK(&active_work_mutex);
	}
	return 0;
}

static inline void print_fusion_tree(FusionNode* node, int depth) {
	if (!node) return;
	for (int i = 0; i < depth; i++) printf("  ");
	printf("Demon %d (Race: %d, Level: %d)", node->demon_id, all_demons[node->demon_id].race, all_demons[node->demon_id].level);
	if (node->component_count == 0) printf(" [BASE]\n");
	else {
		printf(" [%d fusions, %d demons total]\n", node->fusion_count, node->demon_count);
		for (int i = 0; i < node->component_count; i++) print_fusion_tree(node->components[i], depth + 1);
	}
}

int main(int argc, char* argv[]) {
#ifdef DEBUG
	start_time = time(NULL);
	debug_file = my_fopen("fusion_debug.log", "w");
	SPAM_LOG("Debug verbose logging enabled\n");
#endif
	// Parse command line arguments
	if (argc < 4) ERR_EXIT("Error: Usage: %s <target_demon> [base_demon1] [base_demon2] ...\n", argv[0]);
	target_demon_id = atoi(argv[1]);
	DEBUG_LOG("Target demon ID: %d\n", target_demon_id);
	if (target_demon_id < 0 || target_demon_id >= MAX_DEMONS) ERR_EXIT("Error: Invalid target demon ID: %s\n", argv[1]);
	for (int i = 2; i < argc; i++) {
		int demon_id = atoi(argv[i]);
		if (demon_id < 0 || demon_id >= MAX_DEMONS) ERR_LOG("Warning: Skipping invalid demon ID: %s\n", argv[i]);
		DEBUG_LOG("Adding base demon ID: %d\n", demon_id);
		base_demons[demon_id] = true;
	} // finish parsing command line arguments, now initialize data structures and load data from files
	MUTEX_INIT(&solution_mutex);
	COND_INIT(&solution_cond);
	MUTEX_INIT(&active_work_mutex);
	COND_INIT(&work_depth_cond);
	DEBUG_LOG("Initializing data structures...\n");
	DEBUG_LOG("Loading demon data...\n");
	load_demons("data/c/c_demons.json");
	DEBUG_LOG("Loading race fusions...\n");
	load_race_fusions("data/c/c_race_fusions.json");
	DEBUG_LOG("Loading elemental chart...\n");
	load_elemental_chart("data/c/c_elemental_chart.json");
	DEBUG_LOG("Loading race anchors...\n");
	load_race_anchors("data/c/c_race_anchors.json");
	int num_workers = get_num_cpus(); // initialize thread pool after loading all data to avoid unnecessary synchronization on work items during loading phase
	DEBUG_LOG("Detected %d CPU cores, initializing thread pool\n", num_workers, num_workers);
	workers = (Worker*)malloc(num_workers * sizeof(Worker));
	if (!workers) ERR_EXIT("Error: Failed to allocate memory for worker threads\n");
	work_queue = (WorkQueue*)malloc(sizeof(WorkQueue));
	if (!work_queue) ERR_EXIT("Error: Failed to allocate memory for work queue\n");
	work_queue->front = 0;
	work_queue->rear = 0;
	work_queue->count = 0;
	work_queue->shutdown = false;
	MUTEX_INIT(&work_queue->queue_mutex);
	COND_INIT(&work_queue->queue_not_empty); // work_queue finished initializing, now create worker threads
	for (int i = 0; i < num_workers; i++) {
		workers[i].id = i;
		workers[i].queue = work_queue;
		if (!THREAD_CREATE(workers[i].thread, worker_thread, &workers[i])) ERR_EXIT("Error: Failed to create worker thread %d\n", i);
	} // initialization complete, start processing fusions
	printf("Finding fusion chain for demon %d...\n", target_demon_id);
	DEBUG_LOG("Starting fusion chain search for demon ID: %d\n", target_demon_id);
	Bitmask available_demons;
	BITMASK_SET_ALL(&available_demons);
	WorkItem* root_work = create_work_item(target_demon_id, &available_demons, 0);
	if (!root_work) ERR_EXIT("Error: Failed to create root work item\n");
	MUTEX_LOCK(&solution_mutex);
	while (!root_work->result) COND_WAIT(&solution_cond, &solution_mutex);
	MUTEX_UNLOCK(&solution_mutex);
	for (int i = 0; i < num_workers; i++) THREAD_JOIN(workers[i].thread);
	DEBUG_LOG("Fusion chain found for demon %d\n", target_demon_id);
	FusionNode* result = root_work->result; // finished processing, now print results and performance statistics
	if (!result) printf("\nNo fusion chain found for demon %d\n", target_demon_id);
	else {
		printf("\nFound optimal fusion chain for demon %d:\n", target_demon_id);
		printf("Total fusions: %d\n", result->fusion_count);
		printf("Total demons used: %d\n", result->demon_count);
		print_fusion_tree(result, 0);
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
