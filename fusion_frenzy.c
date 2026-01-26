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

#include <windows.h>
#include <process.h>
#define A_THREAD HANDLE
#define THREAD_RETURN_TYPE DWORD WINAPI
#define THREAD_CREATE(thread, func, arg) (thread = CreateThread(NULL, 0, func, arg, 0, NULL))
#define THREAD_JOIN(thread) WaitForSingleObject(thread, INFINITE)
#define THREAD_EXIT(value) ExitThread((DWORD)value)
#define MUTEX CRITICAL_SECTION
#define MUTEX_INIT(mutex) InitializeCriticalSection(&mutex)
#define MUTEX_LOCK(mutex) EnterCriticalSection(&mutex)
#define MUTEX_UNLOCK(mutex) LeaveCriticalSection(&mutex)
#define MUTEX_DESTROY(mutex) DeleteCriticalSection(&mutex)

// For older Windows versions without condition variables
#if (_WIN32_WINNT >= 0x0600)
#define CONDITION_VAR CONDITION_VARIABLE
#define COND_INIT(cond) InitializeConditionVariable(&cond)
#define COND_WAIT(cond, mutex) SleepConditionVariableCS(&cond, &mutex, INFINITE)
#define COND_SIGNAL(cond) WakeConditionVariable(&cond)
#define COND_BROADCAST(cond) WakeAllConditionVariable(&cond)
#define COND_DESTROY(cond) /* No destroy needed */
#else
// Fallback for Windows XP and earlier using manual reset events
typedef struct {
    HANDLE event;
    CRITICAL_SECTION cs;
    int waiters;
} CONDITION_VAR;

#define COND_INIT(cond) do { \
    (cond).event = CreateEvent(NULL, TRUE, FALSE, NULL); \
    InitializeCriticalSection(&(cond).cs); \
    (cond).waiters = 0; \
} while(0)

#define COND_WAIT(cond, mutex) do { \
    EnterCriticalSection(&(cond).cs); \
    (cond).waiters++; \
    LeaveCriticalSection(&(cond).cs); \
    LeaveCriticalSection(&(mutex)); \
    WaitForSingleObject((cond).event, INFINITE); \
    EnterCriticalSection(&(cond).cs); \
    (cond).waiters--; \
    if ((cond).waiters == 0) ResetEvent((cond).event); \
    LeaveCriticalSection(&(cond).cs); \
    EnterCriticalSection(&(mutex)); \
} while(0)

#define COND_SIGNAL(cond) do { \
    EnterCriticalSection(&(cond).cs); \
    if ((cond).waiters > 0) SetEvent((cond).event); \
    LeaveCriticalSection(&(cond).cs); \
} while(0)

#define COND_BROADCAST(cond) do { \
    EnterCriticalSection(&(cond).cs); \
    if ((cond).waiters > 0) SetEvent((cond).event); \
    LeaveCriticalSection(&(cond).cs); \
} while(0)

#define COND_DESTROY(cond) do { \
    CloseHandle((cond).event); \
    DeleteCriticalSection(&(cond).cs); \
} while(0)
#endif

#define SYNC_ADD(ptr, val) InterlockedExchangeAdd((volatile LONG*)(ptr), (LONG)(val))

#else
#include <pthread.h>
#include <unistd.h>
#include <sys/sysinfo.h>
#define A_THREAD pthread_t
#define THREAD_RETURN_TYPE void*
#define THREAD_CREATE(thread, func, arg) pthread_create(&thread, NULL, func, arg)
#define THREAD_JOIN(thread) pthread_join(thread, NULL)
#define THREAD_EXIT(value) pthread_exit((void*)(size_t)value)
#define MUTEX pthread_mutex_t
#define MUTEX_INIT(mutex) pthread_mutex_init(&mutex, NULL)
#define MUTEX_LOCK(mutex) pthread_mutex_lock(&mutex)
#define MUTEX_UNLOCK(mutex) pthread_mutex_unlock(&mutex)
#define MUTEX_DESTROY(mutex) pthread_mutex_destroy(&mutex)
#define CONDITION_VAR pthread_cond_t
#define COND_INIT(cond) pthread_cond_init(&cond, NULL)
#define COND_WAIT(cond, mutex) pthread_cond_wait(&cond, &mutex)
#define COND_SIGNAL(cond) pthread_cond_signal(&cond)
#define COND_BROADCAST(cond) pthread_cond_broadcast(&cond)
#define COND_DESTROY(cond) pthread_cond_destroy(&cond)

#define SYNC_ADD(ptr, val) __sync_fetch_and_add((ptr), (val))
#endif

#define MAX_DEMONS 687
#define MAX_RACES 41
#define MAX_COMPONENTS 3
#define MAX_FUSIONS 6
#define ELEMENTALS 4

// Forward declarations
typedef struct Demon Demon;

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

// Work item for the queue
typedef struct WorkItem {
	int demon_id; // demon to process
	bool available_demons[MAX_DEMONS]; // available demons for this work item
	int depth; // current depth
	FusionNode* result; // pointer to where to store the result
	MUTEX result_mutex;
	char processed; // where in the processing we are (0 for not started, 1 for processing, 2 for done)
	struct WorkItem** parent; // parents work items (for pruning)
	char parent_count; // number of parents
	MUTEX parent_mutex; // mutex to protect parent data
	struct WorkItem*** children; // child work items
	int fusion_count; // number of fusions
	MUTEX child_mutex; // mutex to protect child data
	int best_fusion_count; // best fusion count found so far
	MUTEX available_mutex; // mutex to protect available demons
	volatile int ref_count; // reference count to manage lifetime across threads
} WorkItem;

typedef struct Demon {
	char race; // race of the demon
	unsigned char level; // level of the demon
	Fusion* fusions;  // Possible fusions for this demon
	char fusion_count; // number of fusions available
	WorkItem* work_item; // work item for this demon
	MUTEX work_mutex; // mutex to protect work item
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
typedef struct Worker {
	A_THREAD thread;
	int id;
	bool active;
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
MUTEX active_work_mutex;
CONDITION_VAR work_depth_cond;
MUTEX solution_mutex;
CONDITION_VAR solution_cond;
// Coarse-grained mutex to protect the work-graph (parent/child relationships)
MUTEX work_graph_mutex;

#ifdef DEBUG
static volatile int total_work_items = 0;
static volatile int processed_work_items = 0;
static volatile int pruned_branches = 0;
static FILE* debug_file;
static FILE* inst_file;
static time_t start_time;
#ifdef SPAM
#endif
#endif

// forward declarations of functions
static void update_this_work(WorkItem* work);
static void destroy_work_item(WorkItem* work);

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
	fread(data, 1, length, file);
	fclose(file);
	data[length] = '\0';
	cJSON* json = cJSON_Parse(data);
	free(data);
	if (!json) {
		fprintf(stderr, "JSON parsing failed\n");
		const char* error_ptr = cJSON_GetErrorPtr();
		if (error_ptr) {
			fprintf(stderr, "Error before: %s\n", error_ptr);
		}
		return NULL;
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
		fprintf(stderr, "Error: Exceeded maximum fusions for demon\n");
		return;
	}
	demon->fusions = (Fusion*)realloc(demon->fusions, (demon->fusion_count + 1) * sizeof(Fusion));
	if (!demon->fusions) {
		fprintf(stderr, "Error: Failed to allocate memory for demon fusions\n");
		exit(EXIT_FAILURE);
	}
#ifdef SPAM
	fprintf(debug_file, "Adding fusion to demon ID: %d, fusion count now: %d\n", (int)(demon - all_demons), demon->fusion_count + 1);
#endif
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
#ifdef SPAM
		fprintf(debug_file, "Loading demon ID: %d\n", demon_id);
#endif
		if (demon_id < 0 || demon_id >= MAX_DEMONS) {
			printf("Warning: Demon ID %d out of bounds\n", demon_id);
			continue;
		}
		cJSON* race = cJSON_GetObjectItem(demon_entry, "race");
		cJSON* level = cJSON_GetObjectItem(demon_entry, "level");
		cJSON* fuse_able = cJSON_GetObjectItem(demon_entry, "fuse_able");
		Demon* this_demon = &all_demons[demon_id];
		MUTEX_INIT(this_demon->work_mutex);
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
				fprintf(stderr, "Error: Failed to reallocate memory for race array\n");
				exit(EXIT_FAILURE);
			}
			demons_by_race[this_demon->race].demons[demons_by_race[this_demon->race].count++] = this_demon;
		}
		if (!(fuse_able && fuse_able->valueint)) continue;
		cJSON* special_fusion = cJSON_GetObjectItem(demon_entry, "special_fusion");
		if (special_fusion && cJSON_IsArray(special_fusion)) {
#ifdef SPAM
			fprintf(debug_file, "Demon %d has special fusions\n", demon_id);
#endif
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
					fprintf(stderr, "Error: Failed to allocate memory for fusion components\n");
					exit(EXIT_FAILURE);
				}
				cJSON* component;
				char index = 0;
				cJSON_ArrayForEach(component, recipe) {
					const int comp_id = component->valueint;
					if (comp_id < 0 || comp_id >= MAX_DEMONS) {
						printf("Warning: demon_id for component is out of bounds: %d\n", comp_id);
						free(this_fusion.demon_components);
						continue;
					}
					this_fusion.demon_components[index] = &all_demons[comp_id];
					index++;
				}
#ifdef SPAM
				fprintf(debug_file, "Adding special fusion for demon %d with %d components\n", demon_id, this_fusion.component_count);
#endif
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
#ifdef SPAM
					fprintf(debug_file, "Adding racial fusion for demon %d with race %d\n", demon_id, this_fusion.component_count);
#endif
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
#ifdef SPAM
				fprintf(debug_file, "Adding regular fusion for demon %d with level range %d-%d\n", demon_id, this_fusion.min_level, this_fusion.max_level);
#endif
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
#ifdef SPAM
	fprintf(debug_file, "Total demons loaded: %d\n", demon_count);
#endif
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
			fprintf(debug_file, "Loading race fusion: %d + %d -> %d\n", race1, race2, result_race);
#endif
			if (race1 < race2) {
				race_fusions[result_race][race1] = race2;
			} else {
				race_fusions[result_race][race2] = race1;
			}
		}
	}
	cJSON_Delete(root);
#ifdef SPAM
	fprintf(debug_file, "Total race fusions loaded: %d\n", race_fusion_count);
#endif
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
			fprintf(debug_file, "Loaded elemental chart data: Elemental %d, Race %d, Value %d\n", elemental_count, race_id, elemental_chart[elemental_count][race_id]);
#endif
		}
		elemental_count++;
	}
	cJSON_Delete(root);
	printf("Loaded elemental chart with %d elementals\n", elemental_count);
#ifdef SPAM
	fprintf(debug_file, "Total elemental chart entries loaded: %d\n", elemental_load_count);
#endif
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
			fprintf(stderr, "Error: malloc failed for race %d anchor groups\n", race_id);
			continue;
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
#ifdef SPAM
				fprintf(debug_file, "Loaded race anchor: Race %d, Group %d, Demon %d\n", race_id, i, demon_id);
#endif
				if (demon->race != race_id) {
					printf("Warning: Demon %d (race %d) placed in wrong race anchor group %d\n", demon_id, demon->race, race_id);
				}
			}
		}
	}
	cJSON_Delete(root);
	printf("Successfully loaded race anchors\n");
#ifdef SPAM
	fprintf(debug_file, "Total race anchor groups loaded: %d\n", race_anchor_count);
#endif
}

static FusionNode* create_fusion_node(const int demon_id, const char component_count, FusionNode** components) {
	FusionNode* node = (FusionNode*)malloc(sizeof(FusionNode));
	if (!node) {
		fprintf(stderr, "Error: Failed to allocate memory for fusion node\n");
		return NULL;
	}
	node->demon_id = demon_id;
	node->component_count = component_count;
	node->demon_count = 1;
	node->fusion_count = 0;
	if (component_count > 0 && components) {
		node->components = (FusionNode**)malloc(component_count * sizeof(FusionNode*));
		if (!node->components) {
			fprintf(stderr, "Error: Failed to allocate memory for fusion node components\n");
			free(node);
			return NULL;
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

static FusionNode* create_leaf_fusion_node(const int demon_id) {
	return create_fusion_node(demon_id, 0, NULL);
}

static WorkQueue* create_work_queue() {
	WorkQueue* queue = (WorkQueue*)malloc(sizeof(WorkQueue));
	if (!queue) {
		fprintf(stderr, "Error: Failed to allocate memory for work queue\n");
		return NULL;
	}
	queue->front = 0;
	queue->rear = 0;
	queue->count = 0;
	queue->shutdown = false;
	MUTEX_INIT(queue->queue_mutex);
	COND_INIT(queue->queue_not_empty);
	return queue;
}

static void destroy_work_queue(WorkQueue* queue) {
	if (!queue) return;
	MUTEX_DESTROY(queue->queue_mutex);
	COND_DESTROY(queue->queue_not_empty);
	free(queue);
}

static bool enqueue_work(WorkQueue* queue, WorkItem* work) {
#ifdef SPAM
	fprintf(debug_file, "Enqueuing work for demon ID: %d at depth %d\n", work->demon_id, work->depth);
#endif
	MUTEX_LOCK(queue->queue_mutex);
	if (queue->shutdown) {
		MUTEX_UNLOCK(queue->queue_mutex);
		return false;
	}
	/* queue holds a reference to the work item */
	SYNC_ADD(&work->ref_count, 1);
	queue->items[queue->rear] = work;
	queue->rear = (queue->rear + 1); // no wrap around needed, max size is MAX_DEMONS ensured by logic
	queue->count++;
	MUTEX_LOCK(active_work_mutex);
	active_work_items[work->depth]++;
	MUTEX_UNLOCK(active_work_mutex);
#ifdef DEBUG
	SYNC_ADD(&total_work_items, 1);
#endif
	COND_SIGNAL(queue->queue_not_empty);
	MUTEX_UNLOCK(queue->queue_mutex);
	return true;
}

static WorkItem* dequeue_work(WorkQueue* queue) {
#ifdef SPAM
	fprintf(debug_file, "Dequeueing work item\n");
#endif
	MUTEX_LOCK(queue->queue_mutex);
	while (queue->count == 0 && !queue->shutdown) {
		COND_WAIT(queue->queue_not_empty, queue->queue_mutex);
	}
	if (queue->shutdown) {
		MUTEX_UNLOCK(queue->queue_mutex);
		return NULL;
	}
	WorkItem* work = queue->items[queue->front];
	queue->front = (queue->front + 1);
	queue->count--;
	MUTEX_UNLOCK(queue->queue_mutex);
#ifdef SPAM
	fprintf(debug_file, "Dequeued work for demon ID: %d at depth %d\n", work->demon_id, work->depth);
#endif
	return work;
}

static void shutdown_work_queue(WorkQueue* queue) {
	MUTEX_LOCK(queue->queue_mutex);
	queue->shutdown = true;
	COND_BROADCAST(queue->queue_not_empty);
	MUTEX_UNLOCK(queue->queue_mutex);
}

static WorkItem* create_work_item(int demon_id, bool* available_demons, int depth) {
	WorkItem* work = (WorkItem*)malloc(sizeof(WorkItem));
	if (!work) {
		fprintf(stderr, "Error: Failed to allocate memory for work item\n");
		return NULL;
	}
	work->demon_id = demon_id;
	memcpy(work->available_demons, available_demons, MAX_DEMONS * sizeof(bool));
	work->depth = depth;
	work->result = NULL;
	MUTEX_INIT(work->result_mutex);
	work->processed = 0;
	work->parent = NULL;
	work->parent_count = 0;
	MUTEX_INIT(work->parent_mutex);
	work->children = NULL;
	work->fusion_count = 0;
	MUTEX_INIT(work->child_mutex);
	work->best_fusion_count = MAX_DEMONS;
	MUTEX_INIT(work->available_mutex);
	/* publish work_item after fully initializing the WorkItem to avoid races */
	/* initialize reference count: 1 for the global `all_demons` pointer */
	work->ref_count = 1;
	/* publish under graph lock to avoid races with readers/destroyers */
	MUTEX_LOCK(work_graph_mutex);
	all_demons[demon_id].work_item = work;
	MUTEX_UNLOCK(work_graph_mutex);
	return work;
}

static inline void work_dec_ref(WorkItem* w) {
	if (!w) {
		fprintf(stderr, "Error: work_dec_ref called with NULL\n");
		return;
	}
	if (SYNC_ADD(&w->ref_count, -1) == 1) {
		destroy_work_item(w);
	}
}

static void destroy_work_item(WorkItem* work) {
	if (!work) return;
	/* Protect graph modifications while tearing down children/parents */
	MUTEX_LOCK(work_graph_mutex);
	if (work->children) {
		/* release references to children held by this work item */
		int comp_count = all_demons[work->demon_id].fusions ? (all_demons[work->demon_id].fusions->demon_components ? all_demons[work->demon_id].fusions->component_count : 2) : 2;
		for (int i = 0; i < work->fusion_count; i++) {
			if (work->children[i]) {
				for (int c = 0; c < comp_count; c++) {
					WorkItem* child = work->children[i][c];
					if (child) {
						work_dec_ref(child);
					}
				}
				free(work->children[i]);
				work->children[i] = NULL;
			}
		}
		free(work->children);
		work->children = NULL;
	}
	if (work->parent) {
		free(work->parent);
		work->parent = NULL;
	}
	MUTEX_DESTROY(work->result_mutex);
	MUTEX_DESTROY(work->parent_mutex);
	MUTEX_DESTROY(work->child_mutex);
	all_demons[work->demon_id].work_item = NULL;
	MUTEX_UNLOCK(work_graph_mutex);
	free(work);
}

static void set_result(WorkItem* work, FusionNode* result) {
	MUTEX_LOCK(work->result_mutex);
	work->result = result;
	MUTEX_UNLOCK(work->result_mutex);
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
	int incomplete_count = 1;
	for (char comp = 0; comp < component_count; comp++) {
		if (!child_work[comp]) {
			fprintf(stderr, "Error: null child work item encountered during count_incomplete_children\n");
		}
		MUTEX_LOCK(child_work[comp]->result_mutex);
		if (child_work[comp]->result) {
			incomplete_count += child_work[comp]->result->fusion_count;
			MUTEX_UNLOCK(child_work[comp]->result_mutex);
			continue;
		}
		MUTEX_UNLOCK(child_work[comp]->result_mutex);
		char component_count = all_demons[child_work[comp]->demon_id].fusions->demon_components ? all_demons[child_work[comp]->demon_id].fusions->component_count : 2;
		char this_count = child_work[comp]->fusion_count == 0 ? 1 : MAX_DEMONS;
		for (char c = 0; c < child_work[comp]->fusion_count; c++) {
			if (count_incomplete_children(child_work[comp]->children[c], component_count) < this_count) {
				this_count = count_incomplete_children(child_work[comp]->children[c], component_count);
			}
		}
		incomplete_count += this_count;
	}
	return incomplete_count;
}

// prune a fusion from a work item, steps into children to remove a parent reference
static void prune_fusion(WorkItem* parent, char fusion_index, char component_count) {
#ifdef SPAM
	fprintf(debug_file, "Pruning fusion index %d for demon ID %d\n", fusion_index, parent->demon_id);
#endif
#ifdef SPAM
	if (inst_file) {
		fprintf(inst_file, "[INST] prune_fusion: parent=%d fusion_index=%d component_count=%d parent->fusion_count=%d parent_children=%p\n", parent->demon_id, fusion_index, component_count, parent->fusion_count, (void*)parent->children);
		fflush(inst_file);
	} else {
		fprintf(debug_file, "[INST] prune_fusion: parent=%d fusion_index=%d component_count=%d parent->fusion_count=%d parent_children=%p\n", parent->demon_id, fusion_index, component_count, parent->fusion_count, (void*)parent->children);
		fflush(debug_file);
	}
#endif
	/* Protect graph while removing parent references and updating parent's children */
	MUTEX_LOCK(work_graph_mutex);
	/* Remove parent reference from each child and decrement child's refcount */
	for (int comp = 0; comp < component_count; comp++) {
		WorkItem* child = NULL;
		if (parent->children && parent->children[fusion_index]) child = parent->children[fusion_index][comp];
		if (!child) continue;
		MUTEX_LOCK(child->parent_mutex);
		for (int p = 0; p < child->parent_count; p++) {
			if (child->parent[p] == parent) {
#ifdef SPAM
				fprintf(debug_file, "Removing parent demon ID %d from child demon ID %d\n", parent->demon_id, child->demon_id);
#endif
				for (int q = p; q < child->parent_count - 1; q++) {
					child->parent[q] = child->parent[q + 1];
				}
				child->parent_count--;
				break;
			}
		}
		MUTEX_UNLOCK(child->parent_mutex);
		/* parent no longer references child */
		work_dec_ref(child);
	}
#ifdef SPAM
	fprintf(debug_file, "Removing fusion index %d from parent demon ID %d\n", fusion_index, parent->demon_id);
#endif
	for (int c = fusion_index; c < parent->fusion_count - 1; c++) {
		parent->children[c] = parent->children[c + 1];
	}
	parent->fusion_count--;
	MUTEX_UNLOCK(work_graph_mutex);
#ifdef DEBUG
	SYNC_ADD(&pruned_branches, 1);
#endif
}

static void update_parents(WorkItem* child_work) {
	if (!child_work || !child_work->parent || !child_work->result) {
		fprintf(stderr, "Error: Invalid parameters to update_parents\n");
		return;
	}
	for (char p = 0; p < child_work->parent_count; p++) {
		update_this_work(child_work->parent[p]);
	}
}

static void update_this_work(WorkItem* work) {
	if (!work) {
		fprintf(stderr, "Error: Null work item passed to update_this_work\n");
		return;
	}
	MUTEX_LOCK(work->child_mutex);
	char component_count = all_demons[work->demon_id].fusions->demon_components ? all_demons[work->demon_id].fusions->component_count : 2;
	for (char c = 0; c < work->fusion_count; c++) {
		bool all_done = true;
		int this_fusion_count = 1;
		for (char comp = 0; comp < component_count; comp++) {
			MUTEX_LOCK(work->children[c][comp]->result_mutex);
			if (!work->children[c][comp]->result) {
				all_done = false;
				MUTEX_UNLOCK(work->children[c][comp]->result_mutex);
				break;
			}
			this_fusion_count += work->children[c][comp]->result->fusion_count;
			MUTEX_UNLOCK(work->children[c][comp]->result_mutex);
		}
		if (all_done && this_fusion_count < work->best_fusion_count) {
			work->best_fusion_count = this_fusion_count;
		}
	}
	if (work->best_fusion_count < MAX_DEMONS) { // check for pruning opportunity
		for (char c = 0; c < work->fusion_count; c++) {
			int this_fusion_count = 1;
			bool safe_prune = true;
			for (char comp = 0; comp < component_count; comp++) {
				if (!work->children[c][comp] || !work->children[c][comp]->result) {
					safe_prune = false;
					break;
				}
				this_fusion_count += work->children[c][comp]->result->fusion_count;
			}
			if (safe_prune && this_fusion_count > work->best_fusion_count) {
				prune_fusion(work, c--, component_count);
			} else if (!safe_prune && count_incomplete_children(work->children[c], component_count) >= work->best_fusion_count) {
				prune_fusion(work, c--, component_count);
			}
		}
		if (work->fusion_count == 1) { // only one fusion left, can finalize
			FusionNode** component_nodes = (FusionNode**)malloc(component_count * sizeof(FusionNode*));
			if (!component_nodes) {
				fprintf(stderr, "Error: Failed to allocate memory for component nodes\n");
				return;
			}
			for (char i = 0; i < component_count; i++) {
				if (work->children[0][i] && work->children[0][i]->result) {
					component_nodes[i] = work->children[0][i]->result;
				} else {
					fprintf(stderr, "Error: Missing child result for component %d\n", i);
					free(component_nodes);
					return;
				}
			}
			FusionNode* result_node = create_fusion_node(work->demon_id, component_count, component_nodes);
			free(component_nodes);
			set_result(work, result_node);
			if (work->demon_id == target_demon_id) { // root node
				// signal main thread that we're done
				COND_SIGNAL(solution_cond);
				MUTEX_LOCK(active_work_mutex);
				work_depth_limit = MAX_DEMONS; // unblock all threads
				COND_BROADCAST(work_depth_cond);
				MUTEX_UNLOCK(active_work_mutex);
			} else {
				update_parents(work);
			}
		}
	}
	MUTEX_UNLOCK(work->child_mutex);
}

static bool add_demons_to_work_queue(WorkItem* parent_work, Demon** demons, char demon_count) {
	if (!parent_work || !demons) {
		fprintf(stderr, "Error: Invalid parameters to add_demons_to_work_queue\n");
		return false;
	}
	// Validate demon pointers in the array to avoid NULL dereferences
	for (char i = 0; i < demon_count; i++) {
		if (!demons[i]) {
			fprintf(stderr, "Error: NULL demon pointer at index %d in add_demons_to_work_queue\n", (int)i);
			return false;
		}
	}
#ifdef SPAM
	fprintf(debug_file, "Adding demons to work queue for parent demon ID: %d\n", parent_work->demon_id);
#endif
	/* Grab coarse-grained work-graph lock to avoid races between readers and destroyers */
	MUTEX_LOCK(work_graph_mutex);
	bool add_fusion = true;
	for (char i = 0; i < demon_count; i++) {
		MUTEX_LOCK(demons[i]->work_mutex);
	}
	for (char i = 0; i < demon_count; i++) { // first check for cycles
		if(demons[i]->work_item) {
			WorkItem* child_work = demons[i]->work_item;
			/* take a local reference to prevent simultaneous destroy while inspecting */
			SYNC_ADD(&child_work->ref_count, 1);
#ifdef SPAM
				if (inst_file) {
					fprintf(inst_file, "[INST] add_demons: parent=%d demon_idx=%d demon_id=%d child_work=%p child_work->ref=%d child_work->fusion_count=%d\n", parent_work->demon_id, i, (int)(demons[i]-all_demons), (void*)child_work, child_work?child_work->ref_count:0, child_work?child_work->fusion_count:0);
					fflush(inst_file);
				} else {
					fprintf(debug_file, "[INST] add_demons: parent=%d demon_idx=%d demon_id=%d child_work=%p child_work->ref=%d child_work->fusion_count=%d\n", parent_work->demon_id, i, (int)(demons[i]-all_demons), (void*)child_work, child_work?child_work->ref_count:0, child_work?child_work->fusion_count:0);
					fflush(debug_file);
				}
#endif
			Fusion* child_fusions = all_demons[child_work->demon_id].fusions;
			char child_comp_count = (child_fusions && child_fusions->demon_components) ? child_fusions->component_count : 2;
			for (char f = 0; f < child_work->fusion_count; f++) {
				WorkItem** child_arr = (child_work->children && child_work->children[f]) ? child_work->children[f] : NULL;
				for (char c = 0; c < child_comp_count; c++) {
					if (child_arr && child_arr[c] == parent_work) { // cycle detected, prune and then do not add fusion
#ifdef SPAM
						fprintf(debug_file, "Cycle detected: Demon ID %d is a component of its own parent demon ID %d\n", demons[i]->work_item->demon_id, parent_work->demon_id);
#endif
						prune_fusion(child_work, f--, child_comp_count);
						parent_work->available_demons[demons[i] - all_demons] = false;
						add_fusion = false;
						break;
					}
				}
			}
		}
	}
	/* release local references taken while checking for cycles */
	for (char i = 0; i < demon_count; i++) {
		if (demons[i] && demons[i]->work_item) work_dec_ref(demons[i]->work_item);
	}
	if (!add_fusion) {
		/* release temporary refs taken while checking for cycles */
		for (char i = 0; i < demon_count; i++) {
			if (demons[i] && demons[i]->work_item) work_dec_ref(demons[i]->work_item);
		}
		for (char i = 0; i < demon_count; i++) {
			MUTEX_UNLOCK(demons[i]->work_mutex);
		}
		MUTEX_UNLOCK(work_graph_mutex);
		return false; // do not add this fusion due to cycle
	}
	MUTEX_LOCK(parent_work->child_mutex);
	/* expand children array safely */
	WorkItem*** tmp_children = (WorkItem***)realloc(parent_work->children, (parent_work->fusion_count + 1) * sizeof(WorkItem**));
	if (!tmp_children) {
		fprintf(stderr, "Error: Failed to expand parent children array for demon ID %d\n", parent_work->demon_id);
		MUTEX_UNLOCK(parent_work->child_mutex);
		for (char i = 0; i < demon_count; i++) {
			MUTEX_UNLOCK(demons[i]->work_mutex);
		}
		MUTEX_UNLOCK(work_graph_mutex);
		return false;
	}
	parent_work->children = tmp_children;
	parent_work->children[parent_work->fusion_count] = (WorkItem**)malloc(demon_count * sizeof(WorkItem*));
	if (!parent_work->children[parent_work->fusion_count]) {
		fprintf(stderr, "Error: Failed to allocate child pointers for parent demon ID %d\n", parent_work->demon_id);
		MUTEX_UNLOCK(parent_work->child_mutex);
		for (char i = 0; i < demon_count; i++) {
			MUTEX_UNLOCK(demons[i]->work_mutex);
		}
		MUTEX_UNLOCK(work_graph_mutex);
		return false;
	}
	char processed_children = 0;
	for (char i = 0; i < demon_count; i++) {
		Demon* demon = demons[i];
		WorkItem* child_work;
		if (!demon->work_item) {
			bool available_demons[MAX_DEMONS];
			memcpy(available_demons, parent_work->available_demons, MAX_DEMONS * sizeof(bool));
			child_work = create_work_item(demon - all_demons, available_demons, parent_work->depth + 1);
			if (!child_work) {
				fprintf(stderr, "Error: Failed to create work item for demon ID: %d\n", (int)(demon - all_demons));
				MUTEX_UNLOCK(demon->work_mutex);
				continue;
			}
			MUTEX_LOCK(child_work->parent_mutex);
			child_work->parent = (WorkItem**)malloc(sizeof(WorkItem*));
			child_work->parent[child_work->parent_count++] = parent_work;
			/* parent now references child */
			SYNC_ADD(&child_work->ref_count, 1);
			MUTEX_UNLOCK(child_work->parent_mutex);
			enqueue_work(work_queue, child_work);
		} else {
#ifdef SPAM
			fprintf(debug_file, "Reusing existing work item for demon ID: %d, attaching to parent demon ID: %d\n", (int)(demon - all_demons), parent_work->demon_id);
#endif
			// add parent reference
			child_work = demon->work_item;
			// bitwise and parent's available demons to child's available demons
			MUTEX_LOCK(child_work->available_mutex);
			for (int d = 0; d < MAX_DEMONS; d++) {
				child_work->available_demons[d] = child_work->available_demons[d] & parent_work->available_demons[d];
			}
			MUTEX_UNLOCK(child_work->available_mutex);
			MUTEX_LOCK(child_work->parent_mutex);
			child_work->parent = (WorkItem**)realloc(child_work->parent, (child_work->parent_count + 1) * sizeof(WorkItem*));
			child_work->parent[child_work->parent_count++] = parent_work;
			/* parent now references child */
			SYNC_ADD(&child_work->ref_count, 1);
			if (child_work->result) processed_children++;
			MUTEX_UNLOCK(child_work->parent_mutex);
		}
		/* parent keeps a reference to the child */
		SYNC_ADD(&child_work->ref_count, 1);
		parent_work->children[parent_work->fusion_count][i] = child_work;
		MUTEX_UNLOCK(demon->work_mutex);
	}
	parent_work->fusion_count++;
	MUTEX_UNLOCK(parent_work->child_mutex);
	MUTEX_UNLOCK(work_graph_mutex);
	if (processed_children == demon_count) {
#ifdef SPAM
		fprintf(debug_file, "All child work items already processed for parent demon ID: %d\n", parent_work->demon_id);
#endif
		return true;
	}
	return false;
}

static bool check_demon_availability(WorkItem* work, const Demon* demon) {
	if (!work || !demon) {
		fprintf(stderr, "Error: Invalid parameters to check_demon_availability\n");
		return false;
	}
	int demon_id = demon - all_demons;
	if (demon_id < 0 || demon_id >= MAX_DEMONS) {
		fprintf(stderr, "Error: Demon ID %d out of bounds in check_demon_availability\n", demon_id);
		return false;
	}
	return (work->available_demons[demon_id] && (all_demons[demon_id].fusions != NULL || base_demons[demon_id]));
}

static bool explore_special_fusion(WorkItem* parent_work, Fusion* fusion) {
	if (!parent_work || !fusion || !fusion->demon_components) {
		fprintf(stderr, "Error: Invalid parameters to explore_special_fusion\n");
		return false;
	}
	for (int i = 0; i < fusion->component_count; i++) {
		if (!check_demon_availability(parent_work, fusion->demon_components[i])) {
			return false;
		}
	}
	return add_demons_to_work_queue(parent_work, fusion->demon_components, fusion->component_count);
}

static bool explore_racial_fusion(WorkItem* parent_work, RaceArray* race_array) {
	if (!parent_work || !race_array) {
		fprintf(stderr, "Error: Invalid parameters to explore_racial_fusion\n");
		return false;
	}
	bool completed = false;
	for (int demon1 = 0; demon1 < race_array->count; demon1++) {
		const Demon* comp1 = race_array->demons[demon1];
		if (!check_demon_availability(parent_work, comp1)) continue;
		for (int demon2 = demon1 + 1; demon2 < race_array->count; demon2++) {
			const Demon* comp2 = race_array->demons[demon2];
			if (!check_demon_availability(parent_work, comp2)) continue;
			if (add_demons_to_work_queue(parent_work, (Demon*[]){(Demon*)comp1, (Demon*)comp2}, 2)) completed = true;
		}
	}
	return completed;
}

static bool explore_level_fusion(WorkItem* parent_work, Fusion* fusion) {
	if (!parent_work || !fusion) {
		fprintf(stderr, "Error: Invalid parameters to explore_level_fusion\n");
		return false;
	}
	bool completed = false;
	for (char race1 = 0; race1 < MAX_RACES; race1++) {
		for (char race2 = race1; race2 < MAX_RACES; race2++) {
			if (race_fusions[all_demons[parent_work->demon_id].race][race1] != race2) continue;
			RaceArray* race1_array = &demons_by_race[race1];
			RaceArray* race2_array = &demons_by_race[race2];
			for (int demon1 = 0; demon1 < race1_array->count && race1_array->demons[demon1]->level <= fusion->max_level; demon1++) {
				const Demon* comp1 = race1_array->demons[demon1];
				if (comp1->level < fusion->min_level - 99 || !check_demon_availability(parent_work, comp1)) continue;
				for (int demon2 = 0; demon2 < race2_array->count && race2_array->demons[demon2]->level + comp1->level < fusion->max_level; demon2++) {
					const Demon* comp2 = race2_array->demons[demon2];
					if (comp1->level + comp2->level < fusion->min_level || !check_demon_availability(parent_work, comp2)) continue;
					if (add_demons_to_work_queue(parent_work, (Demon*[]){(Demon*)comp1, (Demon*)comp2}, 2)) completed = true;
				}
			}
		}
	}
	return completed;
}

static bool explore_elemental_fusion(WorkItem* parent_work, Demon* demon) {
	if (!parent_work || !demon || !demon->anchor_group) {
		fprintf(stderr, "Error: Invalid parameters to explore_elemental_fusion\n");
		return false;
	}
	bool completed = false;
	for (int e = 0; e < ELEMENTALS; e++) {
		if (elemental_chart[e][demon->race] == 0 || !check_demon_availability(parent_work, elemental_ids[e])) continue;
		const char direction = elemental_chart[e][demon->race];
		char i = demon->anchor_group - race_anchors[demon->race].groups + direction; // start just past the starting anchor
		for (; i >= 0 && i < race_anchors[demon->race].group_count; i += direction) {
			AnchorGroup* group = &race_anchors[demon->race].groups[i];
			for (int j = 0; j < race_anchors[demon->race].groups[i].demon_count; j++) {
				const Demon* demon_ptr = race_anchors[demon->race].groups[i].demons[j];
				if (!demon_ptr) continue;
				if (!check_demon_availability(parent_work, demon_ptr)) continue;
				if (add_demons_to_work_queue(parent_work, (Demon*[]){(Demon*)elemental_ids[e], (Demon*)demon_ptr}, 2)) completed = true;
			}
			if (race_anchors[demon->race].groups[i].is_anchor) break; // stop after processing next anchor
		}
	}
	return completed;
}

static bool explore_normal_fusion(WorkItem* parent_work, Fusion* fusion) {
	if (!parent_work || !fusion) {
		fprintf(stderr, "Error: Invalid parameters to explore_normal_fusion\n");
		return false;
	}
	bool fusion_completed = explore_level_fusion(parent_work, fusion);
	if (!all_demons[parent_work->demon_id].anchor_group) {
		fprintf(stderr, "Error: Demon %d has no anchor group for elemental fusion\n", parent_work->demon_id);
		return false;
	}
	if (!all_demons[parent_work->demon_id].anchor_group->is_anchor) {
		fprintf(stderr, "Error: Demon %d is not in an anchor group for elemental fusion\n", parent_work->demon_id);
		return false;
	}
	if (explore_elemental_fusion(parent_work, &all_demons[parent_work->demon_id])) fusion_completed = true;
	return fusion_completed;
}

static void process_demon_work(WorkItem* work) {
	if (!work) return;
#ifdef SPAM
	fprintf(debug_file, "Processing work for demon ID: %d at depth %d\n", work->demon_id, work->depth);
#endif
	if (work->depth > MAX_DEMONS / 2) {
		FusionNode* result = (FusionNode*)malloc(sizeof(FusionNode));
		result->components = NULL;
		result->fusion_count = MAX_DEMONS;
		result->demon_count = MAX_DEMONS;
		result->demon_id = work->demon_id;
		result->component_count = 0;
		set_result(work, result);
		return;
	}
	Demon* demon = &all_demons[work->demon_id];
	if (base_demons[work->demon_id]) {
#ifdef SPAM
		fprintf(debug_file, "Demon ID: %d is a base demon, creating leaf fusion node\n", work->demon_id);
#endif
		MUTEX_LOCK(work->result_mutex);
		work->result = create_leaf_fusion_node(work->demon_id);
		MUTEX_LOCK(work->parent_mutex);
		MUTEX_UNLOCK(work->result_mutex);
		update_parents(work);
		MUTEX_UNLOCK(work->parent_mutex);
	} else {
		MUTEX_LOCK(work->available_mutex);
		work->available_demons[work->demon_id] = false;
		MUTEX_UNLOCK(work->available_mutex);
#ifdef SPAM
		fprintf(debug_file, "Exploring fusions for demon ID: %d at depth %d\n", work->demon_id, work->depth);
#endif
		MUTEX_LOCK(active_work_mutex);
		while (work->depth > work_depth_limit && !work_queue->shutdown) { // wait to be allowed to process this level of fusion
			COND_WAIT(work_depth_cond, active_work_mutex);
		}
		if (work_queue->shutdown) {
			MUTEX_UNLOCK(active_work_mutex);
			return;
		}
		MUTEX_UNLOCK(active_work_mutex);
#ifdef SPAM
		fprintf(debug_file, "Worker proceeding with demon ID: %d at depth %d\n", work->demon_id, work->depth);
#endif
		bool any_completed = false;
		for (char f = 0; f < demon->fusion_count; f++) {
			if (demon->fusions[f].demon_components != NULL) {
				if (explore_special_fusion(work, &demon->fusions[f])) any_completed = true;
			} else if (demon->fusions[f].component_count >= 0) {
				if (explore_racial_fusion(work, &demons_by_race[demon->fusions[f].component_count])) any_completed = true; // racial fusions make elementals
			} else {
				if (explore_normal_fusion(work, &demon->fusions[f])) any_completed = true;
			}
		}
		if (any_completed) {
#ifdef SPAM
			fprintf(debug_file, "Some fusions completed immediately for demon ID: %d at depth %d, updating work\n", work->demon_id, work->depth);
#endif
			update_this_work(work);
		}
	}
#ifdef SPAM
	fprintf(debug_file, "Worker finished processing demon ID: %d at depth %d\n", work->demon_id, work->depth);
#endif
	MUTEX_LOCK(active_work_mutex);
	active_work_items[work->depth]--;
	for (int d = 0; d <= work->depth + 1; d++) {
		if (active_work_items[d] > 0) {
#ifdef SPAM
			fprintf(debug_file, "Active work being set to %d\n", d);
#endif
			work_depth_limit = d; // allow next depth level to process only if all work at current level is done
			COND_BROADCAST(work_depth_cond);
			break;
		}
	}
	MUTEX_UNLOCK(active_work_mutex);
}

static THREAD_RETURN_TYPE worker_thread(void* arg) {
	Worker* worker = (Worker*)arg;
	WorkQueue* queue = worker->queue;
#ifdef DEBUG
	fprintf(debug_file, "Worker %d starting\n", worker->id);
#endif
	while (worker->active) {
#ifdef SPAM
		fprintf(debug_file, "Worker %d waiting for work\n", worker->id);
#endif
		WorkItem* work = dequeue_work(queue);
		if (!work) {
			break;
		}
#ifdef SPAM
		fprintf(debug_file, "Worker %d processing demon %d at depth %d\n", worker->id, work->demon_id, work->depth);
#endif
		process_demon_work(work);
#ifdef DEBUG
		SYNC_ADD(&processed_work_items, 1);
#endif
		/* worker no longer needs the queue reference to this work item */
		work_dec_ref(work);
	}
	return 0;
}

static bool init_thread_pool() {
	num_workers = get_num_cpus();
	printf("Detected %d CPU cores, creating thread pool\n", num_workers);
	workers = (Worker*)malloc(num_workers * sizeof(Worker));
	if (!workers) {
		fprintf(stderr, "Error: Failed to allocate memory for workers\n");
		return false;
	}
	work_queue = create_work_queue();
	if (!work_queue) {
		free(workers);
		return false;
	}
	for (int i = 0; i < num_workers; i++) {
		workers[i].id = i;
		workers[i].active = true;
		workers[i].queue = work_queue;
		if (!THREAD_CREATE(workers[i].thread, worker_thread, &workers[i])) {
			fprintf(stderr, "Error: Failed to create worker thread %d\n", i);
			for (int j = 0; j < i; j++) {
				workers[j].active = false;
			}
			shutdown_work_queue(work_queue);
			free(workers);
			destroy_work_queue(work_queue);
			return false;
		}
	}
	return true;
}

static void shutdown_thread_pool() {
	if (!workers) return;
	shutdown_work_queue(work_queue);
	for (int i = 0; i < num_workers; i++) {
		if (workers[i].active) {
			THREAD_JOIN(workers[i].thread);
		}
	}
	free(workers);
	destroy_work_queue(work_queue);
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
	bool available_demons[MAX_DEMONS];
	memset(available_demons, true, MAX_DEMONS * sizeof(bool));
	WorkItem* root_work = create_work_item(target_demon, available_demons, 0);
	if (!root_work) {
		fprintf(stderr, "Error: Failed to create root work item\n");
		return NULL;
	}
	if (!enqueue_work(work_queue, root_work)) {
		destroy_work_item(root_work);
		return NULL;
	}
#ifdef SPAM
	fprintf(debug_file, "Enqueued root work item for demon %d\n", target_demon);
#endif
	MUTEX_LOCK(solution_mutex);
	while (!root_work->result) {
		COND_WAIT(solution_cond, solution_mutex);
	}
	MUTEX_UNLOCK(solution_mutex);
#ifdef SPAM
	fprintf(debug_file, "Fusion chain found for demon %d\n", target_demon);
#endif
	FusionNode* final_result = root_work->result;
	destroy_work_item(root_work);
	return final_result;
}

int main(int argc, char* argv[]) {
#ifdef DEBUG
	start_time = time(NULL);
	debug_file = my_fopen("thread_debug_fixed.log", "w");
#ifdef SPAM
	fprintf(debug_file, "Debug verbose logging enabled\n");
	inst_file = my_fopen("inst_output.log", "w");
	if (inst_file) fprintf(inst_file, "Instrumentation log started\n");
#endif
#endif
	// Parse command line arguments
	if (argc < 4) {
		fprintf(stderr, "Error: Usage: %s <target_demon> [base_demon1] [base_demon2] ...\n", argv[0]);
		return EXIT_FAILURE;
	}
	target_demon_id = atoi(argv[1]);
#ifdef SPAM
	fprintf(debug_file, "Target demon ID: %d\n", target_demon_id);
#endif
	if (target_demon_id < 0 || target_demon_id >= MAX_DEMONS) {
		fprintf(stderr, "Error: Invalid target demon ID: %s\n", argv[1]);
		return EXIT_FAILURE;
	}
	for (int i = 0; i < MAX_DEMONS; i++) {
		base_demons[i] = false;
	}
	for (int i = 2; i < argc; i++) {
		int demon_id = atoi(argv[i]);
		if (demon_id >= 0 && demon_id < MAX_DEMONS) {
#ifdef SPAM
			fprintf(debug_file, "Adding base demon ID: %d\n", demon_id);
#endif
			base_demons[demon_id] = true;
		} else {
			printf("Warning: Skipping invalid demon ID: %s\n", argv[i]);
		}
	}
	MUTEX_INIT(solution_mutex);
	COND_INIT(solution_cond);
	MUTEX_INIT(active_work_mutex);
	COND_INIT(work_depth_cond);
	/* initialize global work-graph mutex */
	MUTEX_INIT(work_graph_mutex);
	for (int i = 0; i < MAX_DEMONS / 2; i++) {
		active_work_items[i] = 0;
	}
#ifdef SPAM
	fprintf(debug_file, "Loading game data...\n");
#endif
	load_demons("data/c/c_demons.json");
#ifdef SPAM
	fprintf(debug_file, "Loading race fusions...\n");
#endif
	load_race_fusions("data/c/c_race_fusions.json");
#ifdef SPAM
	fprintf(debug_file, "Loading elemental chart...\n");
#endif
	load_elemental_chart("data/c/c_elemental_chart.json");
#ifdef SPAM
	fprintf(debug_file, "Loading race anchors...\n");
#endif
	load_race_anchors("data/c/c_race_anchors.json");
	if (!init_thread_pool()) {
		fprintf(stderr, "Error: Failed to initialize thread pool\n");
		return EXIT_FAILURE;
	}
	printf("Finding fusion chain for demon %d...\n", target_demon_id);
#ifdef SPAM
	fprintf(debug_file, "Starting fusion search for demon %d\n", target_demon_id);
#endif
	FusionNode* result = find_fusion_chain(target_demon_id);
	shutdown_thread_pool();
	if (result) {
		printf("\nFound optimal fusion chain for demon %d:\n", target_demon_id);
		printf("Total fusions: %d\n", result->fusion_count);
		printf("Total demons used: %d\n", result->demon_count);
		print_fusion_tree(result, 0);
		free_fusion_node(result);
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
	// Cleanup
	for (int i = 0; i < MAX_DEMONS; i++) {
		free_demon_resources(&all_demons[i]);
		MUTEX_DESTROY(all_demons[i].work_mutex);
	}
	for (int i = 0; i < MAX_RACES; i++) {
		if (demons_by_race[i].demons) {
			free(demons_by_race[i].demons);
			demons_by_race[i].demons = NULL;
		}
	}
	for (int i = 0; i < MAX_RACES; i++) {
		if (race_anchors[i].groups) {
			for (int j = 0; j < race_anchors[i].group_count; j++) {
				if (race_anchors[i].groups[j].demons) {
					free(race_anchors[i].groups[j].demons);
					race_anchors[i].groups[j].demons = NULL;
				}
			}
			free(race_anchors[i].groups);
			race_anchors[i].groups = NULL;
		}
	}
	MUTEX_DESTROY(solution_mutex);
	COND_DESTROY(solution_cond);
	MUTEX_DESTROY(active_work_mutex);
	COND_DESTROY(work_depth_cond);
	MUTEX_DESTROY(work_graph_mutex);
	printf("Program completed successfully\n");
	return 0;
}
