#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "cJSON.h"

// Defined Constants (No Magic Numbers)
#define MAX_DEMONS 1000
#define MAX_RACES 100
#define MAX_COMPONENTS 3
#define MAX_RACIAL_FUSIONS 20
#define MAX_GROUPS 50
#define MAX_GROUP_DEMONS 20
#define MAX_FUSIONS 10
#define MAX_TRI_FALLBACKS (MAX_DEMONS * MAX_FUSIONS)

#define ERROR_EXIT(...) do { fprintf(stderr, __VA_ARGS__); exit(EXIT_FAILURE); } while(0)

typedef struct {
    int target;
    int demons[MAX_COMPONENTS];
    int count;
} ForwardFusion;

typedef struct {
    int id;
    int race;
    int species;
    int level;
    int min_level;
    int max_level;
    bool is_elemental;
	int anchor_group; // index of anchor group for elemental fusions, -1 if none
    
    ForwardFusion* forward_fusions;
    int ff_count;
    
    int racial_fusions[MAX_RACIAL_FUSIONS];
    int rf_count;
} Demon;

typedef struct {
    int demons[MAX_GROUP_DEMONS];
    int demon_count;
    bool is_anchor;
} AnchorGroup;

typedef struct {
    AnchorGroup groups[MAX_GROUPS];
    int group_count;
} RaceAnchorData;

typedef struct {
    int target;
    int demons[MAX_COMPONENTS];
    bool used;
} TriFallback;

typedef struct {
    Demon* demons[MAX_DEMONS];
    int count;
} DemonArray;

// Global Data
Demon all_demons[MAX_DEMONS];
DemonArray demons_by_race[MAX_RACES];
int race_fusions[MAX_RACES][MAX_RACES];
int elemental_chart[MAX_DEMONS][MAX_RACES];
RaceAnchorData race_anchors[MAX_RACES];

TriFallback tri_fallbacks[MAX_TRI_FALLBACKS];
int tri_fallback_count = 0;

// Dijkstra Search State
int best_cost[MAX_DEMONS];
bool settled[MAX_DEMONS];
int parent_recipes[MAX_DEMONS][MAX_COMPONENTS];
int recipe_sizes[MAX_DEMONS];

int target_demon_id = -1;
bool target_found = false;

// Helpers
static inline cJSON* load_json(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) ERROR_EXIT("Error: Failed to open file %s\n", filename);
    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    char* data = (char*)malloc(length + 1);
    fread(data, 1, length, file);
    fclose(file);
    data[length] = '\0';
    
    cJSON* json = cJSON_Parse(data);
    free(data);
    if (!json) ERROR_EXIT("Error: Failed to parse JSON from file %s\n", filename);
    return json;
}

bool contains_demon(int* arr, int count, int demon_id) {
    for (int i = 0; i < count; i++) {
        if (arr[i] == demon_id) return true;
    }
    return false;
}

int compare_demons_by_max_level(const void* a, const void* b) {
    Demon* d1 = *(Demon**)a;
    Demon* d2 = *(Demon**)b;
    return d1->max_level - d2->max_level;
}

// Loading Functions
void load_data() {
    for (int i = 0; i < MAX_DEMONS; i++) {
        all_demons[i].id = -1;
        all_demons[i].is_elemental = false;
        all_demons[i].ff_count = 0;
        all_demons[i].rf_count = 0;
        best_cost[i] = MAX_DEMONS; // MAX_DEMONS acts as our Infinity
        settled[i] = false;
        for (int j = 0; j < MAX_RACES; j++) {
			elemental_chart[i][j] = 0;
		}
    }
    for (int i = 0; i < MAX_RACES; i++) {
        demons_by_race[i].count = 0;
        for (int j = 0; j < MAX_RACES; j++) {
			race_fusions[i][j] = -1;
		}
        race_anchors[i].group_count = 0;
    }

    cJSON* d_json = load_json("data/c/c_demons.json");
    cJSON* d_entry;
    cJSON_ArrayForEach(d_entry, d_json) {
        int id = atoi(d_entry->string);
        Demon* d = &all_demons[id];
        d->id = id;
        d->race = cJSON_GetObjectItem(d_entry, "race")->valueint;
        d->species = cJSON_GetObjectItem(d_entry, "species")->valueint;
        
        cJSON* lvl = cJSON_GetObjectItem(d_entry, "level");
        d->level = lvl ? lvl->valueint : 0;
        
        cJSON* min_lvl = cJSON_GetObjectItem(d_entry, "min_level");
        d->min_level = min_lvl ? min_lvl->valueint : -1;
        
        cJSON* max_lvl = cJSON_GetObjectItem(d_entry, "max_level");
        d->max_level = max_lvl ? max_lvl->valueint : -1;

        // Populate optimized lookup array only if this demon is a regular fuseable demon
		if (d->min_level != -1 && d->max_level != -1) {
        	demons_by_race[d->race].demons[demons_by_race[d->race].count++] = d;
		}

		d->anchor_group = -1; // Initialize anchor group index to -1 (no group)

        cJSON* rfs = cJSON_GetObjectItem(d_entry, "racial_fusion");
        if (rfs) {
            d->rf_count = cJSON_GetArraySize(rfs);
            for (int k = 0; k < d->rf_count && k < MAX_RACIAL_FUSIONS; k++) {
                cJSON* pair = cJSON_GetArrayItem(rfs, k);
                d->racial_fusions[k] = cJSON_GetArrayItem(pair, 0)->valueint;
            }
        }

        cJSON* ffs = cJSON_GetObjectItem(d_entry, "forward_fusion");

        if (!ffs) continue;
		// else forward fusion data exists
		d->ff_count = cJSON_GetArraySize(ffs);
		d->forward_fusions = malloc(d->ff_count * sizeof(ForwardFusion));
		
		cJSON* ff;
		int idx = 0;
		cJSON_ArrayForEach(ff, ffs) {
			ForwardFusion* f = &d->forward_fusions[idx++];
			f->target = cJSON_GetObjectItem(ff, "target")->valueint;
			
			cJSON* dems = cJSON_GetObjectItem(ff, "demons");
			f->count = cJSON_GetArraySize(dems);
			for (int k = 0; k < f->count && k < MAX_COMPONENTS; k++) {
				f->demons[k] = cJSON_GetArrayItem(dems, k)->valueint;
			}

			if (f->count != 3) continue;
			//else this is a tri-fusion forward fusion, add to fallback list if not already present
			bool duplicate = false;
			for (int t = 0; t < tri_fallback_count; t++) {
				if (tri_fallbacks[t].target == f->target &&
					contains_demon(tri_fallbacks[t].demons, MAX_COMPONENTS, f->demons[0]) &&
					contains_demon(tri_fallbacks[t].demons, MAX_COMPONENTS, f->demons[1]) &&
					contains_demon(tri_fallbacks[t].demons, MAX_COMPONENTS, f->demons[2])) {
					duplicate = true;
					break;
				}
			}
			if (duplicate || tri_fallback_count >= MAX_TRI_FALLBACKS) continue;
			// else add to tri-fusion fallback list
			tri_fallbacks[tri_fallback_count].target = f->target;
			for (int k = 0; k < MAX_COMPONENTS; k++) {
				tri_fallbacks[tri_fallback_count].demons[k] = f->demons[k];
			}
			tri_fallbacks[tri_fallback_count].used = false;
			tri_fallback_count++;
		}
    }
    cJSON_Delete(d_json);

    // Sort the optimized lookup arrays by level
    for (int i = 0; i < MAX_RACES; i++) {
        if (demons_by_race[i].count > 1) qsort(demons_by_race[i].demons, demons_by_race[i].count, sizeof(Demon*), compare_demons_by_max_level);
    }

    cJSON* rf_json = load_json("data/c/c_race_fusions.json");
    cJSON* r_entry;
    cJSON_ArrayForEach(r_entry, rf_json) {
        int result_race = atoi(r_entry->string);
        cJSON* pair;
        cJSON_ArrayForEach(pair, r_entry) {
            int r1 = cJSON_GetArrayItem(pair, 0)->valueint;
            int r2 = cJSON_GetArrayItem(pair, 1)->valueint;
            race_fusions[r1][r2] = result_race;
            race_fusions[r2][r1] = result_race;
        }
    }
    cJSON_Delete(rf_json);

    cJSON* el_json = load_json("data/c/c_elemental_chart.json");
    cJSON* el_entry;
    cJSON_ArrayForEach(el_entry, el_json) {
        int elemental_id = atoi(el_entry->string);
        all_demons[elemental_id].is_elemental = true;
        cJSON* target_race;
        cJSON_ArrayForEach(target_race, el_entry) {
            int target_r_id = atoi(target_race->string);
            elemental_chart[elemental_id][target_r_id] = cJSON_IsTrue(target_race) ? 1 : -1;
        }
    }
    cJSON_Delete(el_json);

    cJSON* ra_json = load_json("data/c/c_race_anchors.json");
    cJSON* ra_entry;
    cJSON_ArrayForEach(ra_entry, ra_json) {
        int race_id = atoi(ra_entry->string);
        race_anchors[race_id].group_count = cJSON_GetArraySize(ra_entry);
        
        for (int i = 0; i < race_anchors[race_id].group_count && i < MAX_GROUPS; i++) {
            cJSON* group = cJSON_GetArrayItem(ra_entry, i);
            cJSON* demons = cJSON_GetObjectItem(group, "demons");
            race_anchors[race_id].groups[i].demon_count = cJSON_GetArraySize(demons);
            race_anchors[race_id].groups[i].is_anchor = cJSON_IsTrue(cJSON_GetObjectItem(group, "anchor"));
            
            for (int j = 0; j < race_anchors[race_id].groups[i].demon_count && j < MAX_GROUP_DEMONS; j++) {
				int demon_id = cJSON_GetArrayItem(demons, j)->valueint;
                race_anchors[race_id].groups[i].demons[j] = demon_id;
				all_demons[demon_id].anchor_group = i; // Set anchor group index for elemental fusion processing
            }
        }
    }
    cJSON_Delete(ra_json);
    printf("Data Loaded Successfully.\n");
}

// Fusion Logic Processors
void try_update_cost(int result_id, int cost, int p1, int p2, int p3) {
    if (result_id < 0 || result_id >= MAX_DEMONS) return;
    if (cost < best_cost[result_id]) {
        best_cost[result_id] = cost;
        parent_recipes[result_id][0] = p1;
        parent_recipes[result_id][1] = p2;
        parent_recipes[result_id][2] = p3;
        recipe_sizes[result_id] = (p3 == -1) ? 2 : 3;
    }
}

int move_elemental(int demon_id, int elemental_id) {
    int race = all_demons[demon_id].race;
    int dir = elemental_chart[elemental_id][race];
    if (dir == 0) return -1;
    
    RaceAnchorData* ra = &race_anchors[race];
    int current_group = all_demons[demon_id].anchor_group;
    if (current_group == -1) return -1;
    
    int target_group = current_group + dir;
    while (target_group >= 0 && target_group < ra->group_count && !ra->groups[target_group].is_anchor) {
        target_group += dir;
    }
	if (target_group < 0 || target_group >= ra->group_count) return -1;
    
    for (int i = 0; i < ra->groups[target_group].demon_count; i++) {
        int d = ra->groups[target_group].demons[i];
        if (all_demons[d].species == d) return d; // Must be base demon
    }
    return -1;
}

int regular_fusion(int d1, int d2) {
    int r1 = all_demons[d1].race;
    int r2 = all_demons[d2].race;
    int res_race = race_fusions[r1][r2];
    if (res_race == -1) return -1;
    
    int sum_lvl = all_demons[d1].level + all_demons[d2].level;
    DemonArray* ra = &demons_by_race[res_race];
    
    // Utilize the sorted demons_by_race array for fast lookup
    for (int i = 0; i < ra->count; i++) {
        Demon* target = ra->demons[i];
		if (sum_lvl > target->max_level) continue; // demons_by_race is sorted by max_level with each successive demon being sequentially higher, so we can strictly check max_level
		return target->id;
    }
    return -1;
}

int racial_fusion(int d1, int d2) {
    if (all_demons[d1].race != all_demons[d2].race) return -1;
    if (all_demons[d1].species == all_demons[d2].species) return -1; // No intra-species
    
    int target_race = all_demons[d1].race;
    
    // Strictly find the Base Elemental for this race
    for (int i = 0; i < MAX_DEMONS; i++) {
        Demon* elem = &all_demons[i];
        if (elem->id != -1 && elem->is_elemental && elem->species == elem->id) {
            for (int j = 0; j < elem->rf_count; j++) {
                if (elem->racial_fusions[j] == target_race) return elem->id;
            }
        }
    }
    return -1;
}

void print_recipe(int target, int depth) {
    for (int i = 0; i < depth; i++) printf("  ");
    printf("Demon %d (Cost: %d)\n", target, best_cost[target]);
    
    if (best_cost[target] == 0) return;
    
    for (int i = 0; i < recipe_sizes[target]; i++) {
        print_recipe(parent_recipes[target][i], depth + 1);
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        printf("Usage: %s <target_demon> <base1> <base2> ...\n", argv[0]);
        return 1;
    }

    target_demon_id = atoi(argv[1]);
    load_data();

    // Init Base Demons
    for (int i = 2; i < argc; i++) {
        int b_id = atoi(argv[i]);
        best_cost[b_id] = 0;
    }

    printf("Starting Dijkstra Forward Search for Demon %d...\n", target_demon_id);

    while (!target_found) {
        int d1 = -1;
        int min_cost = MAX_DEMONS;

        for (int i = 0; i < MAX_DEMONS; i++) {
            if (all_demons[i].id != -1 && !settled[i] && best_cost[i] < min_cost) {
                min_cost = best_cost[i];
                d1 = i;
            }
        }
        
        if (d1 == -1) break; // Exhausted
        
        settled[d1] = true;
        if (d1 == target_demon_id) {
            target_found = true;
            break;
        }

        // 1. Check Dual Fusions strictly against PREVIOUSLY SETTLED demons
        for (int d2 = 0; d2 < MAX_DEMONS; d2++) {
            if (!settled[d2] || all_demons[d2].id == -1) continue;
            
            int current_cost = best_cost[d1] + best_cost[d2] + 1;
            bool is_dual_special = false;

            for (int f = 0; f < all_demons[d1].ff_count; f++) {
                ForwardFusion* ff = &all_demons[d1].forward_fusions[f];
                if (ff->count == 2) {
                    if ((ff->demons[0] == d1 && ff->demons[1] == d2) || 
                        (ff->demons[0] == d2 && ff->demons[1] == d1)) {
                        try_update_cost(ff->target, current_cost, d1, d2, -1);
                        is_dual_special = true;
                    }
                }
            }

            if (!is_dual_special && d1 != d2) {
                if (all_demons[d1].is_elemental || all_demons[d2].is_elemental) {
                    int elem = all_demons[d1].is_elemental ? d1 : d2;
                    int norm = all_demons[d1].is_elemental ? d2 : d1;
                    int res = move_elemental(norm, elem);
                    if (res != -1) try_update_cost(res, current_cost, d1, d2, -1);
                } 
                else if (all_demons[d1].race == all_demons[d2].race) {
                    int res = racial_fusion(d1, d2);
                    if (res != -1) try_update_cost(res, current_cost, d1, d2, -1);
                } 
                else {
                    int res = regular_fusion(d1, d2);
                    if (res != -1) try_update_cost(res, current_cost, d1, d2, -1);
                }
            }
        }

        // 2. Check Tri-Fusions
        for (int i = 0; i < tri_fallback_count; i++) {
            TriFallback* tf = &tri_fallbacks[i];
            if (!tf->used && contains_demon(tf->demons, MAX_COMPONENTS, d1)) {
                int c1 = tf->demons[0];
                int c2 = tf->demons[1];
                int c3 = tf->demons[2];
                
                if (settled[c1] && settled[c2] && settled[c3]) {
                    tf->used = true;
                    int tri_cost = best_cost[c1] + best_cost[c2] + best_cost[c3] + 1;
                    try_update_cost(tf->target, tri_cost, c1, c2, c3);
                }
            }
        }
    }

    if (target_found) {
        printf("\nTarget Demon %d successfully synthesized!\n", target_demon_id);
        print_recipe(target_demon_id, 0);
    } else {
        printf("\nImpossible to synthesize Demon %d with provided bases.\n", target_demon_id);
    }

    return 0;
}
