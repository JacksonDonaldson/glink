#include "GBFUtils.hpp"
#include <cstring>
#include <cstdio>
#include <dirent.h>
#include <sys/stat.h>

uint get_gbf_file(const char *ghidra_repo_path, char *program_name, char* gbf_file_path_out, uint gbf_file_path_size) {
    char internal_ghidra_path[MAX_PATH];
    std::strncpy(internal_ghidra_path, ghidra_repo_path, sizeof(internal_ghidra_path) - 1);
    internal_ghidra_path[sizeof(internal_ghidra_path) - 1] = '\0';

    if(std::strncmp(internal_ghidra_path + std::strlen(internal_ghidra_path) - 4, ".gbf", 4) == 0){
        //Transform gbf to gbf? sure
        std::strncpy(gbf_file_path_out, internal_ghidra_path, gbf_file_path_size - 1);
        gbf_file_path_out[gbf_file_path_size - 1] = '\0';
        return static_cast<uint>(ErrorCode::E_OK);
    }    

    if (std::strncmp(internal_ghidra_path + std::strlen(internal_ghidra_path) - 4, ".gpr", 4) == 0) {
        //.gpr is just the pointer to the directory. Assume they want the repo w/ the same name.
        internal_ghidra_path[std::strlen(internal_ghidra_path) - 4] = '\0';
        std::strcat(internal_ghidra_path, ".rep");
    }

    if(std::strncmp(internal_ghidra_path + std::strlen(internal_ghidra_path) - 4, ".rep", 4)){
        return static_cast<uint>(ErrorCode::E_NOT_GHIDRA_REPO);
    }

    char index_dat_path[MAX_PATH];
    ::snprintf(index_dat_path, sizeof(index_dat_path), "%s/idata/~index.dat", internal_ghidra_path);

    FILE *index_dat_file = ::fopen(index_dat_path, "r");
    if (!index_dat_file) {
        return static_cast<uint>(ErrorCode::E_NO_INDEX);
    }

    char* match = nullptr;
    char index_data[MAX_PATH];
    while (::fgets(index_data, sizeof(index_data), index_dat_file)) {
        if ((match = ::strstr(index_data, program_name))) {
            break;
        }
    }
    ::fclose(index_dat_file);

    if(!match || match - index_data < 9){
        return static_cast<uint>(ErrorCode::E_NO_GBF_FILE);
    }

    char folder_0 = *(match - 5);
    char folder_1 = *(match - 4);

    *(match-1) = '\0';

    char gbf_folder_path[MAX_PATH];
    ::snprintf(gbf_folder_path, sizeof(gbf_folder_path), "%s/idata/%c%c/~%s.db/", internal_ghidra_path, folder_0, folder_1, match - 9);

    DIR *dir = opendir(gbf_folder_path);
    if (!dir) {
        return static_cast<uint>(ErrorCode::E_NO_GBF_FILE);
    }

    struct dirent *entry;
    struct stat st;
    char candidate_path[MAX_PATH * 2];
    time_t newest_mtime = 0;
    int found = 0;

    while ((entry = readdir(dir)) != nullptr) {
        size_t len = ::strlen(entry->d_name);
        if (len < 4 || ::strcmp(entry->d_name + len - 4, ".gbf") != 0)
            continue;
        ::snprintf(candidate_path, sizeof(candidate_path), "%s%s", gbf_folder_path, entry->d_name);
        if (stat(candidate_path, &st) == 0 && S_ISREG(st.st_mode)) {
            if (!found || st.st_mtime > newest_mtime) {
                ::strncpy(gbf_file_path_out, candidate_path, gbf_file_path_size - 1);
                gbf_file_path_out[gbf_file_path_size - 1] = '\0';
                newest_mtime = st.st_mtime;
                found = 1;
            }
        }
    }

    closedir(dir);

    if (!found) {
        return static_cast<uint>(ErrorCode::E_NO_GBF_FILE);
    }

    return static_cast<uint>(ErrorCode::E_OK);
}