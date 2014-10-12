/*
 *  Example functions to develop and demonstrate the new feature "hashed catalogue" for Disk ARchive - dar
 *  Copyright (C) 2014  Tobias Specht
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *  To contact the author: https://github.com/peckto/hash_dic_test
 */

#include <iostream>
#include <string>
#include <fstream>
#include <unordered_map>
#include <map>
#include <time.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#define ROUNDS 1
#define SALT_LEN 50
#define MODE_INSERT 0
#define MODE_SEARCH 2
#define MODE_DRY 3

using namespace std;

struct AttrList {
    uid_t st_uid;
    gid_t st_gid;
    mode_t st_mode;
    off_t st_size;
    unsigned char d_type;
    int flags;
    time_t st_ctime_;
};

typedef unordered_map<string, AttrList> HashMap;

void sprint_hash(unsigned char* h, char *h_str) {
    for (int i = 0; i < EVP_MAX_MD_SIZE; i++)
        sprintf(&h_str[i*2], "%02x", (unsigned int)h[i]);
}

void find(string path, HashMap *map, char *uuid, unsigned char *salt, int mode) {
    DIR *dir = NULL;
    dirent *ent = NULL;
    struct stat myStat;
    string s;
    string value;
    unsigned char h[EVP_MAX_MD_SIZE];
    char h_str[EVP_MAX_MD_SIZE*2+1];
    HashMap::const_iterator got;

    if  (*(path.end()-1) != '/') {
        path += "/";
    }
    if (!path.compare("/proc/") || !path.compare("/sys/") || !path.compare("/dev/") || !path.compare("/run/")) {
        return;
    }

    dir = opendir(path.c_str());
    if (dir == NULL ) {
        cout << "cant open dir: " << path << endl;
        return;
    }
    while ((ent = readdir(dir)) != NULL) {
        if(!strcmp(ent->d_name,".") || !strcmp(ent->d_name,".."))
            continue;
        s = path;
        s += ent->d_name;
        // dont follow symboliy links
        if (lstat(s.c_str(), &myStat) == -1) {
            cout << "failed to read information about file: " << s << endl;
            continue;
        }
        // value = path+filename|inodeID|mtime|uuid
        value = s;
        value += "|";
        value += to_string(ent->d_ino);
        value += "|";
        value += to_string(myStat.st_mtime);
        value += "|";
        value += uuid;
        PKCS5_PBKDF2_HMAC(value.c_str(), value.length(), salt, SALT_LEN, ROUNDS, EVP_sha512(), EVP_MAX_MD_SIZE, h);
        sprint_hash(h, h_str);
        if (mode == MODE_SEARCH) {
            got = map->find(h_str);
            if (got == map->end()) {
                cout << "cant find hash!" << endl;
                cout << value << endl;
            } else {
            }
        } else if (mode == MODE_INSERT) {
            (*map)[h_str] = {myStat.st_uid, myStat.st_gid, myStat.st_mode, myStat.st_size, ent->d_type, 0, myStat.st_ctime};
        }
        if (ent->d_type == DT_DIR) {
            find(s, map, uuid, salt, mode);
        }
    }
    delete ent;
    closedir (dir);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        cout << "Usage: " << argv[0] << ": <path>" << endl;
        return 1;
    }
    char *path = argv[1];
    char db[] = "test.db";
    unsigned char salt[SALT_LEN];
    HashMap map;
    clock_t start;
    double s;
    char buffer[20];
    char uuid[] = "fdf7c30d-838c-4e16-af37-2a345650590a";

    RAND_bytes(salt, SALT_LEN);
    OpenSSL_add_all_algorithms();

    cout.imbue(std::locale(""));
    cout << "generate hashes" << endl;
    start = clock();
    find(path, &map, uuid, salt, MODE_DRY);
    s = ((float)(clock() - start))/CLOCKS_PER_SEC;
    cout << "duration: " << (int)s/60<< ":" << (int)s%60 << ":" << ((int)(s*1000))%1000<< endl;
    cout << "---------------------------------" << endl;

    cout << "build hash table" << endl;
    start = clock();
    find(path, &map, uuid, salt, MODE_INSERT);
    s = ((float)(clock() - start))/CLOCKS_PER_SEC;
    cout << "duration: " << (int)s/60<< ":" << (int)s%60 << ":" << ((int)(s*1000))%1000<< endl;
    cout << "---------------------------------" << endl;

    cout << "search in hash table" << endl;
    start = clock();
    find(path, &map, uuid, salt, MODE_SEARCH);
    s = ((float)(clock() - start))/CLOCKS_PER_SEC;
    cout << "duration: " << (int)s/60<< ":" << (int)s%60 << ":" << ((int)(s*1000))%1000<< endl;

    cout << "---------------------------------" << endl;
    cout << "map entries: " << map.size() << endl;
    cout << "map size: ~" << (map.size()*(sizeof(AttrList) + map.begin()->first.size() + sizeof(_Rb_tree_node_base) ))/1000/1000. << "MB" << endl;

    EVP_cleanup();
    return 0;
}

