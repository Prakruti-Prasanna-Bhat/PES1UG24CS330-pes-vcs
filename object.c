// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────
static const char *object_type_name(ObjectType type) {
    switch (type) {
        case OBJ_BLOB:   return "blob";
        case OBJ_TREE:   return "tree";
        case OBJ_COMMIT: return "commit";
        default:         return NULL;
    }
}

static int build_full_object(ObjectType type, const void *data, size_t len,
                             unsigned char **buf_out, size_t *buf_len_out) {
    const char *type_str;
    char header[64];
    int header_len;
    size_t total_len;
    unsigned char *buffer;

    if (!buf_out || !buf_len_out) return -1;
    if (len > 0 && !data) return -1;

    type_str = object_type_name(type);
    if (!type_str) return -1;

    header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len);
    if (header_len < 0 || (size_t)header_len + 1 > sizeof(header)) return -1;

    header[header_len++] = '\0';

    total_len = (size_t)header_len + len;
    buffer = malloc(total_len);
    if (!buffer) return -1;

    memcpy(buffer, header, (size_t)header_len);
    if (len > 0) memcpy(buffer + header_len, data, len);

    *buf_out = buffer;
    *buf_len_out = total_len;
    return 0;
}
static int ensure_shard_dir(const char *object_pathname, char *dir_out, size_t dir_out_size) {
    char *slash;

    if (!object_pathname || !dir_out) return -1;

    snprintf(dir_out, dir_out_size, "%s", object_pathname);
    slash = strrchr(dir_out, '/');
    if (!slash) return -1;

    *slash = '\0';

    if (mkdir(dir_out, 0755) != 0 && access(dir_out, F_OK) != 0) {
        return -1;
    }

    return 0;
}
static int write_all(int fd, const void *buf, size_t len) {
    const unsigned char *p = (const unsigned char *)buf;
    size_t written = 0;

    while (written < len) {
        ssize_t rc = write(fd, p + written, len - written);
        if (rc <= 0) return -1;
        written += (size_t)rc;
    }

    return 0;
}
// Write an object to the store.
//
// Object format on disk:
//   "<type> <size>\0<data>"
//   where <type> is "blob", "tree", or "commit"
//   and <size> is the decimal string of the data length
//
// Steps:
//   1. Build the full object: header ("blob 16\0") + data
//   2. Compute SHA-256 hash of the FULL object (header + data)
//   3. Check if object already exists (deduplication) — if so, just return success
//   4. Create shard directory (.pes/objects/XX/) if it doesn't exist
//   5. Write to a temporary file in the same shard directory
//   6. fsync() the temporary file to ensure data reaches disk
//   7. rename() the temp file to the final path (atomic on POSIX)
//   8. Open and fsync() the shard directory to persist the rename
//   9. Store the computed hash in *id_out

// HINTS - Useful syscalls and functions for this phase:
//   - sprintf / snprintf : formatting the header string
//   - compute_hash       : hashing the combined header + data
//   - object_exists      : checking for deduplication
//   - mkdir              : creating the shard directory (use mode 0755)
//   - open, write, close : creating and writing to the temp file
//                          (Use O_CREAT | O_WRONLY | O_TRUNC, mode 0644)
//   - fsync              : flushing the file descriptor to disk
//   - rename             : atomically moving the temp file to the final path
//

//
// Returns 0 on success, -1 on error.
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    unsigned char *full_obj = NULL;
    size_t full_obj_len = 0;
    char final_path[512];
    char shard_dir[512];
    char temp_path[512];
    int fd = -1;
    int dir_fd = -1;
    int rc = -1;

    if (!id_out) return -1;

    if (build_full_object(type, data, len, &full_obj, &full_obj_len) != 0) {
        return -1;
    }

    compute_hash(full_obj, full_obj_len, id_out);
    object_path(id_out, final_path, sizeof(final_path));

    if (object_exists(id_out)) {
        rc = 0;
        goto cleanup;
    }

    if (ensure_shard_dir(final_path, shard_dir, sizeof(shard_dir)) != 0) {
        goto cleanup;
    }

    if (snprintf(temp_path, sizeof(temp_path), "%s/.tmp-object-%ld", shard_dir, (long)getpid()) >= (int)sizeof(temp_path)) {
    goto cleanup;
    }

    fd = open(temp_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) goto cleanup;

    if (write_all(fd, full_obj, full_obj_len) != 0) goto cleanup;
    if (fsync(fd) != 0) goto cleanup;
    if (close(fd) != 0) {
        fd = -1;
        goto cleanup;
    }
    fd = -1;

    if (rename(temp_path, final_path) != 0) goto cleanup;

    dir_fd = open(shard_dir, O_RDONLY);
    if (dir_fd < 0) goto cleanup;

    if (fsync(dir_fd) != 0) goto cleanup;

    rc = 0;

cleanup:
    if (fd >= 0) close(fd);
    if (dir_fd >= 0) close(dir_fd);
    if (rc != 0) unlink(temp_path);
    free(full_obj);
    return rc;
}

// Read an object from the store.
//
// Steps:
//   1. Build the file path from the hash using object_path()
//   2. Open and read the entire file
//   3. Parse the header to extract the type string and size
//   4. Verify integrity: recompute the SHA-256 of the file contents
//      and compare to the expected hash (from *id). Return -1 if mismatch.
//   5. Set *type_out to the parsed ObjectType
//   6. Allocate a buffer, copy the data portion (after the \0), set *data_out and *len_out
//
// HINTS - Useful syscalls and functions for this phase:
//   - object_path        : getting the target file path
//   - fopen, fread, fseek: reading the file into memory
//   - memchr             : safely finding the '\0' separating header and data
//   - strncmp            : parsing the type string ("blob", "tree", "commit")
//   - compute_hash       : re-hashing the read data for integrity verification
//   - memcmp             : comparing the computed hash against the requested hash
//   - malloc, memcpy     : allocating and returning the extracted data
//
// The caller is responsible for calling free(*data_out).
// Returns 0 on success, -1 on error (file not found, corrupt, etc.).
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    char path[512];
    FILE *fp = NULL;
    long file_size;
    unsigned char *file_buf = NULL;
    unsigned char *payload_buf = NULL;
    unsigned char *null_byte;
    char type_str[16];
    size_t payload_len;
    size_t declared_len;
    ObjectID computed_id;
    
    if (!id || !type_out || !data_out || !len_out) return -1;

    object_path(id, path, sizeof(path));

    fp = fopen(path, "rb");
    if (!fp) return -1;

    if (fseek(fp, 0, SEEK_END) != 0) goto fail;
    file_size = ftell(fp);
    if (file_size < 0) goto fail;
    if (fseek(fp, 0, SEEK_SET) != 0) goto fail;

    file_buf = malloc((size_t)file_size);
    if (!file_buf) goto fail;

    if (file_size > 0 && fread(file_buf, 1, (size_t)file_size, fp) != (size_t)file_size) goto fail;
    fclose(fp);
    fp = NULL;

    null_byte = memchr(file_buf, '\0', (size_t)file_size);
    if (!null_byte) goto fail;

    compute_hash(file_buf, (size_t)file_size, &computed_id);
    if (memcmp(computed_id.hash, id->hash, HASH_SIZE) != 0) goto fail;

    if (sscanf((char *)file_buf, "%15s %zu", type_str, &declared_len) != 2) goto fail;

    if (strcmp(type_str, "blob") == 0) *type_out = OBJ_BLOB;
    else if (strcmp(type_str, "tree") == 0) *type_out = OBJ_TREE;
    else if (strcmp(type_str, "commit") == 0) *type_out = OBJ_COMMIT;
    else goto fail;

    payload_len = (size_t)(file_buf + file_size - (null_byte + 1));
    if (payload_len != declared_len) goto fail;

    payload_buf = malloc(payload_len ? payload_len : 1);
    if (!payload_buf) goto fail;

    if (payload_len > 0) memcpy(payload_buf, null_byte + 1, payload_len);

    *data_out = payload_buf;
    *len_out = payload_len;

    free(file_buf);
    return 0;

fail:
    if (fp) fclose(fp);
    free(file_buf);
    free(payload_buf);
    return -1;
}
