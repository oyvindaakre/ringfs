/*
 * Copyright © 2014 Kosma Moczek <kosma@cloudyourcar.com>
 * This program is free software. It comes without any warranty, to the extent
 * permitted by applicable law. You can redistribute it and/or modify it under
 * the terms of the Do What The Fuck You Want To Public License, Version 2, as
 * published by Sam Hocevar. See the COPYING file for more details.
 */

#ifndef RINGFS_H
#define RINGFS_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup ringfs_api RingFS API
 * @{
 */

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

/**
 * Flash memory+parition descriptor.
 */
struct ringfs_flash_partition
{
    int sector_size;            /**< Sector size, in bytes. */
    int sector_offset;          /**< Partition offset, in sectors. */
    int sector_count;           /**< Partition size, in sectors. */

    /**
     * Erase a sector.
     * @param address Any address inside the sector.
     * @returns Zero on success, -1 on failure.
     */
    int (*sector_erase)(struct ringfs_flash_partition *flash, int address);
    /**
     * Program flash memory bits by toggling them from 1 to 0.
     * @param address Start address, in bytes.
     * @param data Data to program.
     * @param size Size of data.
     * @returns size on success, -1 on failure.
     */
    ssize_t (*program)(struct ringfs_flash_partition *flash, int address, const void *data, size_t size);
    /**
     * Read flash memory.
     * @param address Start address, in bytes.
     * @param data Buffer to store read data.
     * @param size Size of data.
     * @returns size on success, -1 on failure.
     */
    ssize_t (*read)(struct ringfs_flash_partition *flash, int address, void *data, size_t size);
    /**
     * Sends a log message to the application. May be unassigned.
     * @param flash A pointer to this.
     * @param fmt Format string.
     * @param ... Arguments.
     */
    void (*log)(struct ringfs_flash_partition *flash, const char *fmt, ...);

    /**
     * Pointer to some user context data, such as flash driver instance.
     */
    void *user_context;
};

/** @private */
struct ringfs_loc {
    int sector;
    int slot;
};

/**
 * RingFS instance. Should be initialized with ringfs_init() befure use.
 * Structure fields should not be accessed directly.
 * */
struct ringfs {
    /* Constant values, set once at ringfs_init(). */
    struct ringfs_flash_partition *flash;
    uint32_t version;
    int object_size;
    /* Cached values. */
    int slots_per_sector;

    /* Read/write pointers. Modified as needed. */
    struct ringfs_loc read;
    struct ringfs_loc write;
    struct ringfs_loc cursor;
};

enum ringfs_return_value {
    RINGFS_OK = 0,
    /** Generic internal error */
    RINGFS_ERR = -1,
    /** The filesystem contains no data records */
    RINGFS_EMPTY = -2,
    /** Invalid parameter passed to function */
    RINGFS_INVALID_PARAMETER = -3,
    /** A deprecated API was called */
    RINGFS_DEPRECATED = -4,
    /** Data record is corrupted */
    RINGFS_CORRUPTED = -5,
    /** File system contains records with incompatible version */
    RINGFS_INCOMPATIBLE_VERSION = -6,
    /** The destination buffer is not large enough for the read data */
    RINGFS_DESTINATION_MEM_INSUFFICIENT = -7
};

/**
 * Initialize a RingFS instance. Must be called before the instance can be used
 * with the other ringfs_* functions.
 *
 * @param fs RingFS instance to be initialized.
 * @param flash Flash memory interface. Must be implemented externally.
 * @param version Object version. Should be incremented whenever the object's
 *                semantics or size change in a backwards-incompatible way.
 * @param object_size Size of one stored object, in bytes.
 */
void ringfs_init(struct ringfs *fs, struct ringfs_flash_partition *flash, uint32_t version, int object_size);

/**
 * Format the flash memory.
 *
 * If this fails there is no way to recover from ringfs itself. It will require
 * a lowlevel storage erase.
 *
 * @param fs Initialized RingFS instance.
 * @returns RINGFS_OK success
 * @returns RINGFS_ERR on failure
 */
int ringfs_format(struct ringfs *fs);

/**
 * Scan the flash memory for a valid filesystem.
 *
 * @param fs Initialized RingFS instance.
 * @returns RINGFS_OK success
 * @returns RINGFS_CORRUPTED
 * @returns RINGFS_INCOMPATIBLE_VERSION
 * @returns RINGFS_ERR otherwise
 */
int ringfs_scan(struct ringfs *fs);

/**
 * Calculate maximum RingFS capacity.
 *
 * @param fs Initialized RingFS instance.
 * @returns Maximum capacity on success, RINGFS_ERR on failure.
 */
int ringfs_capacity(struct ringfs *fs);

/**
 * Calculate approximate object count.
 * Runs in O(1).
 *
 * @param fs Initialized RingFS instance.
 * @returns Estimated object count on success, -1 on failure.
 */
int ringfs_count_estimate(struct ringfs *fs);

/**
 * Calculate exact object count.
 * Runs in O(n).
 *
 * @param fs Initialized RingFS instance.
 * @returns Exact object count on success, RINGFS_ERR on failure.
 */
int ringfs_count_exact(struct ringfs *fs);

/**
 * Append an object at the end of the ring. Deletes oldest objects as needed.
 * This assumes that \p object has the same size as specified in ringfs_init().
 *
 * @param fs Initialized RingFS instance.
 * @param object Object to be stored.
 * @returns RINGFS_OK on success
 * @returns RINGFS_INVALID_PARAMETER if size is invalid
 * @returns RINGFS_CORRUPTED if ring is corrupted
 * @returns RINGFS_ERR otherwise
 */
int ringfs_append(struct ringfs *fs, const void *object);

/**
 * Append an object at the end of the ring. Deletes oldest objects as needed.
 * \p size must be positive and less than or equal to the size specified in
 * ringfs_init().
 *
 * @param fs Initialized RingFS instance.
 * @param object Object to be stored.
 * @param size Size of the object in bytes.
 * @returns RINGFS_OK on success
 * @returns RINGFS_INVALID_PARAMETER if size is invalid
 * @returns RINGFS_CORRUPTED if ring is corrupted
 * @returns RINGFS_ERR otherwise
 */
int ringfs_append_ex(struct ringfs *fs, const void *object, int size);

/**
 * Append an object at the end of the ring. Deletes oldest objects as needed.
 *
 * @param fs Initialized RingFS instance.
 * @param object Object to be stored.
 * @param size Size of the object in bytes.
 * @returns Zero on success, -1 on failure.
 */
int ringfs_append_var(struct ringfs *fs, const void *object, uint16_t size);

/**
 * Fetch next object from the ring, oldest-first. Advances read cursor.
 * This assumes that \p object has the same size as specified in ringfs_init().
 *
 * @param fs Initialized RingFS instance.
 * @param object Buffer to store retrieved object.
 * @returns RINGFS_OK on success
 * @returns RINGFS_INVALID_PARAMETER if size is invalid
 * @returns RINGFS_ERR otherwise
 */
int ringfs_fetch(struct ringfs *fs, void *object);

/**
 * Fetch next object from the ring, oldest-first. Advances read cursor.
 * \p size must be positive and less than or equal to the size specified in
 * ringfs_init().
 *
 * @param fs Initialized RingFS instance.
 * @param object Buffer to store retrieved object.
 * @param size Size of the object in bytes.
 * @returns RINGFS_OK on success
 * @returns RINGFS_INVALID_PARAMETER if size is invalid
 * @returns RINGFS_ERR otherwise
 */
int ringfs_fetch_ex(struct ringfs *fs, void *object, int size);

/**
 * Fetch next object from the ring, oldest-first. Advances read cursor.
 *
 * @param fs Initialized RingFS instance.
 * @param object Buffer to store retrieved object.
 * @param size [in/out] Size of the destination object in bytes. On successful return contains the number of bytes written to \p object.
 * @returns Zero on success, -1 on failure.
 */
int ringfs_fetch_var(struct ringfs *fs, void *object, uint16_t *size);

/**
 * Discard all fetched objects up to the read cursor.
 *
 * @param fs Initialized RingFS instance.
 * @returns RINGFS_OK on success
 * @returns RINGFS_ERR on failure
 */
int ringfs_discard(struct ringfs *fs);

/**
 * Discards the item pointed by the read pointer,
 * unless the read pointer points to the write pointer which
 * means the ring is empty.
 *
 * @param fs Initialized RingFS instance.
 * @returns RINGFS_OK on success
 * @returns RINGFS_EMPTY if ring is empty
 * @returns RINGFS_ERR otherwise
 */
int ringfs_item_discard(struct ringfs *fs);

/**
 * Rewind the read cursor back to the oldest object.
 *
 * @param fs Initialized RingFS instance.
 * @returns RINGFS_OK on success
 * @returns RINGFS_ERR on failure
 */
int ringfs_rewind(struct ringfs *fs);

/**
 * Dump filesystem metadata. For debugging purposes.
 * @param stream File stream to write to.
 * @param fs Initialized RingFS instance.
 */
void ringfs_dump(FILE *stream, struct ringfs *fs);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

/* vim: set ts=4 sw=4 et: */

