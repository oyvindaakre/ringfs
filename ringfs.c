/*
 * Copyright © 2014 Kosma Moczek <kosma@cloudyourcar.com>
 * This program is free software. It comes without any warranty, to the extent
 * permitted by applicable law. You can redistribute it and/or modify it under
 * the terms of the Do What The Fuck You Want To Public License, Version 2, as
 * published by Sam Hocevar. See the COPYING file for more details.
 */

/**
 * @defgroup ringfs_impl RingFS implementation
 * @details
 *
 * @{
 */

#include <ringfs.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>

#define LOG(fs, str, ...) \
    do { \
        if ((fs)->flash->log) { \
            (fs)->flash->log(fs->flash, str, ##__VA_ARGS__); \
        } \
    } while (0)

/**
 * @defgroup sector
 * @{
 */

enum sector_status {
    SECTOR_ERASED     = 0xFFFFFFFF, /**< Default state after NOR flash erase. */
    SECTOR_FREE       = 0xFFFFFF00, /**< Sector erased. */
    SECTOR_IN_USE     = 0xFFFF0000, /**< Sector contains valid data. */
    SECTOR_ERASING    = 0xFF000000, /**< Sector should be erased. */
    SECTOR_FORMATTING = 0x00000000, /**< The entire partition is being formatted. */
};

struct sector_header {
    uint32_t status;
    uint32_t version;
};

static int _sector_address(struct ringfs *fs, int sector_offset)
{
    return (fs->flash->sector_offset + sector_offset) * fs->flash->sector_size;
}

static int _sector_get_status(struct ringfs *fs, int sector, uint32_t *status)
{
    return fs->flash->read(fs->flash,
            _sector_address(fs, sector) + offsetof(struct sector_header, status),
            status, sizeof(*status));
}

static int _sector_set_status(struct ringfs *fs, int sector, uint32_t status)
{
    return fs->flash->program(fs->flash,
            _sector_address(fs, sector) + offsetof(struct sector_header, status),
            &status, sizeof(status));
}

static int _sector_free(struct ringfs *fs, int sector, uint32_t current_status)
{
    int sector_addr = _sector_address(fs, sector);
    if (current_status != SECTOR_ERASING && current_status != SECTOR_FORMATTING)
        _sector_set_status(fs, sector, SECTOR_ERASING);
    if (fs->flash->sector_erase(fs->flash, sector_addr) == -1)
    {
        return -1;
    }
    if (fs->flash->program(fs->flash,
            sector_addr + offsetof(struct sector_header, version),
            &fs->version, sizeof(fs->version)) == -1)
    {
        return -1;
    }
    return _sector_set_status(fs, sector, SECTOR_FREE);
}

/**
 * @}
 * @defgroup slot
 * @{
 */

enum slot_status {
    SLOT_ERASED   = 0xFFFFFFFF, /**< Default state after NOR flash erase. */
    SLOT_RESERVED = 0xFFFFFF00, /**< Write started but not yet committed. */
    SLOT_VALID    = 0xFFFF0000, /**< Write committed, slot contains valid data. */
    SLOT_GARBAGE  = 0xFF000000, /**< Slot contents discarded and no longer valid. */
};

#define DATA_TYPE_UNKNOWN (uint8_t)0xFF

struct slot_header {
    uint32_t status;
    uint8_t reserved;
    uint8_t data_type;
    uint16_t data_length;
};

static int _slot_address(struct ringfs *fs, struct ringfs_loc *loc) // TODO handle the block count?
{
    return _sector_address(fs, loc->sector) +
           sizeof(struct sector_header) +
           (sizeof(struct slot_header) /*+ fs->object_size*/) * loc->slot; // Now we allow slots to directly follow each other instead of being at fixed positions
}
/*
static int _slot_get_status(struct ringfs *fs, struct ringfs_loc *loc, uint32_t *status)
{
    return fs->flash->read(fs->flash,
            _slot_address(fs, loc) + offsetof(struct slot_header, status),
            status, sizeof(*status));
}
*/

static int _slot_get_data_length(struct ringfs *fs, struct ringfs_loc *loc, uint16_t *data_length)
{
    return fs->flash->read(fs->flash,
            _slot_address(fs, loc) + offsetof(struct slot_header, data_length),
            data_length, sizeof(*data_length));
}

static int _slot_get_header(struct ringfs *fs, struct ringfs_loc *loc, struct slot_header *header)
{
    return fs->flash->read(fs->flash,
            _slot_address(fs, loc), header, sizeof(*header));
}


static int _slot_set_status(struct ringfs *fs, struct ringfs_loc *loc, uint32_t status)
{
    return fs->flash->program(fs->flash,
            _slot_address(fs, loc) + offsetof(struct slot_header, status),
            &status, sizeof(status));
}

static int _slot_set_header(struct ringfs *fs, struct ringfs_loc *loc, struct slot_header *header)
{
    return fs->flash->program(fs->flash, _slot_address(fs, loc), header, sizeof(*header));
}

static int _size_to_number_of_slots(const struct ringfs *fs, int size)
{
    int slots = (size + sizeof(struct slot_header)) / fs->object_size;
    int remain = size % fs->object_size;
    if (remain)
    {
        slots++;
    }
    return slots;
}

static int _slots_to_max_data_length(struct ringfs *fs, int num_slots)
{
    int max_len = num_slots * fs->object_size;
    max_len -= sizeof(struct slot_header);
    if (max_len < 0)
    {
        max_len = 0;
    }
    return max_len;
}

/**
 * @}
 * @defgroup loc
 * @{
 */

static bool _loc_equal(struct ringfs_loc *a, struct ringfs_loc *b)
{
    return (a->sector == b->sector) && (a->slot == b->slot);
}

/** Advance a location to the beginning of the next sector. */
static void _loc_advance_sector(struct ringfs *fs, struct ringfs_loc *loc)
{
    loc->slot = 0;
    loc->sector++;
    if (loc->sector >= fs->flash->sector_count)
        loc->sector = 0;
}

/** Advance a location to the next slot, advancing the sector too if needed. */
static void _loc_advance_slot(struct ringfs *fs, struct ringfs_loc *loc, int steps)
{
    loc->slot += steps;
    if (loc->slot >= fs->slots_per_sector)
        _loc_advance_sector(fs, loc);
}

/**
 * @}
 */

/* And here we go. */

void ringfs_init(struct ringfs *fs, struct ringfs_flash_partition *flash, uint32_t version, int object_size)
{
    /* Copy arguments to instance. */
    fs->flash = flash;
    fs->version = version;
    fs->object_size = object_size;

    /* Precalculate commonly used values. */
    fs->slots_per_sector = (fs->flash->sector_size - sizeof(struct sector_header)) /
                           (sizeof(struct slot_header));
}

int ringfs_format(struct ringfs *fs)
{
    /* Mark all sectors to prevent half-erased filesystems. */
    for (int sector=0; sector<fs->flash->sector_count; sector++)
        if (_sector_set_status(fs, sector, SECTOR_FORMATTING) == -1)
            return RINGFS_ERR;

    /* Erase, update version, mark as free. */
    for (int sector=0; sector<fs->flash->sector_count; sector++)
        if (_sector_free(fs, sector, SECTOR_FORMATTING) == -1)
            return RINGFS_ERR;

    /* Start reading & writing at the first sector. */
    fs->read.sector = 0;
    fs->read.slot = 0;
    fs->write.sector = 0;
    fs->write.slot = 0;
    fs->cursor.sector = 0;
    fs->cursor.slot = 0;

    return RINGFS_OK;
}

int ringfs_scan(struct ringfs *fs)
{
    uint32_t previous_sector_status = SECTOR_FREE;
    /* The read sector is the first IN_USE sector *after* a FREE sector
     * (or the first one). */
    int read_sector = 0;
    /* The write sector is the last IN_USE sector *before* a FREE sector
     * (or the last one). */
    int write_sector = fs->flash->sector_count - 1;
    /* There must be at least one FREE sector available at all times. */
    bool free_seen = false;
    /* If there's no IN_USE sector, we start at the first one. */
    bool used_seen = false;

    /* Iterate over sectors. */
    for (int sector=0; sector<fs->flash->sector_count; sector++) {
        int addr = _sector_address(fs, sector);

        /* Read sector header. */
        struct sector_header header;
        if (fs->flash->read(fs->flash, addr, &header, sizeof(header)) == -1)
        {
            return RINGFS_ERR;
        }

        /* Detect partially-formatted partitions. */
        if (header.status == SECTOR_FORMATTING) {
            LOG(fs, "ringfs_scan: partially formatted partition");
            return RINGFS_ERR;
        }

        /* Detect and fix partially erased sectors. */
        if (header.status == SECTOR_ERASING || header.status == SECTOR_ERASED) {
            _sector_free(fs, sector, header.status);
            header.status = SECTOR_FREE;
        }

        /* Detect corrupted sectors. */
        if (header.status != SECTOR_FREE && header.status != SECTOR_IN_USE) {
            LOG(fs, "ringfs_scan: corrupted sector %d\r\n", sector);
            return RINGFS_CORRUPTED;
        }

        /* Detect obsolete versions. We can't do this earlier because the version
         * could have been invalid due to a partial erase. */
        if (header.version != fs->version) {
            LOG(fs, "ringfs_scan: incompatible version 0x%08"PRIx32"", header.version);
            return RINGFS_INCOMPATIBLE_VERSION;
        }

        /* Record the presence of a FREE sector. */
        if (header.status == SECTOR_FREE)
            free_seen = true;

        /* Record the presence of a IN_USE sector. */
        if (header.status == SECTOR_IN_USE)
            used_seen = true;

        /* Update read & write sectors according to the above rules. */
        if (header.status == SECTOR_IN_USE && previous_sector_status == SECTOR_FREE)
            read_sector = sector;
        if (header.status == SECTOR_FREE && previous_sector_status == SECTOR_IN_USE)
            write_sector = sector-1;

        previous_sector_status = header.status;
    }

    /* Detect the lack of a FREE sector. */
    if (!free_seen) {
        LOG(fs, "ringfs_scan: invariant violated: no FREE sector found");
        return RINGFS_ERR;
    }

    /* Start writing at the first sector if the filesystem is empty. */
    if (!used_seen) {
        write_sector = 0;
    }

    /* Scan the write sector and skip all occupied slots at the beginning. */
    fs->write.sector = write_sector;
    fs->write.slot = 0;
    while (fs->write.sector == write_sector) {
        //uint32_t status;
        //_slot_get_status(fs, &fs->write, &status);
        struct slot_header header = {0,};
        if (_slot_get_header(fs, &fs->write, &header) == -1)
        {
            return RINGFS_ERR;
        }
        if (header.status == SLOT_ERASED)
            break;

        _loc_advance_slot(fs, &fs->write, _size_to_number_of_slots(fs, header.data_length));
    }
    /* If the sector was full, we're at the beginning of a FREE sector now. */

    /* Position the read head at the start of the first IN_USE sector, then skip
     * over garbage/invalid slots until something of value is found or we reach
     * the write head which means there's no data. */
    fs->read.sector = read_sector;
    fs->read.slot = 0;
    while (!_loc_equal(&fs->read, &fs->write)) {
        //uint32_t status;
        //_slot_get_status(fs, &fs->read, &status);
        struct slot_header header = {0,};
        if (_slot_get_header(fs, &fs->read, &header) == -1)
        {
            return RINGFS_ERR;
        }
        int slots_to_advance = 1;
        switch (header.status)
        {
            case SLOT_VALID:
            case SLOT_GARBAGE:
            case SLOT_RESERVED:
                slots_to_advance = _size_to_number_of_slots(fs, header.data_length);
                break;

            default:
                slots_to_advance = 1;
                break;
        }
        if (header.status == SLOT_VALID)
            break;

        _loc_advance_slot(fs, &fs->read, slots_to_advance);
    }

    /* Move the read cursor to the read head position. */
    fs->cursor = fs->read;

    return RINGFS_OK;
}

int ringfs_capacity(struct ringfs *fs)
{
    return fs->slots_per_sector * (fs->flash->sector_count - 1);
}

int ringfs_count_estimate(struct ringfs *fs)
{
    int sector_diff = (fs->write.sector - fs->read.sector + fs->flash->sector_count) %
        fs->flash->sector_count;

    return sector_diff * fs->slots_per_sector + fs->write.slot - fs->read.slot;
}

int ringfs_count_exact(struct ringfs *fs)
{
    int count = 0;

    /* Use a temporary loc for iteration. */
    struct ringfs_loc loc = fs->read;
    while (!_loc_equal(&loc, &fs->write)) {
        //uint32_t status;
        //_slot_get_status(fs, &loc, &status);
        struct slot_header header = {0,};
        if (_slot_get_header(fs, &loc, &header) == -1)
        {
            return RINGFS_ERR;
        }

        int slots_to_advance = 1;
        switch (header.status)
        {
            case SLOT_VALID:
                count++;
                //no break
            case SLOT_GARBAGE:
            case SLOT_RESERVED:
                slots_to_advance = _size_to_number_of_slots(fs, header.data_length);
                break;

            default:
                slots_to_advance = 1;
                break;
        }

        _loc_advance_slot(fs, &loc, slots_to_advance);
    }

    return count;
}

int ringfs_append(struct ringfs *fs, const void *object)
{
    return ringfs_append_ex(fs, object, fs->object_size);
}
int ringfs_append_ex(struct ringfs *fs, const void *object, int size)
{
    if (size > UINT16_MAX)
    {
        return RINGFS_INVALID_PARAMETER;
    }
    return ringfs_append_var(fs, object, size, DATA_TYPE_UNKNOWN);
}

struct slot_header slot_header_create(uint32_t status, uint16_t data_length, uint8_t data_type)
{
    return (struct slot_header) {
        .status = status,
        .data_length = data_length,
        .data_type = data_type,
        .reserved = 0xFF
    };
}

int ringfs_append_var(struct ringfs *fs, const void *object, uint16_t size, uint8_t type)
{
    int slots_needed = _size_to_number_of_slots(fs, size);
    if (slots_needed > fs->slots_per_sector)
    {
        return RINGFS_DESTINATION_MEM_INSUFFICIENT;
    }

    uint32_t status;

    /*
     * There are three sectors involved in appending a value:
     * - the sector where the append happens: it has to be writable
     * - the next sector: it must be free (invariant)
     * - the next-next sector: read & cursor heads are moved there if needed
     */

    /* Make sure the next sector is free. */
    int next_sector = (fs->write.sector+1) % fs->flash->sector_count;
    if (_sector_get_status(fs, next_sector, &status) == -1)
    {
        return RINGFS_ERR;
    }
    if (status != SECTOR_FREE) {
        /* Next sector must be freed. But first... */

        /* Move the read & cursor heads out of the way. */
        if (fs->read.sector == next_sector)
            _loc_advance_sector(fs, &fs->read);
        if (fs->cursor.sector == next_sector)
            _loc_advance_sector(fs, &fs->cursor);

        /* Free the next sector. */
        if (_sector_free(fs, next_sector, status) == -1)
        {
            return RINGFS_ERR;
        }
    }

    /* Now we can make sure the current write sector is writable. */
    if (_sector_get_status(fs, fs->write.sector, &status) == -1)
    {
        return RINGFS_ERR;
    }
    if (status == SECTOR_FREE) {
        /* Free sector. Mark as used. */
        if (_sector_set_status(fs, fs->write.sector, SECTOR_IN_USE) == -1)
        {
            return RINGFS_ERR;
        }
    } else if (status != SECTOR_IN_USE) {
        LOG(fs, "ringfs_append: corrupted filesystem");
        return RINGFS_CORRUPTED;
    }

    int free_slots_in_sector = fs->slots_per_sector - fs->write.slot;
    if (slots_needed > free_slots_in_sector)
    {
        struct slot_header header = slot_header_create(
                SLOT_GARBAGE,
                _slots_to_max_data_length(fs, free_slots_in_sector),
                type);
        if (_slot_set_header(fs, &fs->write, &header) == -1)
        {
            return RINGFS_ERR;
        }
        _loc_advance_slot(fs, &fs->write, free_slots_in_sector);
        return ringfs_append_ex(fs, object, size);
    }

    /* Preallocate slot. */
    struct slot_header header = slot_header_create(
            SLOT_RESERVED,
            size,
            type);
    if (_slot_set_header(fs, &fs->write, &header) == -1)
    {
        return RINGFS_ERR;
    }
    volatile int slot_addr = _slot_address(fs, &fs->write);
    printf("write.slot=%d, write.sector=%d, slot addr=%d\r\n", fs->write.slot, fs->write.sector, slot_addr);
    //_slot_set_status(fs, &fs->write, SLOT_RESERVED);

    /* Write object. */
    if (fs->flash->program(fs->flash,
            _slot_address(fs, &fs->write) + sizeof(struct slot_header),
            object, size) == -1)
    {
        return RINGFS_ERR;
    }

    /* Commit write. */
    if (_slot_set_status(fs, &fs->write, SLOT_VALID) == -1)
    {
        return RINGFS_ERR;
    }

    /* Advance the write head. */
    _loc_advance_slot(fs, &fs->write, slots_needed);

    return RINGFS_OK;
}

int ringfs_fetch(struct ringfs *fs, void *object)
{
    return ringfs_fetch_ex(fs, object, fs->object_size);
}

int ringfs_fetch_ex(struct ringfs *fs, void *object, int size)
{
    uint16_t object_size = size;
    uint8_t type = 0;
    return ringfs_fetch_var(fs, object, &object_size, &type);
}

int ringfs_fetch_var(struct ringfs *fs, void *object, uint16_t *size, uint8_t *type)
{
    if (!size || !type)
    {
        return RINGFS_INVALID_PARAMETER;
    }
    /* Advance forward in search of a valid slot. */
    while (!_loc_equal(&fs->cursor, &fs->write)) {
        struct slot_header header;
        if (_slot_get_header(fs, &fs->cursor, &header) == -1)
        {
            return RINGFS_ERR;
        }
        uint32_t status = header.status;

        //_slot_get_status(fs, &fs->cursor, &status);

        if (status == SLOT_VALID) {
            if (header.data_length > *size)
            {
                return RINGFS_DESTINATION_MEM_INSUFFICIENT;
            }
            if (fs->flash->read(fs->flash,
                    _slot_address(fs, &fs->cursor) + sizeof(struct slot_header),
                    object, header.data_length) == -1)
            {
                return RINGFS_ERR;
            }
            *size = header.data_length;
            *type = header.data_type;
            _loc_advance_slot(fs, &fs->cursor, _size_to_number_of_slots(fs, header.data_length));
            return RINGFS_OK;
        }

        _loc_advance_slot(fs, &fs->cursor, 1);
    }

    return RINGFS_EMPTY;
}

int ringfs_discard(struct ringfs *fs)
{
    while (!_loc_equal(&fs->read, &fs->cursor)) {
        if (_slot_set_status(fs, &fs->read, SLOT_GARBAGE) == -1)
        {
            return RINGFS_ERR;
        }
        
        uint16_t data_length = 0;
        if (_slot_get_data_length(fs, &fs->read, &data_length) == -1)
        {
            return RINGFS_ERR;
        }
        _loc_advance_slot(fs, &fs->read, _size_to_number_of_slots(fs, data_length));
    }

    return RINGFS_OK;
}

int ringfs_item_discard(struct ringfs *fs)
{
    if (_loc_equal(&fs->read, &fs->write)) {
        return RINGFS_EMPTY;
    }

    if (_slot_set_status(fs, &fs->read, SLOT_GARBAGE) == -1) {
        return RINGFS_ERR;
    }
        
    uint16_t data_length = 0;
    if (_slot_get_data_length(fs, &fs->read, &data_length) == -1) {
        return RINGFS_ERR;
    }
    
    _loc_advance_slot(fs, &fs->read, _size_to_number_of_slots(fs, data_length));

    return RINGFS_OK;
}

int ringfs_rewind(struct ringfs *fs)
{
    fs->cursor = fs->read;
    return RINGFS_OK;
}

void ringfs_dump(FILE *stream, struct ringfs *fs)
{
    const char *description;

    fprintf(stream, "RingFS read: {%d,%d} cursor: {%d,%d} write: {%d,%d}\n",
            fs->read.sector, fs->read.slot,
            fs->cursor.sector, fs->cursor.slot,
            fs->write.sector, fs->write.slot);

    for (int sector=0; sector<fs->flash->sector_count; sector++) {
        int addr = _sector_address(fs, sector);

        /* Read sector header. */
        struct sector_header header;
        fs->flash->read(fs->flash, addr, &header, sizeof(header));

        switch (header.status) {
            case SECTOR_ERASED: description = "ERASED"; break;
            case SECTOR_FREE: description = "FREE"; break;
            case SECTOR_IN_USE: description = "IN_USE"; break;
            case SECTOR_ERASING: description = "ERASING"; break;
            case SECTOR_FORMATTING: description = "FORMATTING"; break;
            default: description = "UNKNOWN"; break;
        }

        fprintf(stream, "[%04d] [v=0x%08"PRIx32"] [%-10s] ",
                sector, header.version, description);

        for (int slot=0; slot<fs->slots_per_sector; ) {
            struct ringfs_loc loc = { sector, slot };
            struct slot_header header = {0,};
            //uint32_t status;
            //_slot_get_status(fs, &loc, &status);
            if (_slot_get_header(fs, &loc, &header) == -1)
            {
                return;
            }

            switch (header.status) {
                case SLOT_ERASED: description = "E"; break;
                case SLOT_RESERVED: description = "R"; break;
                case SLOT_VALID: description = "V"; break;
                case SLOT_GARBAGE: description = "G"; break;
                default: description = "?"; break;
            }
            slot += _size_to_number_of_slots(fs, header.data_length);

            fprintf(stream, "%s", description);
        }

        fprintf(stream, "\n");
    }

    fflush(stream);
}

/**
 * @}
 */

/* vim: set ts=4 sw=4 et: */

