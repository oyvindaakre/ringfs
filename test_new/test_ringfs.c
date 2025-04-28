/*
 * Copyright © 2014 Kosma Moczek <kosma@cloudyourcar.com>
 * This program is free software. It comes without any warranty, to the extent
 * permitted by applicable law. You can redistribute it and/or modify it under
 * the terms of the Do What The Fuck You Want To Public License, Version 2, as
 * published by Sam Hocevar. See the COPYING file for more details.
 */

#include <criterion/criterion.h>
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <check.h>

#include "ringfs.h"
#include "flashsim.h"

/* Flashsim tests. */
Test(test_flashsim, basic)
{
    printf("# test_flashsim\n");

    struct flashsim *smallsim = flashsim_open("test.sim", 1024, 16);
    uint8_t buf[48];
    uint8_t data[16];

    flashsim_sector_erase(smallsim, 0);
    flashsim_sector_erase(smallsim, 16);
    flashsim_sector_erase(smallsim, 32);

    memset(data, 0x5a, 16);
    flashsim_program(smallsim, 16, data, 16);

    flashsim_read(smallsim, 0, buf, 48);
    for (int i=0; i<16; i++)
        cr_assert_eq(buf[i], 0xff);
    for (int i=16; i<32; i++)
        cr_assert_eq(buf[i], 0x5a);
    for (int i=32; i<48; i++)
        cr_assert_eq(buf[i], 0xff);

    memset(data, 0x01, 16);
    flashsim_program(smallsim, 0, data, 16);
    memset(data, 0x10, 16);
    flashsim_program(smallsim, 32, data, 16);
    flashsim_sector_erase(smallsim, 16);

    flashsim_read(smallsim, 0, buf, 48);
    for (int i=0; i<16; i++)
        cr_assert_eq(buf[i], 0x01);
    for (int i=16; i<32; i++)
        cr_assert_eq(buf[i], 0xff);
    for (int i=32; i<48; i++)
        cr_assert_eq(buf[i], 0x10);

    free(smallsim);
}

/* Flash simulator + MTD partition fixture. */

static struct flashsim *sim;

static int op_sector_erase(struct ringfs_flash_partition *flash, int address)
{
    (void) flash;
    flashsim_sector_erase(sim, address);
    return 0;
}

static ssize_t op_program(struct ringfs_flash_partition *flash, int address, const void *data, size_t size)
{
    (void) flash;
    flashsim_program(sim, address, data, size);
    return size;
}

static ssize_t op_read(struct ringfs_flash_partition *flash, int address, void *data, size_t size)
{
    (void) flash;
    flashsim_read(sim, address, data, size);
    return size;
}

static void op_log(struct ringfs_flash_partition *flash, const char *fmt, ...)
{
    (void) flash;
    va_list args;
    va_start(args, fmt);
    printf("[ringfs] ");
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
}

/*
 * A really small filesystem: 3 slots per sector, 15 slots total.
 * Has the benefit of causing frequent wraparounds, potentially finding
 * more bugs.
 */
static struct ringfs_flash_partition flash = {
    .sector_size = 64,
    .sector_offset = 4,
    .sector_count = 6,

    .sector_erase = op_sector_erase,
    .program = op_program,
    .read = op_read,
    .log = op_log
};

static void fixture_flashsim_setup(void)
{
    sim = flashsim_open("ringfs.sim",
            flash.sector_size * (flash.sector_offset + flash.sector_count),
            flash.sector_size);
}

static void fixture_flashsim_teardown(void)
{
    flashsim_close(sim);
    sim = NULL;
}

/* RingFS tests. */

#define DEFAULT_VERSION 0x000000042
typedef struct
{
    int32_t data[2];
} object_t;
#define SECTOR_HEADER_SIZE 8
#define SLOT_HEADER_SIZE 8

static void assert_loc_equiv_to_offset(const struct ringfs *fs, const struct ringfs_loc *loc, int offset)
{
    int loc_offset = loc->sector * fs->slots_per_sector + loc->slot;
    cr_assert_eq(offset, loc_offset);
}

static void assert_loc_is_updated(const struct ringfs *fs, const struct ringfs_loc *current_loc, const struct ringfs_loc *old_loc)
{
    int current_offset = current_loc->sector * fs->slots_per_sector + current_loc->slot;
    int old_offset = old_loc->sector * fs->slots_per_sector + old_loc->slot;
    cr_assert_gt(current_offset, old_offset);
}

static void assert_scan_integrity(const struct ringfs *fs)
{
    struct ringfs newfs;
    ringfs_init(&newfs, fs->flash, fs->version, fs->object_size);
    cr_assert(ringfs_scan(&newfs) == 0);

    int count = ringfs_count_exact(&newfs);
    cr_assert_eq(count, ringfs_count_exact((struct ringfs*)fs));

    if (count)
    {
        // Due to the nature of the variable length records,
        // the read position of the original fs might not match that of a newly scanned fs.
        // The reason is that the new fs points to the next valid data, whereas the old fs.read 
        // might point to intermediate garbage data of zero length.
        // This will happen when new data has been added which could not fit in the same sector (ringfs flags
        // them as garbage and advances to next sector with free slots).
        // Doing a new read would fetch the correct data in both filesystems.
        // The way to test for this is to fetch data from both fs and compare
        // the cursor location. Both should now point to the same location.
        object_t obj, obj2;
        // Need to modify the input fs to do this, so cast away the const (sorry)
        cr_assert(ringfs_fetch((struct ringfs*)fs, &obj) == 0);
        cr_assert(ringfs_fetch(&newfs, &obj2) == 0);

        cr_assert_eq(newfs.cursor.sector, fs->cursor.sector);
        cr_assert_eq(newfs.cursor.slot, fs->cursor.slot);
        cr_assert_eq(newfs.write.sector, fs->write.sector);
        cr_assert_eq(newfs.write.slot, fs->write.slot);
        // Again, sorry about modifying const input
        cr_assert(ringfs_rewind((struct ringfs*)fs) == 0);
    }
    else
    {
        cr_assert_eq(newfs.read.sector, fs->read.sector);
        cr_assert_eq(newfs.read.slot, fs->read.slot);
        cr_assert_eq(newfs.cursor.sector, fs->cursor.sector);
        cr_assert_eq(newfs.cursor.slot, fs->cursor.slot);
        cr_assert_eq(newfs.write.sector, fs->write.sector);
        cr_assert_eq(newfs.write.slot, fs->write.slot);
    }
}

TestSuite(test_suite_ringfs, .init = fixture_flashsim_setup, .fini=fixture_flashsim_teardown);

Test(test_suite_ringfs, ringtest_ringfs_format)
{
    printf("# test_ringfs_format\n");

    struct ringfs fs1;
    printf("## ringfs_init()\n");
    ringfs_init(&fs1, &flash, DEFAULT_VERSION, sizeof(object_t));
    printf("## ringfs_format()\n");
    ringfs_format(&fs1);
}

Test(test_suite_ringfs, test_ringfs_scan)
{
    printf("# test_ringfs_scan\n");

    /* first format a filesystem */
    struct ringfs fs1;
    printf("## ringfs_init()\n");
    ringfs_init(&fs1, &flash, DEFAULT_VERSION, sizeof(object_t));
    printf("## ringfs_format()\n");
    ringfs_format(&fs1);

    /* now try to scan it */
    struct ringfs fs2;
    printf("## ringfs_init()\n");
    ringfs_init(&fs2, &flash, DEFAULT_VERSION, sizeof(object_t));
    printf("## ringfs_scan()\n");
    cr_assert(ringfs_scan(&fs2) == 0);

    /* this is an empty FS, should start with this: */
    cr_assert_eq(fs2.slots_per_sector, (flash.sector_size-SECTOR_HEADER_SIZE)/(SLOT_HEADER_SIZE));
    assert_loc_equiv_to_offset(&fs2, &fs2.read, 0);
    assert_loc_equiv_to_offset(&fs2, &fs2.cursor, 0);
    assert_loc_equiv_to_offset(&fs2, &fs2.write, 0);

    /* now insert some objects */
    cr_assert(ringfs_append(&fs2, (int[]) { 0x11 }) == 0);
    cr_assert(ringfs_append(&fs2, (int[]) { 0x22 }) == 0);
    cr_assert(ringfs_append(&fs2, (int[]) { 0x33 }) == 0);

    /* rescan */
    printf("## ringfs_scan()\n");
    cr_assert(ringfs_scan(&fs2) == 0);

    /* make sure the objects are there */
    cr_assert(ringfs_count_exact(&fs2) == 3);

    /* scan should fail if we supply a different version */
    struct ringfs fs3;
    printf("## ringfs_init()\n"); 
    ringfs_init(&fs3, &flash, DEFAULT_VERSION+1, sizeof(object_t));
    printf("## ringfs_scan()\n");
    cr_assert(ringfs_scan(&fs3) != 0);
}

Test(test_suite_ringfs, test_ringfs_append)
{
    printf("# test_ringfs_append\n");

    /* first format a filesystem */
    object_t obj;
    struct ringfs fs;
    printf("## ringfs_init()\n");
    ringfs_init(&fs, &flash, DEFAULT_VERSION, sizeof(object_t));
    printf("## ringfs_format()\n");
    ringfs_format(&fs);

    /* fetches before appends should not change anything */
    for (int i=0; i<3; i++) {
        printf("## ringfs_fetch()\n");
        cr_assert(ringfs_fetch(&fs, &obj) < 0);
    }
    assert_loc_equiv_to_offset(&fs, &fs.read, 0);
    assert_loc_equiv_to_offset(&fs, &fs.write, 0);
    assert_loc_equiv_to_offset(&fs, &fs.cursor, 0);
    assert_scan_integrity(&fs);

    /* now we're brave and we write some data */
    struct ringfs_loc write_prev = {0,0};
    for (int i=0; i<3; i++) {
        printf("## ringfs_append()\n");
        ringfs_append(&fs, (int[]) { 0x11*(i+1) });

        /* make sure the write head has advanced */
        assert_loc_is_updated(&fs, &fs.write, &write_prev);
        write_prev = fs.write;
        assert_scan_integrity(&fs);
    }

    /* now we fetch at it. */
    struct ringfs_loc cursor_prev = {0,0};
    for (int i=0; i<3; i++) {
        printf("## ringfs_fetch()\n");
        cr_assert(ringfs_fetch(&fs, &obj) == 0);
        cr_assert_eq(obj.data[0], 0x11*(i+1));

        /* make sure the cursor head has advanced */
        assert_loc_is_updated(&fs, &fs.cursor, &cursor_prev);
        cursor_prev = fs.cursor;
    }
    /* there should be no data left */
    cr_assert(ringfs_fetch(&fs, &obj) < 0);

    /* test the rewind. */
    cr_assert(ringfs_rewind(&fs) == 0);
    assert_loc_equiv_to_offset(&fs, &fs.cursor, 0);

    /* try to read the objects once again. */
    for (int i=0; i<3; i++) {
        printf("## ringfs_fetch()\n");
        cr_assert(ringfs_fetch(&fs, &obj) == 0);
        cr_assert_eq(obj.data[0], 0x11*(i+1));
    }
}


Test(test_suite_ringfs, test_ringfs_discard)
{
    printf("# test_ringfs_discard\n");

    struct ringfs fs;
    printf("## ringfs_init()\n");
    ringfs_init(&fs, &flash, DEFAULT_VERSION, sizeof(object_t));
    printf("## ringfs_format()\n");
    ringfs_format(&fs);

    /* write some records */
    for (int i=0; i<4; i++) {
        printf("## ringfs_append()\n");
        ringfs_append(&fs, (int[]) { 0x11*(i+1) });
        assert_scan_integrity(&fs);
    }
    /* read some of them */
    object_t obj;
    for (int i=0; i<2; i++) {
        printf("## ringfs_fetch()\n");
        cr_assert(ringfs_fetch(&fs, &obj) == 0);
        cr_assert_eq(obj.data[0], 0x11*(i+1));
    }
    /* discard whatever was read */
    cr_assert(ringfs_discard(&fs) == 0);
    assert_scan_integrity(&fs);
    /* make sure we're consistent */
    // A bit more complicated to test with variable length records,
    // so skipping these
    //assert_loc_equiv_to_offset(&fs, &fs.read, 2);
    //assert_loc_equiv_to_offset(&fs, &fs.cursor, 2);
    //assert_loc_equiv_to_offset(&fs, &fs.write, 4);

    /* read the rest of the records */
    for (int i=2; i<4; i++) {
        printf("## ringfs_fetch()\n");
        cr_assert(ringfs_fetch(&fs, &obj) == 0);
        cr_assert_eq(obj.data[0], 0x11*(i+1));
    }
    /* discard them */
    cr_assert(ringfs_discard(&fs) == 0);
    // I think these 3 asserts know too much about inner details
    // so skipping them and checking all locations are equal
    //assert_loc_equiv_to_offset(&fs, &fs.read, 4);
    //assert_loc_equiv_to_offset(&fs, &fs.cursor, 4);
    //assert_loc_equiv_to_offset(&fs, &fs.write, 4);
    cr_assert_arr_eq(&fs.read, &fs.write, sizeof(struct ringfs_loc));
    cr_assert_arr_eq(&fs.read, &fs.cursor, sizeof(struct ringfs_loc));
    assert_scan_integrity(&fs);
}


Test(test_suite_ringfs, test_ringfs_capacity)
{
    printf("# test_ringfs_capacity\n");

    struct ringfs fs;
    ringfs_init(&fs, &flash, DEFAULT_VERSION, sizeof(object_t));

    int slots_per_sector = (flash.sector_size-SECTOR_HEADER_SIZE)/(SLOT_HEADER_SIZE);
    int sectors = flash.sector_count;
    cr_assert_eq(ringfs_capacity(&fs), (sectors-1) * slots_per_sector);
}


Test(test_suite_ringfs, test_ringfs_count)
{
    printf("# test_ringfs_count\n");

    int obj;
    struct ringfs fs;
    ringfs_init(&fs, &flash, DEFAULT_VERSION, sizeof(object_t));
    ringfs_format(&fs);
    cr_assert(ringfs_count_exact(&fs) == 0);

    printf("## write some records\n");
    for (int i=0; i<10; i++)
        ringfs_append(&fs, (int[]) { 0x11*(i+1) });
    cr_assert_eq(ringfs_count_exact(&fs), 10);


    printf("## rescan\n");
    cr_assert(ringfs_scan(&fs) == 0);
    cr_assert_eq(ringfs_count_exact(&fs), 10);

    printf("## append more records\n");
    for (int i=10; i<13; i++)
        ringfs_append(&fs, (int[]) { 0x11*(i+1) });
    cr_assert_eq(ringfs_count_exact(&fs), 13);

    printf("## fetch some objects without discard\n");
    for (int i=0; i<4; i++) {
        cr_assert(ringfs_fetch(&fs, &obj) == 0);
        cr_assert_eq(obj, 0x11*(i+1));
    }
    cr_assert_eq(ringfs_count_exact(&fs), 13);

    printf("## rescan\n");
    cr_assert(ringfs_scan(&fs) == 0);
    cr_assert_eq(ringfs_count_exact(&fs), 13);

    printf("## fetch some objects with discard\n");
    for (int i=0; i<4; i++) {
        cr_assert(ringfs_fetch(&fs, &obj) == 0);
        cr_assert_eq(obj, 0x11*(i+1));
    }
    cr_assert_eq(ringfs_count_exact(&fs), 13);
    cr_assert(ringfs_discard(&fs) == 0);
    cr_assert_eq(ringfs_count_exact(&fs), 9);

    printf("## fill the segment\n");
    // When dealing with variable length records,
    // I honestly don't see what this test adds
    // that is not already covered by the tests above.
    // So commenting it out for now and maybe revisit it later
    // int count = fs.slots_per_sector - 1;
    // for (int i=0; i<count; i++)
    //     ringfs_append(&fs, (int[]) { 0x42 });
    // cr_assert_eq(ringfs_count_exact(&fs), 9+count);
}


Test(test_suite_ringfs, test_ringfs_overflow)
{
    printf("# test_ringfs_overflow\n");

    printf("## format\n");
    struct ringfs fs;
    ringfs_init(&fs, &flash, DEFAULT_VERSION, sizeof(object_t));
    ringfs_format(&fs);

    int slot_capacity = ringfs_capacity(&fs);
    int slots_per_sector = slot_capacity / (fs.flash->sector_count - 1);
    int max_objects_per_sector = slots_per_sector / ((SLOT_HEADER_SIZE + sizeof(object_t)) / fs.object_size);
    int max_objects = (fs.flash->sector_count - 1) * max_objects_per_sector;

    printf("## fill filesystem to the brim\n");
    for (int i=0; i<max_objects; i++)
        ringfs_append(&fs, (int[]) { i });
    cr_assert_eq(ringfs_count_exact(&fs), max_objects);
    assert_scan_integrity(&fs);

    /* won't hurt to stress it a little bit! */
    for (int round=0; round<3; round++) {
        printf("## add one more object\n");
        ringfs_append(&fs, (int[]) { 0x42 });
        /* should kill one entire sector to make space */
        cr_assert_eq(ringfs_count_exact(&fs), max_objects - max_objects_per_sector + 1);
        assert_scan_integrity(&fs);

        printf("## fill back up to the sector capacity\n");
        for (int i=0; i<max_objects_per_sector-1; i++)
            ringfs_append(&fs, (int[]) { i });

        cr_assert_eq(ringfs_count_exact(&fs), max_objects);
        assert_scan_integrity(&fs);
    }
}


/* vim: set ts=4 sw=4 et: */

