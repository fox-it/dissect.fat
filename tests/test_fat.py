from dissect.fat import fat


def test_fat12(fat12):
    volume_label = "VOLLAB1"

    fs = fat.FATFS(fat12)

    assert fs.fat.bits_per_entry == 12

    assert fs.volume_label == volume_label
    assert fs.volume_id == "e038bb7c"
    assert fs.cluster_size == 512

    verify_fs_content(fs, volume_label)


def test_fat16(fat16):
    volume_label = "LABFAT16"

    fs = fat.FATFS(fat16)

    assert fs.fat.bits_per_entry == 16

    assert fs.volume_label == volume_label
    assert fs.volume_id == "88fa453f"
    assert fs.cluster_size == 512

    verify_fs_content(fs, volume_label)


def test_fat32(fat32):
    volume_label = "LABFAT32"

    fs = fat.FATFS(fat32)

    assert fs.fat.bits_per_entry == 32

    assert fs.volume_label == volume_label
    assert fs.volume_id == "4368dbb7"
    assert fs.cluster_size == 512

    verify_fs_content(fs, volume_label)


def verify_fs_content(fs, volume_label):

    entries_map = {e.name: e for e in fs.root.iterdir()}

    assert set(entries_map.keys()) == {volume_label, "file1.txt", "file2.txt", "subdir1"}

    file1 = entries_map["file1.txt"]
    assert not file1.is_directory()
    assert file1.size == 20

    file2 = entries_map["file2.txt"]
    assert not file2.is_directory()
    assert file2.size == 23

    subdir = entries_map["subdir1"]
    assert subdir.is_directory()
    assert subdir.size == 512

    subdir_entries_map = {e.name: e for e in list(subdir.iterdir())}

    assert set(subdir_entries_map.keys()) == {".", "..", "file3.txt"}

    file3 = subdir_entries_map["file3.txt"]
    assert not file3.is_directory()
    assert file3.size == 27
